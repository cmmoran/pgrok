package conn

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"golang.org/x/net/proxy"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"pgrok/log"
	"sync"
	"unicode"

	vhost "github.com/inconshreveable/go-vhost"
)

type Conn interface {
	net.Conn
	log.Logger
	Id() string
	SetType(string)
	CloseRead() error
}

type loggedConn struct {
	tcp *net.TCPConn
	net.Conn
	log.Logger
	id  int32
	typ string
}

type Listener struct {
	net.Addr
	Conns chan *loggedConn
}

func wrapConn(conn net.Conn, typ string) *loggedConn {
	switch c := conn.(type) {
	case *vhost.HTTPConn:
		wrapped := c.Conn.(*loggedConn)
		return &loggedConn{wrapped.tcp, conn, wrapped.Logger, wrapped.id, wrapped.typ}
	case *loggedConn:
		return c
	case *net.TCPConn:
		wrapped := &loggedConn{c, conn, log.NewPrefixLogger(), rand.Int31(), typ}
		wrapped.AddLogPrefix(wrapped.Id())
		return wrapped
	}

	return nil
}

func Listen(addr, typ string, tlsCfg *tls.Config) (l *Listener, err error) {
	// listen for incoming connections
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return
	}

	l = &Listener{
		Addr:  listener.Addr(),
		Conns: make(chan *loggedConn),
	}

	go func() {
		for {
			rawConn, err := listener.Accept()
			if err != nil {
				log.Error("Failed to accept new TCP connection of type %s: %v", typ, err)
				continue
			}

			c := wrapConn(rawConn, typ)
			if tlsCfg != nil {
				c.Conn = tls.Server(c.Conn, tlsCfg)
			}
			c.Info("New connection from %v", c.RemoteAddr())
			l.Conns <- c
		}
	}()
	return
}

func Wrap(conn net.Conn, typ string) *loggedConn {
	return wrapConn(conn, typ)
}

func Dial(addr, typ string, tlsCfg *tls.Config) (conn *loggedConn, err error) {
	var rawConn net.Conn
	if rawConn, err = net.Dial("tcp", addr); err != nil {
		return
	}

	conn = wrapConn(rawConn, typ)
	conn.Debug("New connection to: %v", rawConn.RemoteAddr())

	if tlsCfg != nil {
		conn.StartTLS(tlsCfg)
	}

	return
}

func DialSocks5Proxy(socksUrl, addr, typ string, tlsCfg *tls.Config) (conn *loggedConn, err error) {
	var parsedUrl *url.URL
	if parsedUrl, err = url.Parse(socksUrl); err != nil {
		return
	}
	var d proxy.Dialer
	d, err = proxy.FromURL(parsedUrl, nil)

	var rawConn net.Conn
	if rawConn, err = d.Dial("tcp", addr); err != nil {
		return
	}

	conn = wrapConn(rawConn, typ)
	conn.Debug("New Socks Proxy connection to: %v", rawConn.RemoteAddr())

	if tlsCfg != nil {
		conn.StartTLS(tlsCfg)
	}

	return
}

func DialHttpProxy(proxyUrl, addr, typ string, tlsCfg *tls.Config) (conn *loggedConn, err error) {
	// parse the proxy address
	var parsedUrl *url.URL
	if parsedUrl, err = url.Parse(proxyUrl); err != nil {
		return
	}

	var proxyAuth string
	if parsedUrl.User != nil {
		proxyAuth = "Basic " + base64.StdEncoding.EncodeToString([]byte(parsedUrl.User.String()))
	}

	var proxyTlsConfig *tls.Config
	switch parsedUrl.Scheme {
	case "http":
		proxyTlsConfig = nil
	case "https":
		proxyTlsConfig = new(tls.Config)
	default:
		err = fmt.Errorf("proxy URL scheme must be http or https, got: %s", parsedUrl.Scheme)
		return
	}

	// dial the proxy
	if conn, err = Dial(parsedUrl.Host, typ, proxyTlsConfig); err != nil {
		return
	}

	// send an HTTP proxy CONNECT message
	req, err := http.NewRequest("CONNECT", "https://"+addr, nil)
	if err != nil {
		return
	}

	if proxyAuth != "" {
		req.Header.Set("Proxy-Authorization", proxyAuth)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; pgrok)")
	req.Write(conn)

	// read the proxy's response
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		err = fmt.Errorf("Non-200 response from proxy server: %s", resp.Status)
		return
	}

	// upgrade to TLS
	conn.StartTLS(tlsCfg)

	return
}

func (c *loggedConn) StartTLS(tlsCfg *tls.Config) {
	c.Conn = tls.Client(c.Conn, tlsCfg)
}

func (c *loggedConn) Close() (err error) {
	if err := c.Conn.Close(); err == nil {
		c.Debug("Closing")
	}
	return
}

func (c *loggedConn) Id() string {
	return fmt.Sprintf("%s:%x", c.typ, c.id)
}

func (c *loggedConn) SetType(typ string) {
	oldId := c.Id()
	c.typ = typ
	c.ClearLogPrefixes()
	c.AddLogPrefix(c.Id())
	c.Info("Renamed connection %s", oldId)
}

func (c *loggedConn) CloseRead() error {
	// XXX: use CloseRead() in Conn.Join() and in Control.shutdown() for cleaner
	// connection termination. Unfortunately, when I've tried that, I've observed
	// failures where the connection was closed *before* flushing its write buffer,
	// set with SetLinger() set properly (which it is by default).
	return c.tcp.CloseRead()
}

func (wc *WriteCopy) Write(p []byte) (int, error) {
	n := len(p)

	wc.c.Write(p)

	return n, nil
}

type WriteCopy struct {
	c Conn
}

func Join(c Conn, c2 Conn) (int64, int64) {
	//
	defer c.Close()
	defer c2.Close()
	var wait sync.WaitGroup

	pipe := func(to Conn, from Conn, bytesCopied *int64) {
		defer wait.Done()

		var err error
		*bytesCopied, err = io.Copy(to, from)
		if err != nil {
			from.Warn("Copied %d bytes to %s before failing with error %v", *bytesCopied, to.Id(), err)
		} else {
			from.Debug("Copied %d bytes to %s", *bytesCopied, to.Id())
		}
	}

	wait.Add(2)
	var fromBytes, toBytes int64
	go pipe(c, c2, &fromBytes)
	go pipe(c2, c, &toBytes)
	wait.Wait()
	return fromBytes, toBytes
}

func JoinWithReplace(replacementsFirstToSecond map[string]string, replacementsSecondToFirst map[string]string, first Conn, second Conn, modifyFirstToSecond bool, modifySecondToFirst bool) (int64, int64) {
	// first Conn, second Conn
	// localConn Conn, remoteConn Conn
	// publicConn Conn, proxyConn Conn
	defer first.Close()
	defer second.Close()
	var wait sync.WaitGroup

	pipe := func(to Conn, from Conn, bytesCopied *int64, doReplace bool, rreplacements map[string]string) {
		defer wait.Done()

		var err error

		if doReplace {
			*bytesCopied, err = copyInterceptBuffer(to, from, nil, rreplacements)
		} else {
			*bytesCopied, err = io.Copy(to, from)
		}
		if err != nil {
			from.Warn("JR: Copied %d bytes to %s before failing with error %v", *bytesCopied, to.Id(), err)
		} else {
			from.Debug("JR: Copied %d bytes to %s", *bytesCopied, to.Id())
		}
	}

	wait.Add(2)
	var fromBytes, toBytes int64
	//Write to first
	go pipe(first, second, &fromBytes, modifySecondToFirst, replacementsSecondToFirst)
	//Write to second
	go pipe(second, first, &toBytes, modifyFirstToSecond, replacementsFirstToSecond)
	wait.Wait()
	return fromBytes, toBytes
}

// copyBuffer is the actual implementation of Copy and CopyBuffer.
// if buf is nil, one is allocated.
func copyInterceptBuffer(dst Conn, src Conn, buf []byte, replacements map[string]string) (written int64, err error) {
	// If the reader has a WriteTo method, use it to do the copy.
	// Avoids an allocation and a copy.
	if len(replacements) == 0 {
		return io.CopyBuffer(dst, src, buf)
	}
	size := 64 * 1024
	if buf == nil {
		buf = make([]byte, size)
	}
	for {
		//src.Debug("%s => %s:Reading...", src.LocalAddr(), src.RemoteAddr())
		nr, er := src.Read(buf)

		/*		bindata := !IsAsciiPrintable(string(buf))
				if bindata {
					str := string(buf)
					idx := strings.LastIndex(str, "\n")
					if idx == -1 {
						src.Debug("%s => %s:Read %d...<binary>", src.LocalAddr(), src.RemoteAddr(), nr)
					} else {
						src.Debug("%s => %s:Read %d...<binary> [%s]", src.LocalAddr(), src.RemoteAddr(), nr, string(buf[0:idx]))
					}
				} else {
					src.Debug("%s => %s:Read %d...[%s]", src.LocalAddr(), src.RemoteAddr(), nr, string(buf))
				}
		*/
		if nr > 0 {
			//lnr := nr
			for find, replace := range replacements {
				//src.Debug("%s => %s:Searching for %s", src.LocalAddr(), src.RemoteAddr(), find)
				bfind := []byte(find)
				brep := []byte(replace)
				index := bytes.Index(buf, bfind)
				if index > -1 {
					//src.Debug("%s => %s:FOUND: [%s] @%d -> [%s]", src.LocalAddr(), src.RemoteAddr(), find, index, replace)
					diff := len(replace) - len(find)
					buf = bytes.Replace(buf, bfind, brep, 1)
					nr += diff
					//src.Debug("%s => %s:REPLACED: [%s] @%d -> [%s]", src.LocalAddr(), src.RemoteAddr(), find, index, string(buf))
				}
			}
			/*			if lnr != nr {
							src.Debug("Adjusted nr by %d", lnr - nr)
						}

						bindata := !IsAsciiPrintable(string(buf))
						if bindata {
							str := string(buf)
							idx := strings.LastIndex(str, "\n")
							if idx == -1 {
								dst.Debug("%s => %s:Writing %d...<binary>", dst.LocalAddr(), dst.RemoteAddr(), nr)
							} else {
								dst.Debug("%s => %s:Writing %d...<binary> [%s]", dst.LocalAddr(), dst.RemoteAddr(), nr, string(buf[0:idx]))
							}
						} else {
							dst.Debug("%s => %s:Writing %d...[%s]", dst.LocalAddr(), dst.RemoteAddr(), nr, string(buf))
						}
			*/
			nw, ew := dst.Write(buf[0:nr])

			/*			bindata = !IsAsciiPrintable(string(buf))
						if bindata {
							str := string(buf)
							idx := strings.LastIndex(str, "\n")
							if idx == -1 {
								dst.Debug("%s => %s:Wrote %d...<binary>", dst.LocalAddr(), dst.RemoteAddr(), nw)
							} else {
								dst.Debug("%s => %s:Wrote %d...<binary> [%s]", dst.LocalAddr(), dst.RemoteAddr(), nw, string(buf[0:idx]))
							}
						} else {
							dst.Debug("%s => %s:Wrote %d...[%s]", dst.LocalAddr(), dst.RemoteAddr(), nw, string(buf[0:nw]))
						}
			*/
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	//dst.Debug("%s => %s:FINISHED %d", dst.LocalAddr(), dst.RemoteAddr(), written)
	return written, err
}

func IsAsciiPrintable(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

/*

func copyprintwriter(out Conn) (pr *io.PipeReader, pw *io.PipeWriter) {
	pr, pw = io.Pipe()

	reader := bufio.NewReader(pr)

	go func() {
		var curr []byte
		var err error
		buff := []byte("")
		flag := false
		for {
			curr, err = reader.ReadBytes('\n')
			if err != nil {
				buff = append(buff, curr...)
				out.Debug("COPY WIRETAP\n%s\n", string(buff))
				out.Write(curr)
				break
			}
			if strings.TrimSpace(string(curr)) == "" {
				flag = true
			}
			if !flag {
				buff = append(buff, curr...)
				out.Debug("COPY WIRETAP\n%s\n", string(buff))
			} else {
				out.Debug("COPY WIRETAP\n%d MORE BINARY DATA\n", len(buff))
			}
			out.Write(curr)
		}
	}()

	return

}

func repwriter(replacements map[string]string, out Conn) (pr *io.PipeReader, pw *io.PipeWriter) {
	pr, pw = io.Pipe()
	reader := bufio.NewReader(pr)
		go func() {
		var curr []byte
		var err error
		buff := []byte("")
		flag := false
		for {
			curr, err = reader.ReadBytes('\n')
			if err != nil {
				buff = append(buff, curr...)
				out.Debug("WRITER WIRETAP\n%s\n", string(buff))
				out.Write(curr)
				break
			}
			tcurr := strings.TrimSpace(string(curr))
			if string(tcurr) == "" {
				flag = true
			}
			replace := replacements[tcurr]
			if replace != "" {
				curr = bytes.Replace(curr, []byte(tcurr), []byte(replace), 1)
				out.Info("WRITER: HostHeader replaced: %s -> %s", tcurr, string(curr))
			}
			if !flag {
				buff = append(buff, curr...)
				out.Debug("WRITER WIRETAP\n%s\n", string(buff))
			} else {
				out.Debug("WRITER WIRETAP\n%d MORE BINARY DATA\n", len(buff))
			}
			out.Write(curr)
		}
	}()

	return
}
func repreader(find string, replace string, in Conn) io.Reader {
	pr, pw := io.Pipe()

	reader := bufio.NewReader(in)
	writer := bufio.NewWriter(pw)

	go func() {
		var curr string
		var err error
		for {
			curr, err = reader.ReadString('\n')
			if err != nil {
				in.Debug("READER: Finalizing with [%s]", curr)
				writer.Write([]byte(curr))
				break
			}
			tcurr := strings.TrimSpace(curr)
			if strings.Index(tcurr, "Host: ") == 0 && tcurr == strings.TrimSpace(find) {
				curr = strings.Replace(curr, find, replace, 1)
				in.Info("READER: HostHeader replaced: %s -> %s", find, strings.TrimSpace(curr))
			}
			writer.Write([]byte(curr))
		}
	}()

	return pr
}
*/
