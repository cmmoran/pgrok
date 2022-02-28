package proto

import (
	"pgrok/conn"
)

type Tcp struct{}

func NewTcp() *Tcp {
	return new(Tcp)
}

func (h *Tcp) GetName() string { return "tcp" }

func (h *Tcp) WrapConn(c conn.Conn, _ string, _ interface{}) conn.Conn {
	return c
}
