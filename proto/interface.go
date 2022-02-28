package proto

import (
	"pgrok/conn"
)

type Protocol interface {
	GetName() string
	WrapConn(conn.Conn, string, interface{}) conn.Conn
}
