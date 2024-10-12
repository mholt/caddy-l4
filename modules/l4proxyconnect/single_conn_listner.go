package l4proxyconnect

import (
	"net"
	"net/http"
)

type singleConnListener struct {
	conn      net.Conn
	ch        chan bool
	closeChan chan bool
}

func NewSingleConnListener(conn net.Conn) net.Listener {
	l := &singleConnListener{
		conn:      conn,
		ch:        make(chan bool, 1),
		closeChan: make(chan bool, 1),
	}

	l.ch <- true
	return l
}

// Accept implements net.Listener
func (l *singleConnListener) Accept() (net.Conn, error) {
	select {
	case <-l.ch:
		return l.conn, nil
	case <-l.closeChan:
		return l.conn, http.ErrServerClosed
	}
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

func (l *singleConnListener) Close() error {
	l.closeChan <- true
	return l.conn.Close()
}
