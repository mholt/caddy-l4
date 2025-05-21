//go:build !linux && !windows

package layer4

import "net"

var listenConfig = net.ListenConfig{}

func readFrom(pc net.PacketConn, buf []byte) (int, net.Addr, net.Addr, error) {
	n, addr, err := pc.ReadFrom(buf)
	return n, addr, nil, err
}
