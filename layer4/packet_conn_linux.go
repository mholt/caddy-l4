//go:build linux

package layer4

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"syscall"
	"unsafe"
)

const (
	hdrSize = unsafe.Sizeof(syscall.Cmsghdr{})
	oobSize = 128 // enough to hold the local address
)

var listenConfig = net.ListenConfig{
	Control: func(network, address string, c syscall.RawConn) error {
		if !strings.HasPrefix(network, "udp") {
			return nil
		}

		var syscallErr error
		err := c.Control(func(fd uintptr) {
			// TODO: check if the address is ipv6 only
			syscallErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_PKTINFO, 1)
			if strings.HasSuffix(network, "6") && syscallErr == nil {
				syscallErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_RECVPKTINFO, 1)
			}
		})
		if err == nil {
			err = syscallErr
		}
		return err
	},
}

func readFrom(pc net.PacketConn, buf []byte) (int, net.Addr, net.Addr, error) {
	if udpConn, ok := pc.(*net.UDPConn); ok {
		oob := make([]byte, oobSize)
		n, oobN, _, rAddr, err := udpConn.ReadMsgUDP(buf, oob)
		if err != nil {
			return 0, nil, nil, err
		}
		if oobN < int(hdrSize) {
			return n, rAddr, nil, nil
		}

		la := udpConn.LocalAddr().(*net.UDPAddr)
		lAddr := &net.UDPAddr{
			IP:   la.IP,
			Port: la.Port,
			Zone: la.Zone,
		}
		br := bytes.NewReader(oob[:oobN])
		var hdr syscall.Cmsghdr
		_ = binary.Read(br, binary.LittleEndian, &hdr)
		if hdr.Level == syscall.IPPROTO_IP && hdr.Type == syscall.IP_PKTINFO {
			var addr syscall.Inet4Pktinfo
			_ = binary.Read(br, binary.LittleEndian, &addr)
			lAddr.IP = addr.Addr[:]
		} else if hdr.Level == syscall.IPPROTO_IPV6 && hdr.Type == syscall.IPV6_PKTINFO {
			var addr syscall.Inet6Pktinfo
			_ = binary.Read(br, binary.LittleEndian, &addr)
			lAddr.IP = addr.Addr[:]
		}
		return n, rAddr, lAddr, nil
	}
	n, addr, err := pc.ReadFrom(buf)
	return n, addr, nil, err
}
