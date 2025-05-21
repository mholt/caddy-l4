//go:build windows

package layer4

import (
	"net"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	hdrSize = unsafe.Sizeof(windows.WSACMSGHDR{})
	oobSize = 64 // enough to hold the local address
)

var listenConfig = net.ListenConfig{
	Control: func(network, address string, c syscall.RawConn) error {
		if !strings.HasPrefix(network, "udp") {
			return nil
		}

		var syscallErr error
		err := c.Control(func(fd uintptr) {
			// TODO: check if the address is ipv6 only
			syscallErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_PKTINFO, 1)
			if strings.HasSuffix(network, "6") && syscallErr == nil {
				syscallErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, windows.IPV6_PKTINFO, 1)
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
		hdr := (*windows.WSACMSGHDR)(unsafe.Pointer(&oob[0]))
		if hdr.Level == windows.IPPROTO_IP && hdr.Type == windows.IP_PKTINFO {
			addr := *(*windows.IN_PKTINFO)(unsafe.Pointer(&oob[hdrSize]))
			lAddr.IP = addr.Addr[:]
		} else if hdr.Level == windows.IPPROTO_IPV6 && hdr.Type == windows.IPV6_PKTINFO {
			addr := *(*windows.IN6_PKTINFO)(unsafe.Pointer(&oob[hdrSize]))
			lAddr.IP = addr.Addr[:]
		}
		return n, rAddr, lAddr, nil
	}
	n, addr, err := pc.ReadFrom(buf)
	return n, addr, nil, err
}
