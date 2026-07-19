//go:build linux

package l4proxy

import (
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const transparentProxySupported = true

func transparentSocketControl(network, _ string, conn syscall.RawConn) error {
	var sockoptErr error
	err := conn.Control(func(fd uintptr) {
		level, option := transparentSocketOption(network)
		sockoptErr = unix.SetsockoptInt(int(fd), level, option, 1)
	})
	if err != nil {
		return err
	}
	return sockoptErr
}

func transparentSocketOption(network string) (int, int) {
	if strings.HasSuffix(network, "6") {
		return unix.SOL_IPV6, unix.IPV6_TRANSPARENT
	}
	return unix.SOL_IP, unix.IP_TRANSPARENT
}
