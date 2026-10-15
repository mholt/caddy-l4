//go:build !linux

package l4proxy

import (
	"fmt"
	"syscall"
)

const transparentProxySupported = false

func transparentSocketControl(_, _ string, _ syscall.RawConn) error {
	return fmt.Errorf("transparent proxying is only supported on Linux")
}
