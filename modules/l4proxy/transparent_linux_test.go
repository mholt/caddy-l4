//go:build linux

package l4proxy

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestTransparentSocketOption(t *testing.T) {
	for network, want := range map[string][2]int{
		"tcp4": {unix.SOL_IP, unix.IP_TRANSPARENT},
		"udp4": {unix.SOL_IP, unix.IP_TRANSPARENT},
		"tcp6": {unix.SOL_IPV6, unix.IPV6_TRANSPARENT},
		"udp6": {unix.SOL_IPV6, unix.IPV6_TRANSPARENT},
	} {
		t.Run(network, func(t *testing.T) {
			level, option := transparentSocketOption(network)
			if level != want[0] || option != want[1] {
				t.Fatalf("transparentSocketOption(%q) = (%d, %d), want (%d, %d)",
					network, level, option, want[0], want[1])
			}
		})
	}
}
