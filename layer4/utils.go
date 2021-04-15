package layer4

import (
	"fmt"
	"net"
	"strings"
)

func GetCIDRFromString(str string) (ipNet *net.IPNet, err error) {
	if strings.Contains(str, "/") {
		_, ipNet, err = net.ParseCIDR(str)
		if err != nil {
			return nil, fmt.Errorf("parsing CIDR expression: %v", err)
		}
	} else {
		ip := net.ParseIP(str)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address: %s", str)
		}
		mask := len(ip) * 8
		ipNet = &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(mask, mask),
		}
	}
	return
}

func GetCIDRsFromStrings(ss []string) (ipNets []*net.IPNet, err error) {
	ipNets = make([]*net.IPNet, len(ss))
	var ipNet *net.IPNet
	for i, str := range ss {
		ipNet, err = GetCIDRFromString(str)
		if err != nil {
			return
		}
		ipNets[i] = ipNet
	}
	return
}


func GetClientIP(cx *Connection) (net.IP, error) {
	remote := cx.Conn.RemoteAddr().String()

	ipStr, _, err := net.SplitHostPort(remote)
	if err != nil {
		ipStr = remote // OK; probably didn't have a port
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid client IP address: %s", ipStr)
	}

	return ip, nil
}