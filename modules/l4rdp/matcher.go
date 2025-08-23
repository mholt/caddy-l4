// Copyright 2024 VNXME
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package l4rdp

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&MatchRDP{})
}

// MatchRDP is able to match RDP connections.
type MatchRDP struct {
	CookieHash       string   `json:"cookie_hash,omitempty"`
	CookieHashRegexp string   `json:"cookie_hash_regexp,omitempty"`
	CookieIPs        []string `json:"cookie_ips,omitempty"`
	CookiePorts      []uint16 `json:"cookie_ports,omitempty"`
	CustomInfo       string   `json:"custom_info,omitempty"`
	CustomInfoRegexp string   `json:"custom_info_regexp,omitempty"`

	cookieIPs []netip.Prefix

	cookieHashRegexp *regexp.Regexp
	customInfoRegexp *regexp.Regexp
}

// CaddyModule returns the Caddy module information.
func (m *MatchRDP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.rdp",
		New: func() caddy.Module { return new(MatchRDP) },
	}
}

// Match returns true if the connection looks like RDP.
func (m *MatchRDP) Match(cx *layer4.Connection) (bool, error) {
	// Replace placeholders in filters
	repl := cx.Context.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	cookieHash := repl.ReplaceAll(m.CookieHash, "")
	cookieHash = cookieHash[:min(RDPCookieHashBytesMax, uint16(len(cookieHash)))] //nolint:gosec // disable G115
	customInfo := repl.ReplaceAll(m.CustomInfo, "")
	customInfo = customInfo[:min(RDPCustomInfoBytesMax, uint16(len(customInfo)))] //nolint:gosec // disable G115

	// Read a number of bytes to parse headers
	headerBuf := make([]byte, RDPConnReqBytesMin)
	n, err := io.ReadFull(cx, headerBuf)
	if err != nil || n < int(RDPConnReqBytesMin) {
		return false, err
	}

	// Parse TPKTHeader
	h := &TPKTHeader{}
	if err = h.FromBytes(headerBuf[TPKTHeaderBytesStart : TPKTHeaderBytesStart+TPKTHeaderBytesTotal]); err != nil {
		return false, nil
	}

	// Validate TPKTHeader
	if h.Version != TPKTHeaderVersion || h.Reserved != TPKTHeaderReserved ||
		h.Length < RDPConnReqBytesMin || h.Length > RDPConnReqBytesMax {
		return false, nil
	}

	// Parse X224Crq
	x := &X224Crq{}
	if err = x.FromBytes(headerBuf[X224CrqBytesStart : X224CrqBytesStart+X224CrqBytesTotal]); err != nil {
		return false, nil
	}

	// Validate X224Crq
	if x.TypeCredit != X224CrqTypeCredit || x.DstRef != X224CrqDstRef ||
		x.SrcRef != X224CrqSrcRef || x.ClassOptions != X224CrqClassOptions ||
		uint16(x.Length) != (h.Length-TPKTHeaderBytesTotal-1) {
		return false, nil
	}

	// Calculate and validate payload length
	// NOTE: at this stage we can't be absolutely sure that the protocol is RDP, though payloads are optional.
	// This behaviour may be changed in the future if there are many false negative matches due to some RDP
	// clients sending RDP connection requests containing TPKTHeader and X224Crq headers only.
	payloadBytesTotal := uint16(x.Length) - (X224CrqBytesTotal - 1)
	if payloadBytesTotal == 0 {
		return false, nil
	}

	// Read a number of bytes to parse payload
	payloadBuf := make([]byte, payloadBytesTotal)
	n, err = io.ReadFull(cx, payloadBuf)
	if err != nil || n < int(payloadBytesTotal) {
		return false, err
	}

	// Validate the remaining connection buffer
	// NOTE: if at least 1 byte remains, we can technically be sure, the protocol isn't RDP.
	// This behaviour may be changed in the future if there are many false negative matches.
	extraBuf := make([]byte, 1)
	n, err = io.ReadFull(cx, extraBuf)
	if err == nil && n == len(extraBuf) {
		return false, err
	}

	// Find CRLF which divides token/cookie from RDPNegReq and RDPCorrInfo
	var RDPNegReqBytesStart uint16 = 0
	for index, b := range payloadBuf {
		if b == ASCIIByteCR && payloadBuf[index+1] == ASCIIByteLF {
			// start after CR LF
			RDPNegReqBytesStart = uint16(index) + 2 //nolint:gosec // disable G115
			break
		}
	}

	// Process optional RDPCookie
	var hasValidCookie bool
	for RDPNegReqBytesStart >= RDPCookieBytesMin {
		RDPCookieBytesTotal := RDPNegReqBytesStart // include CR LF

		// Parse RDPCookie
		c := string(payloadBuf[RDPCookieBytesStart : RDPCookieBytesStart+RDPCookieBytesTotal])

		// Validate RDPCookie
		if RDPCookieBytesTotal > RDPCookieBytesMax || !strings.HasPrefix(c, RDPCookiePrefix) {
			break
		}

		// Extract hash (username truncated to max number of characters from the left)
		// NOTE: according to mstsc.exe tests, if "domain" and "username" are provided, hash will be "domain/us"
		hashBytesStart := uint16(len(RDPCookiePrefix))
		hashBytesTotal := RDPCookieBytesTotal - hashBytesStart - 2 // exclude CR LF
		hash := c[hashBytesStart : hashBytesStart+hashBytesTotal]

		// Add hash to the replacer
		repl.Set("l4.rdp.cookie_hash", hash)

		// Full match
		if len(cookieHash) > 0 && cookieHash != hash {
			break
		}

		// Regexp match
		if len(m.CookieHashRegexp) > 0 && !m.cookieHashRegexp.MatchString(hash) {
			break
		}

		hasValidCookie = true
		break //nolint:staticcheck
	}

	// NOTE: we can stop validation because hash hasn't matched
	if !hasValidCookie && (len(cookieHash) > 0 || len(m.CookieHashRegexp) > 0) {
		return false, nil
	}

	// Process optional RDPToken
	var hasValidToken bool
	for !hasValidCookie && RDPNegReqBytesStart >= RDPTokenBytesMin {
		RDPTokenBytesTotal := RDPNegReqBytesStart // include CR LF

		// Parse RDPToken
		t := &RDPToken{}
		if err = t.FromBytes(payloadBuf[RDPTokenBytesStart : RDPTokenBytesStart+RDPTokenBytesTotal]); err != nil {
			break
		}

		// Validate RDPToken
		if t.Version != RDPTokenVersion || t.Reserved != RDPTokenReserved ||
			t.Length != RDPTokenBytesTotal || t.LengthIndicator != uint8(t.Length-5) || //nolint:gosec // disable G115
			t.TypeCredit != x.TypeCredit || t.DstRef != x.DstRef || t.SrcRef != x.SrcRef ||
			t.ClassOptions != x.ClassOptions {
			break
		}

		// NOTE: RDPToken without a cookie value is technically correct
		l := t.Length - RDPTokenBytesMin
		if l == 0 {
			hasValidToken = (len(m.cookieIPs) == 0) && (len(m.CookiePorts) == 0)
			break
		}

		// Validate RDPToken.Optional (1/6)
		// NOTE: maximum length has been calculated for a cookie having IPv4 address. If it supports IPv6 addresses,
		// RDPTokenOptionalCookieBytesMax constant has to be adjusted accordingly. The IP parsing process
		// would also need to be redesigned to provide for solutions relevant for both address families.
		RDPTokenOptionalCookieBytesTotal := l - 2 // exclude CR LF
		if RDPTokenOptionalCookieBytesTotal < RDPTokenOptionalCookieBytesMin ||
			RDPTokenOptionalCookieBytesTotal > RDPTokenOptionalCookieBytesMax {
			break
		}

		// Validate RDPToken.Optional (2/6)
		c := string(t.Optional[RDPTokenOptionalCookieBytesStart:RDPTokenOptionalCookieBytesTotal])
		if !strings.HasPrefix(c, RDPTokenOptionalCookiePrefix) {
			break
		}

		// Validate RDPToken.Optional (3/6)
		d := strings.Split(c[len(RDPTokenOptionalCookiePrefix):], string(RDPTokenOptionalCookieSeparator))
		if len(d) != 3 {
			break
		}

		// Validate RDPToken.Optional (4/6)
		ipStr, portStr, reservedStr := d[0], d[1], d[2]
		if reservedStr != RDPTokenOptionalCookieReserved {
			break
		}

		// Validate RDPToken.Optional (5/6)
		ipNum, err := strconv.ParseUint(ipStr, 10, 32)
		if err != nil {
			break
		}
		ipBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(ipBuf, uint32(ipNum))
		ipVal := make(net.IP, 4)
		if err = binary.Read(bytes.NewBuffer(ipBuf), binary.BigEndian, &ipVal); err != nil {
			break
		}

		// Validate RDPToken.Optional (6/6)
		portNum, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			break
		}
		portBuf := make([]byte, 4)
		binary.LittleEndian.PutUint16(portBuf, uint16(portNum))
		portVal := uint16(0)
		if err = binary.Read(bytes.NewBuffer(portBuf), binary.BigEndian, &portVal); err != nil {
			break
		}

		// Add IP and port to the replacer
		repl.Set("l4.rdp.cookie_ip", ipVal.String())
		repl.Set("l4.rdp.cookie_port", strconv.Itoa(int(portVal)))

		if len(m.cookieIPs) > 0 {
			var found bool
			for _, prefix := range m.cookieIPs {
				if prefix.Contains(netip.AddrFrom4([4]byte(ipVal))) {
					found = true
					break
				}
			}
			if !found {
				break
			}
		}

		if len(m.CookiePorts) > 0 {
			if !slices.Contains(m.CookiePorts, portVal) {
				break
			}
		}

		hasValidToken = true
		break //nolint:staticcheck
	}

	// NOTE: we can stop validation because IPs or ports haven't matched
	if !hasValidToken && (len(m.cookieIPs) > 0 || len(m.CookiePorts) > 0) {
		return false, nil
	}

	// Process RDPCustom
	var hasValidCustom bool
	for !(hasValidCookie || hasValidToken) && RDPNegReqBytesStart >= RDPCustomBytesMin { //nolint:staticcheck
		RDPCustomBytesTotal := RDPNegReqBytesStart // include CR LF

		// Parse RDPCustom
		c := string(payloadBuf[RDPCustomBytesStart : RDPCustomBytesStart+RDPCustomBytesTotal])

		// Validate RDPCustom
		if RDPCustomBytesTotal > RDPCustomBytesMax {
			break
		}

		// Extract info (everything before CR LF)
		// NOTE: according to Apache Guacamole tests, if "load balance info/cookie" option is non-empty,
		// its contents is included into the RDP Connection Request packet without any changes
		infoBytesTotal := RDPCustomBytesTotal - RDPCustomInfoBytesStart - 2 // exclude CR LF
		info := c[RDPCustomInfoBytesStart : RDPCustomInfoBytesStart+infoBytesTotal]

		// Add info to the replacer
		repl.Set("l4.rdp.custom_info", info)

		// Full match
		if len(customInfo) > 0 && customInfo != info {
			break
		}

		// Regexp match
		if len(m.CustomInfoRegexp) > 0 && !m.customInfoRegexp.MatchString(info) {
			break
		}

		hasValidCustom = true
		break //nolint:staticcheck
	}

	// NOTE: we can stop validation because info hasn't matched
	if !hasValidCustom && (len(customInfo) > 0 || len(m.CustomInfoRegexp) > 0) {
		return false, nil
	}

	// Validate RDPCookie, RDPToken and RDPCustom presence to match payload boundaries
	// NOTE: if there is anything before CR LF, but RDPCookie and RDPToken parsing has failed,
	// we can technically be sure, the protocol isn't RDP. However, given RDPCustom has no mandatory prefix
	// by definition (it's an extension to the official documentation), this condition can barely be met.
	if RDPNegReqBytesStart > 0 && (!hasValidCookie && !hasValidToken && !hasValidCustom) {
		return false, nil
	}

	// NOTE: Given RDPNegReq and RDPCorrInfo are optional, we have found CR LF at the end of the payload,
	// and all the validations above have passed, we can reasonably treat the protocol in question as RDP.
	// This behaviour may be changed in the future if there are many false positive matches.
	if RDPNegReqBytesStart == payloadBytesTotal {
		return true, nil
	}

	// Validate RDPNegReq boundaries
	if RDPNegReqBytesStart+RDPNegReqBytesTotal > payloadBytesTotal {
		return false, nil
	}

	// Parse RDPNegReq
	r := &RDPNegReq{}
	if err = r.FromBytes(payloadBuf[RDPNegReqBytesStart : RDPNegReqBytesStart+RDPNegReqBytesTotal]); err != nil {
		return false, nil
	}

	// Validate RDPNegReq
	// NOTE: for simplicity, we treat a RDPNegReq with all flags and protocols set as valid.
	// This behaviour may be changed in the future if there are many false positive matches.
	if r.Type != RDPNegReqType || r.Length != RDPNegReqLength ||
		r.Flags|RDPNegReqFlagsAll != RDPNegReqFlagsAll || r.Protocols|RDPNegReqProtocolsAll != RDPNegReqProtocolsAll ||
		(r.Protocols&RDPNegReqProtoHybridEx == RDPNegReqProtoHybridEx && r.Protocols&RDPNegReqProtoHybrid == 0) ||
		(r.Protocols&RDPNegReqProtoHybrid == RDPNegReqProtoHybrid && r.Protocols&RDPNegReqProtoSSL == 0) {
		return false, nil
	}

	// Validate RDPCorrInfo presence to match payload boundaries
	// NOTE: nothing must be present after RDPNegReq unless RDPNegReqFlagCorrInfo is set,
	// otherwise we can reasonably treat the connection as RDP, given all the validations above have passed.
	if r.Flags&RDPNegReqFlagCorrInfo == 0 {
		if RDPNegReqBytesStart+RDPNegReqBytesTotal < payloadBytesTotal {
			return false, nil
		} else {
			return true, nil
		}
	}

	// Validate RDPCorrInfo boundaries
	RDPCorrInfoBytesStart := RDPNegReqBytesStart + RDPNegReqBytesTotal
	if RDPCorrInfoBytesStart+RDPCorrInfoBytesTotal > payloadBytesTotal {
		return false, nil
	}

	// Parse RDPCorrInfo
	i := &RDPCorrInfo{}
	if err = i.FromBytes(payloadBuf[RDPCorrInfoBytesStart : RDPCorrInfoBytesStart+RDPCorrInfoBytesTotal]); err != nil {
		return false, nil
	}

	// Validate RDPCorrInfo (1/3)
	// NOTE: the first byte of RDPCorrInfo.Identity must not be equal 0x00 or 0xF4
	if i.Type != RDPCorrInfoType || i.Flags != RDPCorrInfoFlags || i.Length != RDPCorrInfoLength ||
		i.Identity[0] == RDPCorrInfoReserved || i.Identity[0] == RDPCorrInfoIdentityF4 {
		return false, nil
	}

	// Validate RDPCorrInfo (2/3)
	// NOTE: no byte of RDPCorrInfo.Identity must be equal 0x0D
	for _, b := range i.Identity {
		if b == ASCIIByteCR {
			return false, nil
		}
	}

	// Add base64 of identity bytes to the replacer
	repl.Set("l4.rdp.correlation_id", base64.StdEncoding.EncodeToString(i.Identity[:]))

	// Validate RDPCorrInfo (3/3)
	// NOTE: any byte of RDPCorrInfo.Reserved must be equal 0x00
	for _, b := range i.Reserved {
		if b != RDPCorrInfoReserved {
			return false, nil
		}
	}

	return true, nil
}

// Provision parses m's IP ranges, either from IP or CIDR expressions, and regular expressions.
func (m *MatchRDP) Provision(_ caddy.Context) (err error) {
	repl := caddy.NewReplacer()
	for _, cookieAddrOrCIDR := range m.CookieIPs {
		cookieAddrOrCIDR = repl.ReplaceAll(cookieAddrOrCIDR, "")
		prefix, err := caddyhttp.CIDRExpressionToPrefix(cookieAddrOrCIDR)
		if err != nil {
			return err
		}
		m.cookieIPs = append(m.cookieIPs, prefix)
	}
	m.cookieHashRegexp, err = regexp.Compile(repl.ReplaceAll(m.CookieHashRegexp, ""))
	if err != nil {
		return err
	}
	m.customInfoRegexp, err = regexp.Compile(repl.ReplaceAll(m.CustomInfoRegexp, ""))
	if err != nil {
		return err
	}
	return nil
}

// UnmarshalCaddyfile sets up the MatchRDP from Caddyfile tokens. Syntax:
//
//	rdp {
//		cookie_hash <value>
//	}
//	rdp {
//		cookie_hash_regexp <value>
//	}
//	rdp {
//		cookie_ip <ranges...>
//		cookie_port <ports...>
//	}
//	rdp {
//		custom_info <value>
//	}
//	rdp {
//		custom_info_regexp <value>
//	}
//	rdp
//
// Note: according to the protocol documentation, RDP cookies and tokens are optional, i.e. it depends on the client
// whether they are included in the first packet (RDP Connection Request) or not. Besides, no valid RDP CR packet must
// contain cookie_hash ("mstshash") and cookie_ip:cookie_port ("msts") at the same time, i.e. Match will always return
// false if cookie_hash and any of cookie_ip and cookie_port are set simultaneously. If this matcher has cookie_hash
// option, but a valid RDP CR packet doesn't have it, Match will return false. If this matcher has a set of cookie_ip
// and cookie_port options, or any of them, but a valid RDP CR packet doesn't have them, Match will return false.
//
// There are some RDP clients (e.g. Apache Guacamole) that support any text to be included into an RDP CR packet
// instead of "mstshash" and "msts" cookies for load balancing and/or routing purposes, parsed here as custom_info.
// If this matcher has custom_info option, but a valid RDP CR packet doesn't have it, Match will return false.
// If custom_info option is combined with cookie_hash, cookie_ip or cookie_port, Match will return false as well.
func (m *MatchRDP) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// No same-line arguments are supported
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	var hasCookieHash, hasCookieIPOrPort, hasCustomInfo bool
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "cookie_hash":
			if hasCookieIPOrPort || hasCustomInfo {
				return d.Errf("%s option '%s' can't be combined with other options", wrapper, optionName)
			}
			if hasCookieHash {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			_, val := d.NextArg(), d.Val()
			m.CookieHash, hasCookieHash = val, true
		case "cookie_hash_regexp":
			if hasCookieIPOrPort || hasCustomInfo {
				return d.Errf("%s option '%s' can't be combined with other options", wrapper, optionName)
			}
			if hasCookieHash {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			_, val := d.NextArg(), d.Val()
			m.CookieHashRegexp, hasCookieHash = val, true
		case "cookie_ip":
			if hasCookieHash || hasCustomInfo {
				return d.Errf("%s option '%s' can only be combined with 'cookie_port' option", wrapper, optionName)
			}
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			for d.NextArg() {
				val := d.Val()
				if val == "private_ranges" {
					m.CookieIPs = append(m.CookieIPs, caddyhttp.PrivateRangesCIDR()...)
					continue
				}
				m.CookieIPs = append(m.CookieIPs, val)
			}
			hasCookieIPOrPort = true
		case "cookie_port":
			if hasCookieHash || hasCustomInfo {
				return d.Errf("%s option '%s' can only be combined with 'cookie_ip' option", wrapper, optionName)
			}
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			for d.NextArg() {
				val := d.Val()
				num, err := strconv.ParseUint(val, 10, 16)
				if err != nil {
					return d.Errf("parsing %s option '%s': %v", wrapper, optionName, err)
				}
				m.CookiePorts = append(m.CookiePorts, uint16(num))
			}
			hasCookieIPOrPort = true
		case "custom_info":
			if hasCookieHash || hasCookieIPOrPort {
				return d.Errf("%s option '%s' can't be combined with other options", wrapper, optionName)
			}
			if hasCustomInfo {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			_, val := d.NextArg(), d.Val()
			m.CustomInfo, hasCustomInfo = val, true
		case "custom_info_regexp":
			if hasCookieHash || hasCookieIPOrPort {
				return d.Errf("%s option '%s' can't be combined with other options", wrapper, optionName)
			}
			if hasCustomInfo {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			_, val := d.NextArg(), d.Val()
			m.CustomInfoRegexp, hasCustomInfo = val, true
		default:
			return d.ArgErr()
		}

		// No nested blocks are supported
		if d.NextBlock(nesting + 1) {
			return d.Errf("malformed %s option '%s': blocks are not supported", wrapper, optionName)
		}
	}

	return nil
}

type RDPCorrInfo struct {
	Type     uint8
	Flags    uint8
	Length   uint16
	Identity [16]uint8
	Reserved [16]uint8
}

func (i *RDPCorrInfo) FromBytes(src []byte) error {
	return binary.Read(bytes.NewBuffer(src), RDPCorrInfoBytesOrder, i)
}

func (i *RDPCorrInfo) ToBytes() ([]byte, error) {
	dst := bytes.NewBuffer(make([]byte, 0, RDPCorrInfoBytesTotal))
	err := binary.Write(dst, RDPCorrInfoBytesOrder, i)
	return dst.Bytes(), err
}

type RDPNegReq struct {
	Type      uint8
	Flags     uint8
	Length    uint16
	Protocols uint32
}

func (r *RDPNegReq) FromBytes(src []byte) error {
	return binary.Read(bytes.NewBuffer(src), RDPNegReqBytesOrder, r)
}

func (r *RDPNegReq) ToBytes() ([]byte, error) {
	dst := bytes.NewBuffer(make([]byte, 0, RDPNegReqBytesTotal))
	err := binary.Write(dst, RDPNegReqBytesOrder, r)
	return dst.Bytes(), err
}

type RDPToken struct {
	Version         uint8
	Reserved        uint8
	Length          uint16
	LengthIndicator uint8
	TypeCredit      uint8
	DstRef          uint16
	SrcRef          uint16
	ClassOptions    uint8
	Optional        []uint8
}

func (t *RDPToken) FromBytes(src []byte) error {
	buf := bytes.NewBuffer(src)
	if err := binary.Read(buf, RDPTokenBytesOrder, &t.Version); err != nil {
		return err
	}
	if err := binary.Read(buf, RDPTokenBytesOrder, &t.Reserved); err != nil {
		return err
	}
	if err := binary.Read(buf, RDPTokenBytesOrder, &t.Length); err != nil {
		return err
	}
	if err := binary.Read(buf, RDPTokenBytesOrder, &t.LengthIndicator); err != nil {
		return err
	}
	if err := binary.Read(buf, RDPTokenBytesOrder, &t.TypeCredit); err != nil {
		return err
	}
	if err := binary.Read(buf, RDPTokenBytesOrder, &t.DstRef); err != nil {
		return err
	}
	if err := binary.Read(buf, RDPTokenBytesOrder, &t.SrcRef); err != nil {
		return err
	}
	if err := binary.Read(buf, RDPTokenBytesOrder, &t.ClassOptions); err != nil {
		return err
	}
	if buf.Len() > 0 {
		t.Optional = append(t.Optional, buf.Bytes()...)
	}
	return nil
}

func (t *RDPToken) ToBytes() ([]byte, error) {
	dst := bytes.NewBuffer(make([]byte, 0, RDPTokenBytesMin+uint16(len(t.Optional)))) //nolint:gosec // disable G115
	if err := binary.Write(dst, RDPTokenBytesOrder, &t.Version); err != nil {
		return nil, err
	}
	if err := binary.Write(dst, RDPTokenBytesOrder, &t.Reserved); err != nil {
		return nil, err
	}
	if err := binary.Write(dst, RDPTokenBytesOrder, &t.Length); err != nil {
		return nil, err
	}
	if err := binary.Write(dst, RDPTokenBytesOrder, &t.LengthIndicator); err != nil {
		return nil, err
	}
	if err := binary.Write(dst, RDPTokenBytesOrder, &t.TypeCredit); err != nil {
		return nil, err
	}
	if err := binary.Write(dst, RDPTokenBytesOrder, &t.DstRef); err != nil {
		return nil, err
	}
	if err := binary.Write(dst, RDPTokenBytesOrder, &t.SrcRef); err != nil {
		return nil, err
	}
	if err := binary.Write(dst, RDPTokenBytesOrder, &t.ClassOptions); err != nil {
		return nil, err
	}
	return append(dst.Bytes(), t.Optional...), nil
}

type TPKTHeader struct {
	Version  byte
	Reserved byte
	Length   uint16
}

func (h *TPKTHeader) FromBytes(src []byte) error {
	return binary.Read(bytes.NewBuffer(src), TPKTHeaderBytesOrder, h)
}

func (h *TPKTHeader) ToBytes() ([]byte, error) {
	dst := bytes.NewBuffer(make([]byte, 0, TPKTHeaderBytesTotal))
	err := binary.Write(dst, TPKTHeaderBytesOrder, h)
	return dst.Bytes(), err
}

type X224Crq struct {
	Length       uint8
	TypeCredit   uint8
	DstRef       uint16
	SrcRef       uint16
	ClassOptions uint8
}

func (x *X224Crq) FromBytes(src []byte) error {
	return binary.Read(bytes.NewBuffer(src), X224CrqBytesOrder, x)
}

func (x *X224Crq) ToBytes() ([]byte, error) {
	dst := bytes.NewBuffer(make([]byte, 0, X224CrqBytesTotal))
	err := binary.Write(dst, X224CrqBytesOrder, x)
	return dst.Bytes(), err
}

// Interface guards
var (
	_ caddy.Provisioner     = (*MatchRDP)(nil)
	_ caddyfile.Unmarshaler = (*MatchRDP)(nil)
	_ layer4.ConnMatcher    = (*MatchRDP)(nil)
)

// Constants specific to RDP Connection Request. Packet structure is described in the comments below.
const (
	ASCIIByteCR uint8 = 0x0D
	ASCIIByteLF uint8 = 0x0A

	RDPCookieBytesMax            = uint16(X224CrqLengthMax) - (X224CrqBytesTotal - 1)
	RDPCookieBytesMin            = uint16(len(RDPCookiePrefix)) + 1 + 2 // 2 bytes for CR LF and at least 1 character
	RDPCookieBytesStart   uint16 = 0
	RDPCookieHashBytesMax        = RDPCookieBytesMax - (RDPCookieBytesMin - 1)
	RDPCookiePrefix              = "Cookie: mstshash="

	RDPCorrInfoBytesTotal uint16 = 36
	RDPCorrInfoType       uint8  = 0x06
	RDPCorrInfoFlags      uint8  = 0x00
	RDPCorrInfoLength            = RDPCorrInfoBytesTotal
	RDPCorrInfoIdentityF4 uint8  = 0xF4
	RDPCorrInfoReserved   uint8  = 0x00

	RDPCustomBytesMax              = uint16(X224CrqLengthMax) - (X224CrqBytesTotal - 1)
	RDPCustomBytesMin       uint16 = 1 + 2 // 2 bytes for CR LF and at least 1 character
	RDPCustomBytesStart     uint16 = 0
	RDPCustomInfoBytesMax          = RDPCustomBytesMax - (RDPCustomBytesMin - 1)
	RDPCustomInfoBytesStart uint16 = 0

	RDPNegReqBytesTotal    uint16 = 8
	RDPNegReqType          uint8  = 0x01
	RDPNegReqFlagAdminMode uint8  = 0x01
	RDPNegReqFlagAuthMode  uint8  = 0x02
	RDPNegReqFlagCorrInfo  uint8  = 0x08
	RDPNegReqFlagsAll             = RDPNegReqFlagAdminMode | RDPNegReqFlagAuthMode | RDPNegReqFlagCorrInfo
	RDPNegReqLength               = RDPNegReqBytesTotal
	RDPNegReqProtoStandard uint32 = 0x00000000
	RDPNegReqProtoSSL      uint32 = 0x00000001
	RDPNegReqProtoHybrid   uint32 = 0x00000002
	RDPNegReqProtoRDSTLS   uint32 = 0x00000004
	RDPNegReqProtoHybridEx uint32 = 0x00000008
	RDPNegReqProtoRDSAAD   uint32 = 0x00000010
	RDPNegReqProtocolsAll         = RDPNegReqProtoStandard | RDPNegReqProtoSSL | RDPNegReqProtoHybrid |
		RDPNegReqProtoRDSTLS | RDPNegReqProtoHybridEx | RDPNegReqProtoRDSAAD

	RDPTokenBytesMin               uint16 = 11
	RDPTokenBytesStart             uint16 = 0
	RDPTokenVersion                uint8  = 0x03
	RDPTokenReserved               uint8  = 0x00
	RDPTokenOptionalCookieBytesMax        = uint16(len(RDPTokenOptionalCookiePrefix)) +
		10 + // decimal representation of 2^32 has 10 digits, so 10 bytes are required at most
		2 + // 2 bytes for separators
		5 + // decimal representation of 2^16 has 5 digits, so 5 bytes are required at most
		4 + // 4 reserved bytes for trailing zeros
		2 + // 2 bytes for CR LF
		0
	RDPTokenOptionalCookieBytesMin = uint16(len(RDPTokenOptionalCookiePrefix)) +
		1 + // at least 1 byte (1 digit) for IP
		2 + // 2 bytes for separators
		1 + // at least 1 byte (1 digit) for port
		4 + // 4 reserved bytes for trailing zeros
		2 + // 2 bytes for CR LF
		0
	RDPTokenOptionalCookieBytesStart uint16 = 0
	RDPTokenOptionalCookiePrefix            = "Cookie: msts="
	RDPTokenOptionalCookieReserved          = "0000"
	RDPTokenOptionalCookieSeparator  uint8  = 0x2E

	TPKTHeaderBytesStart uint16 = 0
	TPKTHeaderBytesTotal uint16 = 4
	TPKTHeaderReserved   uint8  = 0x00
	TPKTHeaderVersion    uint8  = 0x03

	X224CrqBytesStart          = TPKTHeaderBytesStart + TPKTHeaderBytesTotal
	X224CrqBytesTotal   uint16 = 7
	X224CrqLengthMax    uint8  = 254  // 255 is reserved for possible extensions
	X224CrqTypeCredit   uint8  = 0xE0 // also known as TPDU code
	X224CrqDstRef       uint16 = 0x0000
	X224CrqSrcRef       uint16 = 0x0000
	X224CrqClassOptions uint8  = 0x00

	RDPConnReqBytesMax = TPKTHeaderBytesTotal + uint16(X224CrqLengthMax) + 1 // 1 byte for X224Crq.Length
	RDPConnReqBytesMin = TPKTHeaderBytesTotal + X224CrqBytesTotal
)

// Variables specific to RDP Connection Request. Packet structure is described in the comments below.
var (
	RDPCorrInfoBytesOrder = binary.LittleEndian
	RDPNegReqBytesOrder   = binary.LittleEndian
	RDPTokenBytesOrder    = binary.BigEndian
	TPKTHeaderBytesOrder  = binary.BigEndian
	X224CrqBytesOrder     = binary.BigEndian
)

// Remote Desktop Protocol (RDP)
// ref: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d2a48824-e362-4ed1-bda8-0eb7cbb28b8c
// ref: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/18a27ef9-6f9a-4501-b000-94b1fe3c2c10
// ref: https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-RDPBCGR/%5BMS-RDPBCGR%5D.pdf
// X.224 CR PDU, a packet each RDP connections begins with, has at least 11 bytes and may contain 6 elements:
//
//	ref: https://go.microsoft.com/fwlink/?LinkId=90541
//	1. MANDATORY tpktHeader (4 bytes):
//		tpktHeader.version (1 byte) must equal
//			0x03 = 0b00000011
//		tpktHeader.reserved (1 byte) must equal
//			0x00
//		tpktHeader.length (2 bytes) must equal the total length of tpktHeader, including:
//			tpktHeader, x224Crq, routingToken, cookie, rdpNegReq, rdpCorrelationInfo
//
//	ref: https://go.microsoft.com/fwlink/?LinkId=90588
//	2. MANDATORY x224Crq (7 bytes):
//		x224Crq.length (1 byte) must equal the total length of fixed and variable parts of x224Crq
//			0x0E = 0b00001110 - 14 = tpktHeader.length - 4 - 1
//		x224Crq.TypeCredit (1 byte) must equal
//			0xE0 = 0x11100000
//		x224Crq.dstRef (2 bytes) must equal
//			0x00
//		x224Crq.srcRef (2 bytes) must equal
//			0x00
//		x224Crq.classOptions (1 byte) must equal
//			0x00
//
//	ref: https://go.microsoft.com/fwlink/?LinkId=90204
//	3. OPTIONAL routingToken (variable length; must not be present if cookie is present):
//		routingToken.version (1 byte) must equal
//			0x03
//		routingToken.reserved (1 byte) must equal
//			0x00
//		routingToken.length (2 bytes, big-endian) must equal the total length of routingToken, including:
//			version, reserved, length, lengthIndicator, typeCredit, dstRef, srcRef, classOptions, optional
//		routingToken.lengthIndicator (1 byte) must equal the total length of the following components:
//			typeCredit, dstRef, srcRef, classOptions, optional; i.e. it must be 5 bytes less than length
//		routingToken.typeCredit (1 byte) must equal
//			[???; it must probably equal to x224Crq.typeCredit]
//		routingToken.dstRef (2 bytes) must equal
//			[???; it must probably equal to x224Crq.dstRef]
//		routingToken.srcRef (2 bytes) must equal
//			[???; it must probably equal to x224Crq.srcRef]
//		routingToken.classOptions (1 byte) must equal
//			[???; it must probably equal to x224Crq.classOptions]
//		routingToken.optional (variable length) may contain a cookie (max 37 bytes) formatted as follows:
//			0x436F6F6B69653A206D7374733D (Cookie: msts=)
//			[IP']0x2E[PORT']0x2E[RESERVED] ([number].[number].[number])
//			0x0D0A (CR LF);
//			where decimal IP and PORT values are converted into hex, byte order is reversed,
//			then resulting hex values are converted back into decimals to get IP' and PORT',
//			and RESERVED must equal 0x30303030; see ref for additional guidance on cookie format
//
//	ref: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/cbe1ed0a-d320-4ea5-be5a-f2eb6e032853#Appendix_A_43
//	4. OPTIONAL cookie (ANSI string of variable length, max 28 bytes; must not be present if routingToken is present;
//	all Microsoft RDP clients >5.0 include cookie, if a username is specified before connecting):
//		0x436F6F6B69653A206D737473686173683D (Cookie: mstshash=)
//		[IDENTIFIER]
//		0x0D0A (CR LF);
//		where IDENTIFIER can be a "domain/username" string truncated to 9 symbols for a native client (mstsc.exe),
//		and an intact "username" string for Apache Guacamole (unless a load balance token/info field is set)
//
// 	ref: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/902b090b-9cb3-4efc-92bf-ee13373371e3
//	5. OPTIONAL rdpNegReq (8 bytes):
//		rdpNegReq.type (1 byte) must equal
//			0x01 (TYPE_RDP_NEG_REQ)
//		rdpNegReq.flags (1 byte) contains the following flags:
//			0x01 (RESTRICTED_ADMIN_MODE_REQUIRED)
//			0x02 (REDIRECTED_AUTHENTICATION_MODE_REQUIRED)
//			0x08 (CORRELATION_INFO_PRESENT)
//		rdpNegReq.length (2 bytes) must equal
//			0x0008 - 8 bytes in total
//		rdpNegReq.requestedProtocols (4 bytes) contains the following flags:
//			0x00000000 (PROTOCOL_RDP) - Standard RDP Security
//			0x00000001 (PROTOCOL_SSL) - TLS 1.0, 1.1, or 1.2
//			0x00000002 (PROTOCOL_HYBRID) - CredSSP, requires PROTOCOL_SSL flag
//			0x00000004 (PROTOCOL_RDSTLS) - RDSTLS protocol
//			0x00000008 (PROTOCOL_HYBRID_EX) - CredSSP with EUAR PDU, requires PROTOCOL_HYBRID flag
//			0x00000010 (PROTOCOL_RDSAAD) - RDS-AAD-Auth Security
//
//	6. OPTIONAL rdpCorrelationInfo (36 bytes; must only be present if CORRELATION_INFO_PRESENT is set in rdpNegReq.flags):
//		rdpCorrelationInfo.type (1 byte) must equal
//			0x06 (TYPE_RDP_CORRELATION_INFO)
//		rdpCorrelationInfo.flags (1 byte) must equal
//			0x00
//		rdpCorrelationInfo.length (2 bytes) must equal
//			0x0024 - 36 bytes in total
//		rdpCorrelationInfo.correlationId (16 bytes) - a unique identifier to associate with the connection;
//		the first byte SHOULD NOT have a value of 0x00 or 0xF4 and the value 0x0D SHOULD NOT be present at all
//		rdpCorrelationInfo.reserved (16 bytes) must equal
//			16x[0x00] - all bytes are zeroed
