// Copyright 2020 Matthew Holt
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

package l4tls

import (
	"crypto/tls"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

// Most of this file is borrowed from the Go standard library, ca. May 2020.
// It was written by the Go Authors and has this copyright:
//
//    Copyright 2009 The Go Authors. All rights reserved.
//    Use of this source code is governed by a BSD-style
//    license that can be found in the LICENSE file.
//
// This code has been modified since then.

func parseRawClientHello(data []byte) (info ClientHelloInfo) {
	defer func() {
		if len(info.SupportedVersions) == 0 {
			info.SupportedVersions = supportedVersionsFromMax(info.Version)
		}
	}()

	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&info.Version) || !s.ReadBytes(&info.Random, 32) ||
		!readUint8LengthPrefixed(&s, &info.SessionID) {
		return
	}

	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return
	}
	for !cipherSuites.Empty() {
		var suite uint16
		if !cipherSuites.ReadUint16(&suite) {
			return
		}
		if suite == scsvRenegotiation {
			info.SecureRenegotiationSupported = true
		}
		info.CipherSuites = append(info.CipherSuites, suite)
	}

	if !readUint8LengthPrefixed(&s, &info.CompressionMethods) {
		return
	}

	if s.Empty() {
		// ClientHello is optionally followed by extension data
		return
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return
		}

		// record that client advertised support for this extension
		info.Extensions = append(info.Extensions, extension)

		switch extension {
		case extensionServerName:
			// RFC 6066, Section 3
			var nameList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
				return
			}
			for !nameList.Empty() {
				var nameType uint8
				var serverName cryptobyte.String
				if !nameList.ReadUint8(&nameType) ||
					!nameList.ReadUint16LengthPrefixed(&serverName) ||
					serverName.Empty() {
					return
				}
				if nameType != 0 {
					continue
				}
				if len(info.ServerName) != 0 {
					// Multiple names of the same name_type are prohibited.
					return
				}
				info.ServerName = string(serverName)
				// An SNI value may not include a trailing dot.
				if strings.HasSuffix(info.ServerName, ".") {
					return
				}
			}
		case extensionStatusRequest:
			// RFC 4366, Section 3.6
			var statusType uint8
			var ignored cryptobyte.String
			if !extData.ReadUint8(&statusType) ||
				!extData.ReadUint16LengthPrefixed(&ignored) ||
				!extData.ReadUint16LengthPrefixed(&ignored) {
				return
			}
			info.OCSPStapling = statusType == statusTypeOCSP
		case extensionSupportedCurves:
			// RFC 4492, sections 5.1.1 and RFC 8446, Section 4.2.7
			var curves cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&curves) || curves.Empty() {
				return
			}
			for !curves.Empty() {
				var curve uint16
				if !curves.ReadUint16(&curve) {
					return
				}
				info.SupportedCurves = append(info.SupportedCurves, tls.CurveID(curve))
			}
		case extensionSupportedPoints:
			// RFC 4492, Section 5.1.2
			if !readUint8LengthPrefixed(&extData, &info.SupportedPoints) ||
				len(info.SupportedPoints) == 0 {
				return
			}
		case extensionSessionTicket:
			// RFC 5077, Section 3.2
			info.TicketSupported = true
			extData.ReadBytes(&info.SessionTicket, len(extData))
		case extensionSignatureAlgorithms:
			// RFC 5246, Section 7.4.1.4.1
			var sigAndAlgs cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
				return
			}
			for !sigAndAlgs.Empty() {
				var sigAndAlg uint16
				if !sigAndAlgs.ReadUint16(&sigAndAlg) {
					return
				}
				info.SignatureSchemes = append(
					info.SignatureSchemes, tls.SignatureScheme(sigAndAlg))
			}
		case extensionSignatureAlgorithmsCert:
			// RFC 8446, Section 4.2.3
			var sigAndAlgs cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
				return
			}
			for !sigAndAlgs.Empty() {
				var sigAndAlg uint16
				if !sigAndAlgs.ReadUint16(&sigAndAlg) {
					return
				}
				info.SupportedSchemesCert = append(
					info.SupportedSchemesCert, tls.SignatureScheme(sigAndAlg))
			}
		case extensionRenegotiationInfo:
			// RFC 5746, Section 3.2
			if !readUint8LengthPrefixed(&extData, &info.SecureRenegotiation) {
				return
			}
			info.SecureRenegotiationSupported = true
		case extensionALPN:
			// RFC 7301, Section 3.1
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return
			}
			for !protoList.Empty() {
				var proto cryptobyte.String
				if !protoList.ReadUint8LengthPrefixed(&proto) || proto.Empty() {
					return
				}
				info.SupportedProtos = append(info.SupportedProtos, string(proto))
			}
		case extensionSCT:
			// RFC 6962, Section 3.3.1
			info.SCTs = true
		case extensionSupportedVersions:
			// RFC 8446, Section 4.2.1
			var versList cryptobyte.String
			if !extData.ReadUint8LengthPrefixed(&versList) || versList.Empty() {
				return
			}
			for !versList.Empty() {
				var vers uint16
				if !versList.ReadUint16(&vers) {
					return
				}
				info.SupportedVersions = append(info.SupportedVersions, vers)
			}
		case extensionCookie:
			// RFC 8446, Section 4.2.2
			if !readUint16LengthPrefixed(&extData, &info.Cookie) ||
				len(info.Cookie) == 0 {
				return
			}
		case extensionKeyShare:
			// RFC 8446, Section 4.2.8
			var clientShares cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&clientShares) {
				return
			}
			for !clientShares.Empty() {
				var ks KeyShare
				if !clientShares.ReadUint16((*uint16)(&ks.Group)) ||
					!readUint16LengthPrefixed(&clientShares, &ks.Data) ||
					len(ks.Data) == 0 {
					return
				}
				info.KeyShares = append(info.KeyShares, ks)
			}
		case extensionEarlyData:
			// RFC 8446, Section 4.2.10
			info.EarlyData = true
		case extensionPSKModes:
			// RFC 8446, Section 4.2.9
			if !readUint8LengthPrefixed(&extData, &info.PSKModes) {
				return
			}
		case extensionPreSharedKey:
			// RFC 8446, Section 4.2.11
			if !extensions.Empty() {
				return // pre_shared_key must be the last extension
			}
			var identities cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&identities) || identities.Empty() {
				return
			}
			for !identities.Empty() {
				var psk PSKIdentity
				if !readUint16LengthPrefixed(&identities, &psk.label) ||
					!identities.ReadUint32(&psk.obfuscatedTicketAge) ||
					len(psk.label) == 0 {
					return
				}
				info.PSKIdentities = append(info.PSKIdentities, psk)
			}
			var binders cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&binders) || binders.Empty() {
				return
			}
			for !binders.Empty() {
				var binder []byte
				if !readUint8LengthPrefixed(&binders, &binder) ||
					len(binder) == 0 {
					return
				}
				info.PSKBinders = append(info.PSKBinders, binder)
			}
		default:
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return
		}
	}

	return
}

// allKnownVersions is all the TLS versions this package knows.
var allKnownVersions = []uint16{
	tls.VersionTLS13,
	tls.VersionTLS12,
	tls.VersionTLS11,
	tls.VersionTLS10,
}

// supportedVersionsFromMax returns a list of supported versions derived from a
// legacy maximum version value. Note that only versions supported by this
// library are returned. Any newer peer will use allKnownVersions anyway.
func supportedVersionsFromMax(maxVersion uint16) []uint16 {
	versions := make([]uint16, 0, len(allKnownVersions))
	for _, v := range allKnownVersions {
		if v > maxVersion {
			continue
		}
		versions = append(versions, v)
	}
	return versions
}

// readUint8LengthPrefixed acts like s.ReadUint8LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint8LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint8LengthPrefixed((*cryptobyte.String)(out))
}

// readUint16LengthPrefixed acts like s.ReadUint16LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint16LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint16LengthPrefixed((*cryptobyte.String)(out))
}

// TLS extension numbers
const (
	extensionServerName              uint16 = 0
	extensionStatusRequest           uint16 = 5
	extensionSupportedCurves         uint16 = 10 // supported_groups in TLS 1.3, see RFC 8446, Section 4.2.7
	extensionSupportedPoints         uint16 = 11
	extensionSignatureAlgorithms     uint16 = 13
	extensionALPN                    uint16 = 16
	extensionSCT                     uint16 = 18
	extensionSessionTicket           uint16 = 35
	extensionPreSharedKey            uint16 = 41
	extensionEarlyData               uint16 = 42
	extensionSupportedVersions       uint16 = 43
	extensionCookie                  uint16 = 44
	extensionPSKModes                uint16 = 45
	extensionCertificateAuthorities  uint16 = 47
	extensionSignatureAlgorithmsCert uint16 = 50
	extensionKeyShare                uint16 = 51
	extensionRenegotiationInfo       uint16 = 0xff01
)

// TLS signaling cipher suite values
const (
	scsvRenegotiation uint16 = 0x00ff
)

// TLS CertificateStatusType (RFC 3546)
const (
	statusTypeOCSP uint8 = 1
)

// KeyShare is a TLS 1.3 Key Share. See RFC 8446, Section 4.2.8.
type KeyShare struct {
	Group tls.CurveID
	Data  []byte
}

// PSKIdentity is a TLS 1.3 PSK Identity.
// Can be a Session Ticket, or a reference to a saved
// session. See RFC 8446, Section 4.2.11.
type PSKIdentity struct {
	label               []byte
	obfuscatedTicketAge uint32
}
