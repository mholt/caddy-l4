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
)

// ClientHelloInfo holds information about a TLS ClientHello.
// Our own parser collects a little more information than
// the standard library's struct holds.
type ClientHelloInfo struct {
	tls.ClientHelloInfo

	Version                      uint16
	Random                       []byte
	SessionID                    []byte
	SecureRenegotiationSupported bool
	SecureRenegotiation          []byte
	CompressionMethods           []byte

	Extensions []uint16

	OCSPStapling         bool
	TicketSupported      bool
	SessionTicket        []uint8
	SupportedSchemesCert []tls.SignatureScheme
	SCTs                 bool
	Cookie               []byte
	KeyShares            []KeyShare
	EarlyData            bool
	PSKModes             []uint8
	PSKIdentities        []PSKIdentity
	PSKBinders           [][]byte
}

// FillTLSClientConfig fills cfg (a client-side TLS config) with information
// from chi. It does not overwrite any fields in cfg that are already non-zero.
func (chi ClientHelloInfo) FillTLSClientConfig(cfg *tls.Config) {
	if cfg.NextProtos == nil {
		cfg.NextProtos = chi.ClientHelloInfo.SupportedProtos
	}
	if cfg.ServerName == "" {
		cfg.ServerName = chi.ClientHelloInfo.ServerName
	}
	if cfg.CipherSuites == nil {
		cfg.CipherSuites = chi.ClientHelloInfo.CipherSuites
	}
	if cfg.CurvePreferences == nil {
		cfg.CurvePreferences = chi.ClientHelloInfo.SupportedCurves
	}
	var minVer, maxVer uint16
	for _, ver := range chi.ClientHelloInfo.SupportedVersions {
		if minVer == 0 || ver < minVer {
			minVer = ver
		}
		if maxVer == 0 || ver > maxVer {
			maxVer = ver
		}
	}
	if cfg.MinVersion == 0 {
		cfg.MinVersion = minVer
	}
	if cfg.MaxVersion == 0 {
		cfg.MaxVersion = maxVer
	}
}
