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

package l4openvpn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Unexpected error: %s\n", err)
	}
}

func Test_AuthDigests_CheckAll(t *testing.T) {
	plain := plainPacket1[9:14]
	names := make(map[string]int, len(AuthDigests))
	hashes := make([][]byte, 0, len(AuthDigests))
	var hmac []byte
	for i, ad := range AuthDigests {
		if len(ad.Names) == 0 {
			t.Fatalf("Test %d: there must be at least one name", i)
		}
		for j, name := range ad.Names {
			if len(name) == 0 {
				t.Fatalf("Test %d [%s]: empty name %d", i, ad.Names[0], j)
			}
			if k, existing := names[name]; existing {
				t.Fatalf("Test %d [%s]: name %d [%s] used by %s", i, ad.Names[0], j, name, AuthDigests[k].Names[0])
			}
			names[name] = i
		}
		if ad.Size == 0 {
			t.Fatalf("Test %d [%s]: zero size", i, ad.Names[0])
		}
		if !slices.Contains(AuthDigestSizes, ad.Size) {
			t.Fatalf("Test %d [%s]: size missing in AuthDigestSizes", i, ad.Names[0])
		}
		if ad.Creator == nil && ad.Generator == nil {
			t.Fatalf("Test %d [%s]: missing a creator or a generator", i, ad.Names[0])
		}
		if ad.Generator != nil {
			hmac = ad.Generator(groupKey12.GetClientAuthKey(ad.Size), plain)
		} else {
			hmac = HMACCreateAndGenerate(ad.Creator, groupKey12.GetClientAuthKey(ad.Size), plain)
		}
		if len(hmac) != ad.Size {
			t.Fatalf("Test %d [%s]: HMAC length doesn't match its size", i, ad.Names[0])
		}
		for j, existing := range hashes {
			if bytes.Equal(hmac, existing) {
				t.Fatalf("Test %d [%s]: HMAC bytes same as %s", i, ad.Names[0], AuthDigests[j].Names[0])
			}
		}
		hashes = append(hashes, hmac)
	}
}

func Test_MessagePlain_FromBytes_Match_ToBytes(t *testing.T) {
	for i, packet := range [][]byte{
		plainPacket1, plainPacket2,
		plainPacket3, plainPacket4,
	} {
		msg := &MessagePlain{}
		if err := msg.FromBytes(packet); err != nil {
			t.Fatalf("Test %d: failed to unpack: %s", i, err)
		}
		if !bytes.Equal(packet, msg.ToBytes()) {
			t.Fatalf("Test %d: failed to pack", i)
		}
		if !msg.Match() {
			t.Fatalf("Test %d: failed to match", i)
		}
	}
}

func Test_MessageAuth_FromBytes_Match_ToBytes(t *testing.T) {
	for i, packet := range [][]byte{
		// Legacy digests
		authMD5Packet1, authMD5Packet2,
		authSHA1Packet1, authSHA1Packet2,
		// SHA2 digests
		authSHA224Packet1, authSHA224Packet2,
		authSHA256Packet1, authSHA256Packet2,
		authSHA384Packet1, authSHA384Packet2,
		authSHA512Packet1, authSHA512Packet2,
		authSHA512224Packet1, authSHA512224Packet2,
		authSHA512256Packet1, authSHA512256Packet2,
		// SHA3 digests
		authSHA3224Packet1, authSHA3224Packet2,
		authSHA3256Packet1, authSHA3256Packet2,
		authSHA3384Packet1, authSHA3384Packet2,
		authSHA3512Packet1, authSHA3512Packet2,
		// BLAKE digests
		authBLAKE2s256Packet1, authBLAKE2s256Packet2,
		authBLAKE2b512Packet1, authBLAKE2b512Packet2,
	} {
		msg := &MessageAuth{}
		if err := msg.FromBytes(packet); err != nil {
			t.Fatalf("Test %d: failed to unpack: %s", i, err)
		}
		if !msg.Match(true, false, nil, groupKey12) {
			t.Fatalf("Test %d: failed to match", i)
		}
		if !bytes.Equal(packet, msg.ToBytes()) {
			t.Fatalf("Test %d: failed to pack", i)
		}
	}
}

func Test_MessageAuth_FromBytes_Match(t *testing.T) {
	for i, packet := range [][]byte{
		// Legacy digests
		authMD5Packet3, authMD5Packet4,
		authSHA1Packet3, authSHA1Packet4,
		// SHA2 digests
		authSHA224Packet3, authSHA224Packet4,
		authSHA256Packet3, authSHA256Packet4,
		authSHA384Packet3, authSHA384Packet4,
		authSHA512Packet3, authSHA512Packet4,
	} {
		msg := &MessageAuth{}
		if err := msg.FromBytes(packet); err != nil {
			t.Fatalf("Test %d: failed to unpack: %s", i, err)
		}
		if !msg.Match(true, true, nil, groupKey12) {
			t.Fatalf("Test %d: failed to match", i)
		}
	}
}

func Test_MessageCrypt_FromBytes_Match_ToBytes(t *testing.T) {
	for i, packet := range [][]byte{
		cryptPacket1, cryptPacket2,
	} {
		msg := &MessageCrypt{}
		if err := msg.FromBytes(packet); err != nil {
			t.Fatalf("Test %d: failed to unpack: %s", i, err)
		}
		if !msg.Match(true, false, nil, groupKey12) {
			t.Fatalf("Test %d: failed to match", i)
		}
		if !bytes.Equal(packet, msg.ToBytes()) {
			t.Fatalf("Test %d: failed to pack", i)
		}
	}
}

func Test_MessageCrypt_FromBytes_Match(t *testing.T) {
	for i, packet := range [][]byte{
		cryptPacket3, cryptPacket4,
	} {
		msg := &MessageCrypt{}
		if err := msg.FromBytes(packet); err != nil {
			t.Fatalf("Test %d: failed to unpack: %s", i, err)
		}
		if !msg.Match(true, true, nil, groupKey12) {
			t.Fatalf("Test %d: failed to match", i)
		}
	}
}

func Test_MessageCrypt2_FromBytes_Match_ToBytes(t *testing.T) {
	for i, packet := range [][]byte{
		crypt2Packet5, crypt2Packet6,
	} {
		msg := &MessageCrypt2{}
		if err := msg.FromBytes(packet); err != nil {
			t.Fatalf("Test %d: failed to unpack: %s", i, err)
		}
		if !msg.Match(true, false, nil, serverKey56, nil) {
			t.Fatalf("Test %d: failed to match with a server key", i)
		}
		if !msg.Match(true, false, nil, nil, []*WrappedKey{clientKey56}) {
			t.Fatalf("Test %d: failed to match with a client key", i)
		}
		if !bytes.Equal(packet, msg.ToBytes()) {
			fmt.Printf("%x\n%x\n", packet, msg.ToBytes())
			t.Fatalf("Test %d: failed to pack", i)
		}
	}
}

func Test_MessageCrypt2_FromBytes_Match(t *testing.T) {
	for i, packet := range [][]byte{
		crypt2Packet5, crypt2Packet6,
	} {
		msg := &MessageCrypt2{}
		if err := msg.FromBytes(packet); err != nil {
			t.Fatalf("Test %d: failed to unpack: %s", i, err)
		}
		if !msg.Match(true, false, nil, nil, nil) {
			t.Fatalf("Test %d: failed to match", i)
		}
	}
}

func Test_MatchOpenVPN_Match(t *testing.T) {
	type test struct {
		matcher     *MatchOpenVPN
		data        []byte
		shouldMatch bool
	}

	modesNotAuth := []string{"crypt", "crypt2", "plain"}
	modesNotPlain := []string{"auth", "crypt", "crypt2"}
	modesNotCrypt := []string{"auth", "crypt2", "plain"}
	modesNotCrypt2 := []string{"auth", "crypt", "plain"}

	testsPlain := func() []test {
		m0 := &MatchOpenVPN{}
		m1 := &MatchOpenVPN{Modes: modesNotPlain}
		tests := make([]test, 0, 3*2*2)
		for i, packet := range [][]byte{
			plainPacket1, plainPacket2,
			plainPacket3, plainPacket4,
		} {
			tests = append(tests,
				test{matcher: m0, data: packet[:MessagePlainBytesTotal-i-1], shouldMatch: false},
				test{matcher: m0, data: packet, shouldMatch: true},
				test{matcher: m1, data: packet, shouldMatch: false},
			)
		}
		return tests
	}()

	testsKnownKeyAuth := func() []test {
		m0 := &MatchOpenVPN{}
		m1 := &MatchOpenVPN{IgnoreTimestamp: true}
		m2 := &MatchOpenVPN{IgnoreTimestamp: true, Modes: modesNotAuth}
		m3 := &MatchOpenVPN{IgnoreTimestamp: true, GroupKey: groupKey12Hex}
		m4 := &MatchOpenVPN{IgnoreTimestamp: true, GroupKey: groupKey12Hex, AuthDigest: "shake128"}
		m5 := &MatchOpenVPN{IgnoreTimestamp: true, GroupKey: groupKey12Hex, GroupKeyDirection: GroupKeyDirectionInverse}
		tests := make([]test, 0, 6*15*2)
		for _, packet := range [][]byte{
			authMD5Packet1, authMD5Packet2,
			authSHA1Packet1, authSHA1Packet2,
			authSHA224Packet1, authSHA224Packet2,
			authSHA256Packet1, authSHA256Packet2,
			authSHA384Packet1, authSHA384Packet2,
			authSHA512Packet1, authSHA512Packet2,
			authSHA512224Packet1, authSHA512224Packet2,
			authSHA512256Packet1, authSHA512256Packet2,
			authSHA3224Packet1, authSHA3224Packet2,
			authSHA3256Packet1, authSHA3256Packet2,
			authSHA3384Packet1, authSHA3384Packet2,
			authSHA3512Packet1, authSHA3512Packet2,
			authBLAKE2s256Packet1, authBLAKE2s256Packet2,
			authBLAKE2b512Packet1, authBLAKE2b512Packet2,
		} {
			tests = append(tests,
				test{matcher: m0, data: packet, shouldMatch: false},
				test{matcher: m1, data: packet, shouldMatch: true},
				test{matcher: m2, data: packet, shouldMatch: false},
				test{matcher: m3, data: packet, shouldMatch: true},
				test{matcher: m4, data: packet, shouldMatch: false},
				test{matcher: m5, data: packet, shouldMatch: false},
			)
		}
		return tests
	}()

	testsUnknownKeyAuth := func() []test {
		m0 := &MatchOpenVPN{}
		m1 := &MatchOpenVPN{IgnoreTimestamp: true}
		m2 := &MatchOpenVPN{IgnoreTimestamp: true, Modes: modesNotAuth}
		m3 := &MatchOpenVPN{IgnoreTimestamp: true, GroupKey: groupKey12Hex}
		tests := make([]test, 0, 4*6*2)
		for _, packet := range [][]byte{
			authMD5Packet3, authMD5Packet4,
			authSHA1Packet3, authSHA1Packet4,
			authSHA224Packet3, authSHA224Packet4,
			authSHA256Packet3, authSHA256Packet4,
			authSHA384Packet3, authSHA384Packet4,
			authSHA512Packet3, authSHA512Packet4,
		} {
			tests = append(tests,
				test{matcher: m0, data: packet, shouldMatch: false},
				test{matcher: m1, data: packet, shouldMatch: true},
				test{matcher: m2, data: packet, shouldMatch: false},
				test{matcher: m3, data: packet, shouldMatch: false},
			)
		}
		return tests
	}()

	testsUnsupportedDigestsAuth := func() []test {
		m0 := &MatchOpenVPN{}
		m1 := &MatchOpenVPN{IgnoreTimestamp: true}
		m2 := &MatchOpenVPN{IgnoreTimestamp: true, Modes: modesNotAuth}
		m3 := &MatchOpenVPN{IgnoreTimestamp: true, GroupKey: groupKey12Hex}
		tests := make([]test, 0, 4*6*2)
		for _, packet := range [][]byte{
			authMD5SHA1Packet1, authMD5SHA1Packet2,
			authSM3Packet1, authSM3Packet2,
			authWhirlpoolPacket1, authWhirlpoolPacket2,
			authMD5SHA1Packet3, authMD5SHA1Packet4,
		} {
			tests = append(tests,
				test{matcher: m0, data: packet, shouldMatch: false},
				test{matcher: m1, data: packet, shouldMatch: true},
				test{matcher: m2, data: packet, shouldMatch: false},
				test{matcher: m3, data: packet, shouldMatch: false},
			)
		}
		return tests
	}()

	testsKnownKeyCrypt := func() []test {
		m0 := &MatchOpenVPN{}
		m1 := &MatchOpenVPN{IgnoreTimestamp: true}
		m2 := &MatchOpenVPN{IgnoreTimestamp: true, Modes: modesNotCrypt}
		m3 := &MatchOpenVPN{IgnoreTimestamp: true, GroupKey: groupKey12Hex}
		tests := make([]test, 0, 4*1*2)
		for _, packet := range [][]byte{
			cryptPacket1, cryptPacket2,
		} {
			tests = append(tests,
				test{matcher: m0, data: packet, shouldMatch: false},
				test{matcher: m1, data: packet, shouldMatch: true},
				test{matcher: m2, data: packet, shouldMatch: false},
				test{matcher: m3, data: packet, shouldMatch: true},
			)
		}
		return tests
	}()

	testsUnknownKeyCrypt := func() []test {
		m0 := &MatchOpenVPN{}
		m1 := &MatchOpenVPN{IgnoreTimestamp: true}
		m2 := &MatchOpenVPN{IgnoreTimestamp: true, Modes: modesNotCrypt}
		m3 := &MatchOpenVPN{IgnoreTimestamp: true, GroupKey: groupKey12Hex}
		tests := make([]test, 0, 4*1*2)
		for _, packet := range [][]byte{
			cryptPacket3, cryptPacket4,
		} {
			tests = append(tests,
				test{matcher: m0, data: packet, shouldMatch: false},
				test{matcher: m1, data: packet, shouldMatch: true},
				test{matcher: m2, data: packet, shouldMatch: false},
				test{matcher: m3, data: packet, shouldMatch: false},
			)
		}
		return tests
	}()

	testsKnownKeyCrypt2 := func() []test {
		m0 := &MatchOpenVPN{}
		m1 := &MatchOpenVPN{IgnoreTimestamp: true}
		m2 := &MatchOpenVPN{IgnoreTimestamp: true, Modes: modesNotCrypt2}
		m3 := &MatchOpenVPN{IgnoreTimestamp: true, ServerKey: serverKey56Base64}
		m4 := &MatchOpenVPN{IgnoreTimestamp: true, ClientKeys: []string{clientKey56Base64}}
		tests := make([]test, 0, 5*1*2)
		for _, packet := range [][]byte{
			crypt2Packet5, crypt2Packet6,
		} {
			tests = append(tests,
				test{matcher: m0, data: packet, shouldMatch: false},
				test{matcher: m1, data: packet, shouldMatch: true},
				test{matcher: m2, data: packet, shouldMatch: false},
				test{matcher: m3, data: packet, shouldMatch: true},
				test{matcher: m4, data: packet, shouldMatch: true},
			)
		}
		return tests
	}()

	tests := make([]test, 0, len(testsPlain)+len(testsKnownKeyAuth)+len(testsUnknownKeyAuth)+
		len(testsUnsupportedDigestsAuth)+len(testsKnownKeyCrypt)+len(testsUnknownKeyCrypt)+len(testsKnownKeyCrypt2))
	tests = append(tests, testsPlain...)
	tests = append(tests, testsKnownKeyAuth...)
	tests = append(tests, testsUnknownKeyAuth...)
	tests = append(tests, testsUnsupportedDigestsAuth...)
	tests = append(tests, testsKnownKeyCrypt...)
	tests = append(tests, testsUnknownKeyCrypt...)
	tests = append(tests, testsKnownKeyCrypt2...)

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	for i, tc := range tests {
		func() {
			err := tc.matcher.Provision(ctx)
			assertNoError(t, err)

			in, out := net.Pipe()
			defer func() {
				_, _ = io.Copy(io.Discard, out)
				_ = out.Close()
			}()

			cx := layer4.WrapConnection(out, []byte{}, zap.NewNop())
			go func() {
				_, err := in.Write(tc.data)
				assertNoError(t, err)
				_ = in.Close()
			}()

			matched, err := tc.matcher.Match(cx)
			assertNoError(t, err)

			if matched != tc.shouldMatch {
				if tc.shouldMatch {
					t.Fatalf("Test %d: matcher did not match | %+v\n", i, tc.matcher)
				} else {
					t.Fatalf("Test %d: matcher should not match | %+v\n", i, tc.matcher)
				}
			}
		}()
	}
}

// https://github.com/OpenVPN/openvpn/blob/master/sample/sample-keys/ta.key
var groupKey12Hex = "" +
	"21d94830510107f8753d3b6f3145e01d" +
	"ed37075115afcb0538ecdd8503ee9663" +
	"7218c9ed38d908d594231d7d143c73da" +
	"5055310f89d336da99c8b3dcb18909c7" +
	"9dd44f540670ebc0f120beb7211e9683" +
	"9cb542572c48bfa7ffaa9a22cb8304b7" +
	"869b92f4442918e598745bb78ac8877f" +
	"02b00a7cdef3f2446c130d39a7c45126" +
	"9ef399fd6029cdfc80a7c604041312ab" +
	"0a969bc906bdee6e6d707afdcbe8c7fb" +
	"97beb66049c3d328340775025433ceba" +
	"1e38008a826cf92443d903106199373b" +
	"dadd9c2c735cf481e580db4e81b99f12" +
	"e3f46b6159c687cd1b9e689f7712573c" +
	"0f02735a45573dfb5cd55cf464942389" +
	"2c7e91f439bdd7337a8ceebd302cfbfa"

var groupKey12 = StaticKeyNewFromHex(groupKey12Hex, false, false)

/*
 *	All the sample packets below are generated with the sample static key above.
 */

var (
	plainPacket1 = []byte{56, 131, 30, 193, 48, 89, 179, 111, 104, 0, 0, 0, 0, 0}
	plainPacket2 = []byte{56, 48, 212, 183, 154, 72, 13, 92, 194, 0, 0, 0, 0, 0}
)

var (
	authMD5Packet1  = []byte{56, 108, 88, 142, 73, 58, 114, 77, 35, 45, 192, 5, 145, 148, 66, 118, 118, 229, 204, 60, 174, 162, 74, 50, 78, 0, 0, 0, 1, 102, 234, 243, 9, 0, 0, 0, 0, 0}
	authMD5Packet2  = []byte{56, 31, 34, 72, 211, 219, 0, 85, 46, 200, 142, 75, 104, 53, 70, 109, 234, 137, 253, 29, 138, 148, 218, 83, 141, 0, 0, 0, 1, 102, 234, 243, 39, 0, 0, 0, 0, 0}
	authSHA1Packet1 = []byte{56, 38, 129, 217, 92, 90, 2, 14, 97, 123, 32, 15, 106, 140, 112, 232, 206, 242, 138, 133, 246, 151, 31, 71, 44, 140, 201, 188, 248, 0, 0, 0, 1, 102, 234, 241, 204, 0, 0, 0, 0, 0}
	authSHA1Packet2 = []byte{56, 200, 170, 60, 164, 170, 196, 13, 56, 240, 33, 30, 131, 14, 244, 151, 16, 1, 7, 173, 226, 133, 237, 132, 58, 101, 188, 6, 132, 0, 0, 0, 1, 102, 234, 242, 139, 0, 0, 0, 0, 0}
)

var (
	authSHA224Packet1    = []byte{56, 120, 162, 216, 21, 223, 131, 234, 134, 80, 127, 130, 174, 30, 102, 244, 238, 216, 176, 213, 66, 172, 6, 45, 221, 153, 93, 227, 228, 70, 180, 76, 82, 233, 176, 242, 229, 0, 0, 0, 1, 102, 234, 243, 221, 0, 0, 0, 0, 0}
	authSHA224Packet2    = []byte{56, 122, 21, 55, 125, 40, 237, 190, 189, 15, 86, 80, 48, 61, 30, 49, 106, 231, 188, 22, 247, 221, 163, 252, 20, 146, 229, 246, 134, 11, 85, 67, 57, 90, 81, 233, 82, 0, 0, 0, 1, 102, 234, 243, 251, 0, 0, 0, 0, 0}
	authSHA256Packet1    = []byte{56, 241, 168, 141, 190, 188, 201, 75, 111, 199, 1, 198, 27, 138, 167, 106, 34, 70, 142, 66, 147, 64, 216, 37, 38, 62, 8, 150, 42, 120, 226, 65, 81, 10, 81, 27, 180, 47, 147, 125, 81, 0, 0, 0, 1, 102, 234, 244, 77, 0, 0, 0, 0, 0}
	authSHA256Packet2    = []byte{56, 198, 120, 101, 184, 178, 101, 227, 112, 52, 242, 119, 31, 128, 235, 50, 107, 58, 233, 34, 122, 77, 17, 220, 196, 226, 154, 108, 211, 182, 10, 155, 196, 199, 66, 72, 174, 72, 44, 220, 36, 0, 0, 0, 1, 102, 235, 45, 106, 0, 0, 0, 0, 0}
	authSHA384Packet1    = []byte{56, 160, 37, 56, 112, 116, 89, 66, 24, 154, 38, 199, 92, 228, 209, 62, 141, 171, 224, 61, 218, 223, 221, 98, 33, 77, 134, 136, 40, 146, 36, 112, 30, 207, 152, 170, 2, 216, 227, 212, 205, 1, 115, 113, 22, 3, 11, 8, 208, 81, 97, 20, 191, 64, 202, 169, 249, 0, 0, 0, 1, 102, 234, 244, 185, 0, 0, 0, 0, 0}
	authSHA384Packet2    = []byte{56, 175, 250, 66, 242, 105, 89, 222, 222, 108, 120, 226, 236, 11, 225, 251, 172, 175, 118, 219, 249, 225, 140, 228, 111, 129, 234, 103, 248, 34, 220, 49, 65, 99, 241, 43, 235, 15, 49, 216, 249, 41, 140, 75, 231, 56, 33, 200, 228, 255, 207, 231, 234, 189, 248, 105, 1, 0, 0, 0, 1, 102, 235, 46, 153, 0, 0, 0, 0, 0}
	authSHA512Packet1    = []byte{56, 161, 94, 244, 194, 238, 125, 66, 225, 158, 56, 169, 182, 153, 161, 60, 52, 18, 97, 185, 50, 29, 118, 249, 132, 174, 102, 134, 41, 219, 138, 47, 121, 94, 151, 157, 117, 100, 50, 28, 187, 17, 127, 71, 193, 79, 142, 107, 174, 210, 123, 68, 207, 70, 40, 98, 73, 118, 125, 217, 193, 236, 245, 181, 36, 237, 68, 214, 150, 103, 239, 47, 69, 0, 0, 0, 1, 102, 234, 245, 25, 0, 0, 0, 0, 0}
	authSHA512Packet2    = []byte{56, 216, 77, 99, 2, 63, 78, 109, 231, 0, 10, 151, 81, 69, 223, 219, 180, 247, 218, 140, 170, 125, 79, 34, 161, 70, 29, 172, 91, 88, 45, 168, 55, 171, 209, 42, 255, 50, 38, 254, 254, 69, 190, 54, 201, 7, 176, 188, 231, 178, 32, 104, 23, 230, 139, 31, 109, 7, 74, 23, 204, 111, 15, 47, 184, 142, 42, 87, 177, 229, 241, 249, 5, 0, 0, 0, 1, 102, 234, 255, 102, 0, 0, 0, 0, 0}
	authSHA512224Packet1 = []byte{56, 120, 93, 159, 15, 39, 241, 197, 215, 124, 49, 249, 190, 40, 30, 103, 24, 237, 160, 8, 161, 166, 93, 197, 148, 86, 250, 10, 149, 235, 99, 28, 241, 101, 144, 232, 87, 0, 0, 0, 1, 102, 235, 51, 45, 0, 0, 0, 0, 0}
	authSHA512224Packet2 = []byte{56, 53, 50, 102, 177, 253, 154, 44, 246, 173, 13, 203, 52, 177, 212, 190, 163, 163, 56, 75, 12, 35, 102, 36, 104, 173, 105, 79, 88, 155, 95, 205, 120, 223, 140, 149, 46, 0, 0, 0, 1, 102, 235, 51, 79, 0, 0, 0, 0, 0}
	authSHA512256Packet1 = []byte{56, 156, 159, 218, 246, 224, 82, 248, 79, 214, 160, 218, 53, 181, 49, 88, 113, 34, 84, 237, 38, 173, 51, 70, 73, 213, 141, 198, 137, 96, 146, 164, 20, 250, 51, 190, 127, 193, 138, 146, 150, 0, 0, 0, 1, 102, 235, 51, 120, 0, 0, 0, 0, 0}
	authSHA512256Packet2 = []byte{56, 186, 196, 224, 32, 227, 61, 79, 121, 104, 237, 52, 167, 134, 171, 65, 80, 24, 151, 202, 16, 228, 171, 154, 174, 102, 41, 163, 190, 181, 203, 116, 114, 212, 38, 182, 6, 85, 139, 204, 151, 0, 0, 0, 1, 102, 235, 51, 146, 0, 0, 0, 0, 0}
)

var (
	authSHA3224Packet1 = []byte{56, 75, 11, 103, 27, 91, 109, 41, 244, 55, 38, 214, 34, 145, 221, 10, 39, 122, 95, 31, 247, 145, 61, 200, 0, 50, 20, 138, 13, 157, 64, 45, 229, 228, 103, 188, 122, 0, 0, 0, 1, 102, 235, 49, 75, 0, 0, 0, 0, 0}
	authSHA3224Packet2 = []byte{56, 27, 135, 234, 94, 136, 16, 205, 183, 224, 158, 35, 33, 167, 179, 186, 129, 221, 189, 91, 145, 254, 97, 214, 73, 168, 98, 178, 238, 57, 164, 23, 10, 231, 232, 228, 130, 0, 0, 0, 1, 102, 235, 49, 166, 0, 0, 0, 0, 0}
	authSHA3256Packet1 = []byte{56, 102, 44, 44, 250, 78, 239, 197, 24, 141, 207, 4, 172, 243, 182, 248, 89, 85, 126, 211, 221, 77, 58, 132, 232, 210, 92, 100, 224, 138, 249, 189, 233, 173, 65, 107, 247, 44, 12, 44, 25, 0, 0, 0, 1, 102, 235, 49, 221, 0, 0, 0, 0, 0}
	authSHA3256Packet2 = []byte{56, 111, 169, 160, 21, 96, 100, 39, 245, 239, 232, 248, 180, 118, 223, 2, 151, 181, 0, 11, 135, 228, 62, 200, 44, 74, 41, 61, 165, 219, 6, 140, 9, 232, 100, 126, 61, 31, 78, 112, 114, 0, 0, 0, 1, 102, 235, 49, 255, 0, 0, 0, 0, 0}
	authSHA3384Packet1 = []byte{56, 218, 149, 197, 79, 218, 74, 75, 4, 109, 230, 99, 239, 20, 110, 58, 247, 115, 155, 16, 0, 63, 246, 58, 163, 117, 183, 254, 124, 158, 57, 90, 135, 115, 197, 127, 124, 240, 153, 252, 185, 94, 204, 83, 67, 204, 234, 217, 139, 253, 229, 231, 48, 124, 223, 87, 116, 0, 0, 0, 1, 102, 235, 50, 44, 0, 0, 0, 0, 0}
	authSHA3384Packet2 = []byte{56, 182, 206, 108, 83, 191, 147, 63, 158, 59, 66, 8, 109, 134, 242, 142, 55, 34, 184, 130, 40, 104, 48, 136, 113, 123, 93, 177, 36, 111, 185, 151, 14, 35, 42, 200, 95, 241, 192, 218, 171, 88, 217, 108, 229, 133, 112, 162, 157, 218, 83, 149, 212, 102, 179, 173, 248, 0, 0, 0, 1, 102, 235, 50, 76, 0, 0, 0, 0, 0}
	authSHA3512Packet1 = []byte{56, 56, 51, 121, 50, 97, 82, 27, 97, 63, 0, 247, 55, 225, 68, 192, 42, 21, 209, 75, 160, 240, 219, 32, 232, 98, 25, 109, 168, 157, 235, 66, 58, 236, 39, 211, 113, 42, 63, 83, 156, 141, 128, 86, 58, 252, 72, 252, 160, 4, 49, 100, 226, 2, 23, 206, 245, 74, 243, 19, 37, 96, 95, 45, 66, 114, 214, 204, 242, 76, 169, 149, 188, 0, 0, 0, 1, 102, 235, 50, 116, 0, 0, 0, 0, 0}
	authSHA3512Packet2 = []byte{56, 35, 221, 191, 87, 222, 230, 175, 109, 149, 129, 74, 255, 48, 70, 110, 253, 142, 246, 140, 49, 20, 10, 69, 34, 12, 194, 51, 250, 81, 94, 127, 4, 33, 56, 80, 212, 219, 18, 173, 203, 113, 67, 16, 10, 252, 253, 100, 209, 106, 164, 171, 174, 200, 225, 141, 218, 251, 169, 147, 139, 91, 67, 114, 19, 67, 180, 240, 81, 96, 189, 75, 126, 0, 0, 0, 1, 102, 235, 50, 144, 0, 0, 0, 0, 0}
)

var (
	authBLAKE2s256Packet1 = []byte{56, 117, 185, 201, 73, 60, 231, 94, 83, 79, 58, 65, 198, 193, 150, 251, 40, 240, 186, 67, 214, 103, 173, 128, 71, 85, 169, 180, 57, 185, 190, 142, 169, 29, 70, 15, 227, 16, 233, 122, 248, 0, 0, 0, 1, 102, 235, 52, 237, 0, 0, 0, 0, 0}
	authBLAKE2s256Packet2 = []byte{56, 113, 195, 33, 169, 198, 218, 173, 209, 221, 244, 170, 234, 51, 121, 193, 200, 71, 196, 195, 124, 161, 83, 34, 216, 32, 220, 169, 217, 119, 173, 198, 111, 212, 180, 207, 239, 133, 126, 23, 73, 0, 0, 0, 1, 102, 235, 53, 26, 0, 0, 0, 0, 0}
	authBLAKE2b512Packet1 = []byte{56, 85, 88, 174, 47, 95, 41, 94, 246, 10, 210, 140, 132, 252, 217, 139, 220, 49, 214, 53, 127, 38, 150, 43, 148, 226, 184, 99, 168, 70, 117, 193, 144, 71, 193, 51, 66, 175, 1, 199, 90, 168, 165, 252, 200, 183, 163, 149, 209, 150, 81, 156, 180, 62, 40, 71, 169, 157, 115, 55, 227, 142, 235, 232, 186, 16, 163, 153, 165, 225, 206, 65, 218, 0, 0, 0, 1, 102, 235, 53, 76, 0, 0, 0, 0, 0}
	authBLAKE2b512Packet2 = []byte{56, 81, 167, 144, 212, 181, 169, 247, 183, 247, 121, 237, 117, 202, 78, 166, 17, 78, 117, 65, 216, 21, 66, 25, 153, 188, 93, 74, 87, 190, 188, 117, 121, 177, 19, 55, 28, 183, 97, 209, 51, 33, 207, 175, 170, 42, 132, 26, 136, 166, 120, 154, 94, 36, 33, 5, 43, 244, 234, 80, 16, 72, 109, 54, 200, 77, 191, 229, 251, 101, 62, 90, 10, 0, 0, 0, 1, 102, 235, 53, 114, 0, 0, 0, 0, 0}
)

var (
	authMD5SHA1Packet1 = []byte{56, 179, 179, 82, 117, 88, 75, 7, 103, 207, 125, 244, 183, 3, 111, 46, 96, 79, 33, 216, 220, 7, 46, 234, 213, 182, 38, 87, 48, 131, 127, 227, 208, 13, 246, 26, 169, 220, 143, 161, 18, 68, 67, 179, 92, 0, 0, 0, 1, 102, 235, 48, 73, 0, 0, 0, 0, 0}
	authMD5SHA1Packet2 = []byte{56, 72, 91, 69, 91, 123, 156, 4, 2, 200, 34, 158, 108, 40, 218, 3, 95, 19, 203, 170, 36, 86, 29, 207, 40, 251, 124, 79, 93, 174, 221, 45, 22, 18, 125, 250, 150, 82, 37, 64, 100, 108, 251, 29, 114, 0, 0, 0, 1, 102, 235, 48, 132, 0, 0, 0, 0, 0}
)

var (
	authSM3Packet1 = []byte{56, 61, 163, 194, 51, 225, 14, 218, 181, 76, 125, 35, 206, 68, 24, 66, 176, 84, 237, 88, 38, 121, 213, 67, 33, 172, 83, 167, 103, 89, 82, 122, 7, 166, 156, 79, 26, 67, 191, 210, 226, 0, 0, 0, 1, 102, 235, 50, 211, 0, 0, 0, 0, 0}
	authSM3Packet2 = []byte{56, 216, 20, 196, 148, 131, 37, 73, 181, 55, 166, 108, 86, 143, 5, 25, 20, 21, 149, 77, 221, 237, 110, 232, 237, 23, 40, 231, 192, 225, 197, 160, 172, 49, 130, 178, 78, 12, 143, 130, 229, 0, 0, 0, 1, 102, 235, 50, 243, 0, 0, 0, 0, 0}
)

var (
	authWhirlpoolPacket1 = []byte{56, 36, 245, 218, 233, 15, 158, 142, 144, 116, 207, 71, 60, 35, 210, 55, 90, 223, 92, 122, 87, 53, 131, 122, 248, 84, 50, 42, 69, 254, 231, 197, 30, 216, 65, 242, 173, 160, 127, 229, 165, 224, 32, 16, 118, 45, 197, 158, 145, 0, 130, 72, 78, 104, 107, 247, 100, 54, 185, 151, 70, 116, 219, 15, 112, 175, 78, 30, 177, 222, 41, 223, 29, 0, 0, 0, 1, 102, 235, 55, 2, 0, 0, 0, 0, 0}
	authWhirlpoolPacket2 = []byte{56, 31, 112, 117, 225, 131, 182, 114, 117, 242, 139, 201, 7, 108, 19, 165, 164, 120, 243, 26, 152, 195, 228, 36, 162, 249, 105, 116, 114, 121, 232, 215, 253, 153, 249, 243, 54, 55, 83, 70, 28, 19, 87, 233, 54, 164, 69, 52, 96, 28, 107, 220, 236, 226, 35, 224, 155, 100, 78, 59, 174, 220, 107, 120, 56, 100, 160, 122, 182, 96, 94, 83, 71, 0, 0, 0, 1, 102, 235, 55, 144, 0, 0, 0, 0, 0}
)

var (
	cryptPacket1 = []byte{56, 76, 98, 159, 244, 184, 134, 148, 158, 0, 0, 0, 1, 102, 237, 91, 50, 14, 141, 87, 40, 125, 165, 204, 227, 61, 5, 91, 201, 99, 44, 253, 7, 202, 200, 84, 124, 48, 80, 144, 250, 52, 248, 173, 26, 201, 173, 67, 166, 16, 189, 73, 203, 12}
	cryptPacket2 = []byte{56, 162, 49, 153, 71, 88, 124, 182, 93, 0, 0, 0, 1, 102, 237, 91, 95, 84, 154, 63, 127, 63, 175, 65, 227, 69, 45, 146, 14, 64, 81, 56, 239, 162, 229, 54, 81, 103, 167, 133, 38, 57, 83, 119, 60, 149, 149, 218, 201, 144, 193, 202, 149, 111}
)

/*
 *	All the sample packets below are generated with another static key.
 */

var (
	cryptPacket3 = []byte{56, 114, 151, 86, 204, 204, 137, 212, 215, 0, 0, 0, 1, 102, 231, 24, 196, 58, 184, 197, 69, 200, 222, 132, 120, 248, 163, 68, 112, 17, 137, 97, 240, 56, 122, 62, 49, 172, 177, 176, 86, 180, 187, 148, 69, 17, 251, 38, 0, 31, 203, 0, 237, 122}
	cryptPacket4 = []byte{56, 49, 193, 232, 78, 82, 175, 151, 76, 0, 0, 0, 1, 102, 231, 25, 92, 82, 125, 47, 131, 35, 217, 41, 164, 145, 71, 178, 38, 218, 194, 60, 100, 167, 212, 8, 160, 131, 22, 61, 246, 52, 20, 100, 6, 16, 108, 18, 127, 24, 185, 240, 99, 156}
)

var (
	authSHA512Packet3  = []byte{56, 9, 137, 51, 217, 234, 95, 85, 78, 254, 110, 108, 95, 38, 212, 11, 224, 47, 57, 16, 51, 199, 136, 76, 111, 191, 16, 107, 75, 219, 113, 162, 191, 67, 46, 146, 184, 246, 177, 52, 53, 53, 127, 191, 5, 184, 24, 166, 146, 223, 234, 222, 239, 9, 92, 227, 241, 225, 196, 46, 230, 138, 3, 5, 85, 186, 65, 251, 189, 11, 16, 28, 102, 0, 0, 0, 1, 102, 231, 16, 138, 0, 0, 0, 0, 0}
	authSHA512Packet4  = []byte{56, 178, 216, 6, 201, 115, 66, 0, 252, 112, 99, 34, 163, 140, 85, 246, 137, 75, 183, 212, 159, 38, 251, 25, 190, 253, 36, 249, 198, 196, 70, 177, 201, 14, 65, 227, 248, 77, 108, 115, 189, 160, 244, 174, 98, 107, 141, 70, 231, 120, 91, 118, 74, 229, 197, 11, 34, 193, 58, 35, 253, 148, 135, 235, 90, 101, 6, 152, 24, 139, 17, 204, 33, 0, 0, 0, 1, 102, 231, 16, 206, 0, 0, 0, 0, 0}
	authSHA384Packet3  = []byte{56, 219, 201, 226, 49, 70, 125, 55, 178, 191, 78, 40, 216, 206, 58, 20, 224, 132, 135, 191, 172, 205, 188, 24, 176, 48, 143, 139, 127, 225, 202, 39, 8, 196, 77, 57, 9, 41, 94, 103, 73, 169, 38, 206, 220, 2, 48, 62, 228, 47, 75, 97, 94, 55, 92, 204, 186, 0, 0, 0, 1, 102, 231, 17, 154, 0, 0, 0, 0, 0}
	authSHA384Packet4  = []byte{56, 16, 226, 49, 167, 146, 222, 219, 13, 3, 106, 151, 111, 210, 227, 142, 102, 16, 216, 234, 94, 111, 244, 11, 94, 253, 12, 186, 117, 92, 196, 92, 65, 107, 141, 17, 229, 249, 197, 17, 103, 41, 223, 153, 181, 117, 29, 117, 56, 22, 175, 162, 64, 31, 77, 122, 72, 0, 0, 0, 1, 102, 231, 17, 193, 0, 0, 0, 0, 0}
	authMD5SHA1Packet3 = []byte{56, 99, 167, 201, 107, 123, 246, 212, 180, 87, 93, 31, 188, 10, 53, 149, 139, 232, 13, 207, 71, 108, 154, 143, 114, 180, 196, 221, 157, 16, 106, 225, 14, 219, 137, 223, 222, 146, 106, 226, 168, 120, 86, 22, 124, 0, 0, 0, 1, 102, 231, 23, 250, 0, 0, 0, 0, 0}
	authMD5SHA1Packet4 = []byte{56, 37, 80, 49, 19, 199, 20, 62, 202, 74, 99, 211, 73, 42, 204, 120, 193, 83, 126, 182, 7, 159, 177, 126, 206, 70, 29, 198, 68, 211, 249, 15, 123, 201, 45, 193, 38, 134, 223, 186, 236, 58, 235, 55, 130, 0, 0, 0, 1, 102, 231, 24, 40, 0, 0, 0, 0, 0}
	authSHA256Packet3  = []byte{56, 102, 151, 183, 239, 253, 36, 110, 23, 150, 73, 73, 166, 35, 204, 199, 240, 149, 243, 16, 8, 55, 68, 108, 31, 11, 74, 186, 254, 65, 15, 81, 5, 222, 184, 12, 106, 72, 2, 114, 154, 0, 0, 0, 1, 102, 231, 17, 9, 0, 0, 0, 0, 0}
	authSHA256Packet4  = []byte{56, 95, 17, 119, 145, 64, 76, 195, 82, 28, 120, 32, 8, 114, 93, 80, 206, 88, 123, 172, 37, 73, 97, 54, 221, 37, 7, 157, 39, 147, 73, 251, 107, 61, 52, 76, 11, 97, 161, 3, 96, 0, 0, 0, 1, 102, 231, 17, 93, 0, 0, 0, 0, 0}
	authSHA224Packet3  = []byte{56, 27, 28, 60, 231, 13, 31, 116, 190, 88, 126, 12, 34, 137, 96, 59, 7, 91, 163, 246, 60, 2, 38, 129, 69, 217, 9, 24, 18, 36, 210, 88, 86, 2, 226, 0, 96, 0, 0, 0, 1, 102, 231, 20, 101, 0, 0, 0, 0, 0}
	authSHA224Packet4  = []byte{56, 248, 223, 183, 225, 174, 116, 5, 214, 134, 211, 177, 21, 142, 215, 9, 8, 164, 55, 40, 10, 206, 40, 254, 173, 235, 176, 126, 12, 67, 35, 221, 219, 209, 30, 244, 178, 0, 0, 0, 1, 102, 231, 20, 137, 0, 0, 0, 0, 0}
	authSHA1Packet3    = []byte{56, 237, 200, 39, 23, 233, 70, 6, 161, 241, 68, 106, 124, 33, 176, 55, 84, 222, 250, 76, 156, 191, 179, 213, 51, 159, 4, 62, 210, 0, 0, 0, 1, 102, 231, 18, 45, 0, 0, 0, 0, 0}
	authSHA1Packet4    = []byte{56, 130, 31, 160, 196, 239, 31, 197, 116, 52, 169, 99, 61, 200, 67, 148, 130, 219, 9, 88, 119, 50, 245, 69, 146, 204, 29, 211, 206, 0, 0, 0, 1, 102, 231, 18, 99, 0, 0, 0, 0, 0}
	authMD5Packet3     = []byte{56, 215, 5, 24, 98, 120, 183, 161, 99, 207, 88, 65, 149, 207, 91, 106, 49, 202, 38, 190, 180, 159, 186, 132, 12, 0, 0, 0, 1, 102, 231, 18, 140, 0, 0, 0, 0, 0}
	authMD5Packet4     = []byte{56, 54, 43, 62, 107, 142, 244, 8, 206, 17, 95, 99, 7, 97, 10, 102, 63, 210, 191, 101, 209, 192, 183, 94, 67, 0, 0, 0, 1, 102, 231, 18, 188, 0, 0, 0, 0, 0}
)

var (
	plainPacket3 = []uint8{56, 232, 90, 55, 186, 10, 31, 142, 127, 0, 0, 0, 0, 0}
	plainPacket4 = []uint8{56, 177, 22, 70, 225, 86, 175, 190, 204, 0, 0, 0, 0, 0}
)

/*
 *	All the sample packets below are generated with a pair of tls-crypt-v2 server key and tls-crypt-v2 client key.
 */

var (
	serverKey56Base64 = "U2hihe8H77pInpRzMEWNZ/NwM1CBSSVSw5HyXT7/+1pspISJzKBiECs+LRvE6QlwgKm606H1wLv0defgJRNU1UG1fi25oMPqjFcYybU+wOgY8eX6OWM0EWI6d2XaL6Neu1E9fMGDAWnzQFsFZhMQH80xv0kzzLm13UjL7lrdQnM="
	clientKey56Base64 = "HZVyTZ3S2YMR9UFUei+kWmNcCaxxT31StqhozQFXVQ41WK203PFtunbuA7HZNPaBLQbyC3aaxwGcEsqW1Jnm/3WptcPWFYhFGhW+H37x2howQyAGj6IIsjZQyS9gwYgGr8bVNTZIywz3hw+KLRCAzkhTqk6ONen1wf5rewu03g2RNq/suLU6V31OTDOxeyb1WkUA25Ych7le6FJzO8YqI5jOosokID3ueT05vCdMIDa6FsHR3BmPjX2OYLquV+wBF7IBykKcxrCvrT2Qf/tBpv7PtUkKx6pCApKiUuPxLALMxqv3ATa7vrCB8qZQWmO4dRY40ORYZ622MiqCDmDFGKQca1bPxdHdpFCr5o8gvYHR9p0Xm2t6KcCvAO+CUAMKA1DsUqIYrrhQIkkZI/dbffBGnxyrb/XlzGnSynv5d8oAl7QSrW292JLtm7VCGE7NePEMvAx9iAXNTwxpdwNNfPmb3ZNWq7H+mGUaYQpcs7xW45zzyUkV9fESFEnlePxeJ3pjqxawcjnOBy1yLk/RKyFOakNJ/Z6r7IFjgI6usooo1i7+Tp6O5MHQasWcpyLWzW5KvjGPIKH0SFl6VJdBMkWWYm1D5KdgqXX8716uNvpY0dVpXgE+KfJPxIRQDGCuS8zyrxAHCvm8MAbiOpi9g35/4vKFj+cvar4EssHrvSX+l0Z7q5kGnMbnvStH7MEzTQXCcMT30vDWBn2W9SEkOh9KIq1z3/46owEr"
)

var (
	serverKey56 = StaticKeyNewFromBase64(serverKey56Base64, false, false)
	clientKey56 = WrappedKeyNewFromBase64(clientKey56Base64)
)

var (
	crypt2Packet5 = []byte{80, 100, 224, 45, 159, 27, 166, 162, 220, 15, 0, 0, 1, 102, 240, 100, 162, 53, 85, 10, 213, 183, 32, 34, 176, 186, 16, 66, 59, 48, 128, 24, 240, 143, 116, 59, 133, 18, 152, 241, 84, 81, 95, 195, 181, 88, 112, 148, 217, 127, 200, 222, 197, 88, 164, 28, 107, 86, 207, 197, 209, 221, 164, 80, 171, 230, 143, 32, 189, 129, 209, 246, 157, 23, 155, 107, 122, 41, 192, 175, 0, 239, 130, 80, 3, 10, 3, 80, 236, 82, 162, 24, 174, 184, 80, 34, 73, 25, 35, 247, 91, 125, 240, 70, 159, 28, 171, 111, 245, 229, 204, 105, 210, 202, 123, 249, 119, 202, 0, 151, 180, 18, 173, 109, 189, 216, 146, 237, 155, 181, 66, 24, 78, 205, 120, 241, 12, 188, 12, 125, 136, 5, 205, 79, 12, 105, 119, 3, 77, 124, 249, 155, 221, 147, 86, 171, 177, 254, 152, 101, 26, 97, 10, 92, 179, 188, 86, 227, 156, 243, 201, 73, 21, 245, 241, 18, 20, 73, 229, 120, 252, 94, 39, 122, 99, 171, 22, 176, 114, 57, 206, 7, 45, 114, 46, 79, 209, 43, 33, 78, 106, 67, 73, 253, 158, 171, 236, 129, 99, 128, 142, 174, 178, 138, 40, 214, 46, 254, 78, 158, 142, 228, 193, 208, 106, 197, 156, 167, 34, 214, 205, 110, 74, 190, 49, 143, 32, 161, 244, 72, 89, 122, 84, 151, 65, 50, 69, 150, 98, 109, 67, 228, 167, 96, 169, 117, 252, 239, 94, 174, 54, 250, 88, 209, 213, 105, 94, 1, 62, 41, 242, 79, 196, 132, 80, 12, 96, 174, 75, 204, 242, 175, 16, 7, 10, 249, 188, 48, 6, 226, 58, 152, 189, 131, 126, 127, 226, 242, 133, 143, 231, 47, 106, 190, 4, 178, 193, 235, 189, 37, 254, 151, 70, 123, 171, 153, 6, 156, 198, 231, 189, 43, 71, 236, 193, 51, 77, 5, 194, 112, 196, 247, 210, 240, 214, 6, 125, 150, 245, 33, 36, 58, 31, 74, 34, 173, 115, 223, 254, 58, 163, 1, 43}
	crypt2Packet6 = []byte{80, 136, 240, 154, 124, 25, 199, 138, 59, 15, 0, 0, 1, 102, 240, 107, 4, 103, 91, 3, 26, 182, 97, 79, 186, 12, 192, 49, 251, 104, 205, 177, 215, 107, 141, 155, 102, 232, 247, 246, 206, 142, 216, 230, 20, 218, 58, 153, 248, 131, 173, 105, 2, 213, 164, 28, 107, 86, 207, 197, 209, 221, 164, 80, 171, 230, 143, 32, 189, 129, 209, 246, 157, 23, 155, 107, 122, 41, 192, 175, 0, 239, 130, 80, 3, 10, 3, 80, 236, 82, 162, 24, 174, 184, 80, 34, 73, 25, 35, 247, 91, 125, 240, 70, 159, 28, 171, 111, 245, 229, 204, 105, 210, 202, 123, 249, 119, 202, 0, 151, 180, 18, 173, 109, 189, 216, 146, 237, 155, 181, 66, 24, 78, 205, 120, 241, 12, 188, 12, 125, 136, 5, 205, 79, 12, 105, 119, 3, 77, 124, 249, 155, 221, 147, 86, 171, 177, 254, 152, 101, 26, 97, 10, 92, 179, 188, 86, 227, 156, 243, 201, 73, 21, 245, 241, 18, 20, 73, 229, 120, 252, 94, 39, 122, 99, 171, 22, 176, 114, 57, 206, 7, 45, 114, 46, 79, 209, 43, 33, 78, 106, 67, 73, 253, 158, 171, 236, 129, 99, 128, 142, 174, 178, 138, 40, 214, 46, 254, 78, 158, 142, 228, 193, 208, 106, 197, 156, 167, 34, 214, 205, 110, 74, 190, 49, 143, 32, 161, 244, 72, 89, 122, 84, 151, 65, 50, 69, 150, 98, 109, 67, 228, 167, 96, 169, 117, 252, 239, 94, 174, 54, 250, 88, 209, 213, 105, 94, 1, 62, 41, 242, 79, 196, 132, 80, 12, 96, 174, 75, 204, 242, 175, 16, 7, 10, 249, 188, 48, 6, 226, 58, 152, 189, 131, 126, 127, 226, 242, 133, 143, 231, 47, 106, 190, 4, 178, 193, 235, 189, 37, 254, 151, 70, 123, 171, 153, 6, 156, 198, 231, 189, 43, 71, 236, 193, 51, 77, 5, 194, 112, 196, 247, 210, 240, 214, 6, 125, 150, 245, 33, 36, 58, 31, 74, 34, 173, 115, 223, 254, 58, 163, 1, 43}
)
