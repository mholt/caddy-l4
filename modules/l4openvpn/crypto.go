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
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/sha3"
)

// AuthDigest represents a digest used for computing HMACs of control messages.
type AuthDigest struct {
	// Creator is a function returning something that implements hash.Hash interface.
	// Creator is required whenever Generator is nil.
	Creator func() hash.Hash
	// Generator is a function returning an HMAC for a given set of key and plain bytes.
	// Generator is optional, but it takes precedence over Creator.
	Generator func(key, plain []byte) []byte
	// Names contains a list of digest names in various notations.
	Names []string
	// Size is a number of bytes all computed HMACs will have.
	Size int
}

// HMACGenerateOnClient computes an HMAC of a given plain text with a part of a given StaticKey
// (to be sent by the client to the server).
func (ad *AuthDigest) HMACGenerateOnClient(sk *StaticKey, plain []byte) []byte {
	key := sk.GetClientAuthKey(ad.Size)
	if ad.Generator != nil {
		return ad.Generator(key, plain)
	}
	return HMACCreateAndGenerate(ad.Creator, key, plain)
}

// HMACGenerateOnServer computes an HMAC of a given plain text with a part of a given StaticKey
// (to be sent by the server to the client).
func (ad *AuthDigest) HMACGenerateOnServer(sk *StaticKey, plain []byte) []byte {
	key := sk.GetServerAuthKey(ad.Size)
	if ad.Generator != nil {
		return ad.Generator(key, plain)
	}
	return HMACCreateAndGenerate(ad.Creator, key, plain)
}

// HMACValidateOnClient compares an expected HMAC (as received by the client from the server)
// with an actual HMAC of a given plain text it computes with a part of a given StaticKey.
func (ad *AuthDigest) HMACValidateOnClient(sk *StaticKey, plain, expected []byte) bool {
	actual := ad.HMACGenerateOnServer(sk, plain)
	return hmac.Equal(actual, expected)
}

// HMACValidateOnServer compares an expected HMAC (as received by the server from the client)
// with an actual HMAC of a given plain text it computes with a part of a given StaticKey.
func (ad *AuthDigest) HMACValidateOnServer(sk *StaticKey, plain, expected []byte) bool {
	actual := ad.HMACGenerateOnClient(sk, plain)
	return hmac.Equal(actual, expected)
}

// CryptCipher represents a cipher used for en/decrypting control messages.
type CryptCipher struct {
	// Decryptor is a function returning plain bytes from encrypted ones.
	Decryptor func(key, iv, encrypted []byte) []byte
	// Encryptor is a function returning encrypted bytes from plain ones.
	Encryptor func(key, iv, plain []byte) []byte
	// Names contains a list of cipher names in various notations.
	Names []string
	// SizeBlock is a number of bytes an initialization vector (IV) must have.
	SizeBlock int
	// SizeKey is a number of bytes an en/decryption key must have.
	SizeKey int
}

// DecryptOnClient decrypts given encrypted bytes with a part of a given StaticKey
// (as received by the client from the server).
func (cc *CryptCipher) DecryptOnClient(sk *StaticKey, iv, encrypted []byte) []byte {
	key := sk.GetClientDecryptKey(cc.SizeKey)
	return cc.Decryptor(key, iv, encrypted)
}

// DecryptOnServer decrypts given encrypted bytes with a part of a given StaticKey
// (as received by the server from the client).
func (cc *CryptCipher) DecryptOnServer(sk *StaticKey, iv, encrypted []byte) []byte {
	key := sk.GetServerDecryptKey(cc.SizeKey)
	return cc.Decryptor(key, iv, encrypted)
}

// EncryptOnClient encrypts given plain bytes with a part of a given StaticKey
// (to be sent by the client to the server).
func (cc *CryptCipher) EncryptOnClient(sk *StaticKey, iv, plain []byte) []byte {
	key := sk.GetClientEncryptKey(cc.SizeKey)
	return cc.Encryptor(key, iv, plain)
}

// EncryptOnServer encrypts given plain bytes with a part of a given StaticKey
// (to be sent by the server to the client).
func (cc *CryptCipher) EncryptOnServer(sk *StaticKey, iv, plain []byte) []byte {
	key := sk.GetServerEncryptKey(cc.SizeKey)
	return cc.Encryptor(key, iv, plain)
}

// StaticKey is an OpenVPN static key used for authentication and encryption of control messages.
//
// Notes:
//
// Authentication. If no key direction is set (i.e. a bidirectional key), OpenVPN uses key[64:64+size] for
// computing and validating HMACs on both the client and the server. If the client has `key-direction 1`
// and the server has `key-direction 0`, OpenVPN uses key[192:192+size] for computing HMACs on the client and
// validating them on the server. If the client has `key-direction 0` and the server has `key-direction 1`
// (i.e. an inverse direction in violation of the recommendations), OpenVPN uses key[64:64+size] for computing
// HMACs on the client and validating them on the server. Inverse and Bidi are mutually exclusive. If both are
// set, Bidi takes precedence.
//
// En/decryption. OpenVPN always takes 2 different keys for encryption and decryption, so Bidi is completely
// ignored. Unless Inverse is set, key[128:128+size] is used for encryption on the client and key[0:0+size] is
// used for decryption on the client with the server applying these keys in the other way.
type StaticKey struct {
	// Bidi mimics `key-direction` omitted for both the server and the client.
	Bidi bool
	// Inverse mimics `key-direction 1` set for the server and `key-direction 0` set for the client.
	Inverse bool
	// KeyBytes must contain 128 or 256 bytes of the static key.
	KeyBytes []byte
}

// FromBase64 fills sk's KeyBytes from a given base64 string.
func (sk *StaticKey) FromBase64(s string) (err error) {
	sk.KeyBytes, err = base64.StdEncoding.DecodeString(s)
	return
}

// FromGroupKeyFile fills sk's KeyBytes from a given group key file.
func (sk *StaticKey) FromGroupKeyFile(path string) error {
	return sk.FromFile(path, StaticKeyFromFileHex, StaticKeyBytesTotal*2, sk.FromHex)
}

// FromServerKeyFile fills sk's KeyBytes from a given server key file.
func (sk *StaticKey) FromServerKeyFile(path string) error {
	return sk.FromFile(path, StaticKeyFromFileBase64, base64.StdEncoding.EncodedLen(StaticKeyBytesHalf), sk.FromBase64)
}

// FromFile fills sk's KeyBytes from a given file.
func (sk *StaticKey) FromFile(path string, re *regexp.Regexp, size int, from func(string) error) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	n := 1024
	buf := make([]byte, n)
	n, err = file.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}

	if n > 0 {
		var s string
		if r := re.FindStringSubmatch(string(buf[:n])); len(r) == 2 {
			s = strings.ReplaceAll(r[1], "\r", "")
			s = strings.ReplaceAll(s, "\n", "")
			if size == 0 || len(s) == size {
				return from(s)
			}
		}
	}

	return ErrInvalidStaticKeyFileContents
}

// FromHex fills sk's KeyBytes from a given hex string.
func (sk *StaticKey) FromHex(s string) (err error) {
	sk.KeyBytes, err = hex.DecodeString(s)
	return
}

// GetClientAuthBytes returns a quarter of KeyBytes to be used for authentication of control messages
// composed by the client.
func (sk *StaticKey) GetClientAuthBytes() []byte {
	if sk.Inverse || sk.Bidi {
		return sk.GetQuarterBytes(1)
	}
	return sk.GetQuarterBytes(3)
}

// GetClientAuthKey returns a key of a given size from GetClientAuthBytes.
func (sk *StaticKey) GetClientAuthKey(size int) []byte {
	return sk.GetClientAuthBytes()[:min(size, StaticKeyBytesQuarter)]
}

// GetClientEncryptBytes returns a quarter of KeyBytes to be used for encryption of control messages
// composed by the client.
func (sk *StaticKey) GetClientEncryptBytes() []byte {
	if sk.Inverse {
		return sk.GetQuarterBytes(0)
	}
	return sk.GetQuarterBytes(2)
}

// GetClientEncryptKey returns a key of a given size from GetClientEncryptBytes.
func (sk *StaticKey) GetClientEncryptKey(size int) []byte {
	return sk.GetClientEncryptBytes()[:min(size, StaticKeyBytesQuarter)]
}

// GetClientDecryptBytes returns a quarter of KeyBytes to be used for decryption of control messages
// received by the client.
func (sk *StaticKey) GetClientDecryptBytes() []byte {
	if sk.Inverse {
		return sk.GetQuarterBytes(2)
	}
	return sk.GetQuarterBytes(0)
}

// GetClientDecryptKey returns a key of a given size from GetClientDecryptBytes.
func (sk *StaticKey) GetClientDecryptKey(size int) []byte {
	return sk.GetClientDecryptBytes()[:min(size, StaticKeyBytesQuarter)]
}

// GetServerAuthBytes returns a quarter of KeyBytes to be used for authentication of control messages
// composed by the server.
func (sk *StaticKey) GetServerAuthBytes() []byte {
	if sk.Inverse && !sk.Bidi {
		return sk.GetQuarterBytes(3)
	}
	return sk.GetQuarterBytes(1)
}

// GetServerAuthKey returns a key of a given size from GetServerAuthKey.
func (sk *StaticKey) GetServerAuthKey(size int) []byte {
	return sk.GetServerAuthBytes()[:min(size, StaticKeyBytesQuarter)]
}

// GetServerEncryptBytes returns a quarter of KeyBytes to be used for encryption of control messages
// composed by the server.
func (sk *StaticKey) GetServerEncryptBytes() []byte {
	return sk.GetClientDecryptBytes()
}

// GetServerEncryptKey returns a key of a given size from GetServerEncryptBytes.
func (sk *StaticKey) GetServerEncryptKey(size int) []byte {
	return sk.GetClientDecryptKey(size)
}

// GetServerDecryptBytes returns a quarter of KeyBytes to be used for decryption of control messages
// received by the server.
func (sk *StaticKey) GetServerDecryptBytes() []byte {
	return sk.GetClientEncryptBytes()
}

// GetServerDecryptKey returns a key of a given size from GetServerDecryptBytes.
func (sk *StaticKey) GetServerDecryptKey(size int) []byte {
	return sk.GetClientEncryptKey(size)
}

// GetQuarterBytes returns a nth (0-based) quarter of KeyBytes
func (sk *StaticKey) GetQuarterBytes(q uint) []byte {
	q = q % 4
	if len(sk.KeyBytes) < StaticKeyBytesTotal {
		q = q % 2
	}
	if len(sk.KeyBytes) < StaticKeyBytesHalf {
		q = 0
	}
	if len(sk.KeyBytes) < StaticKeyBytesQuarter {
		return sk.KeyBytes
	}
	return sk.KeyBytes[q*StaticKeyBytesQuarter : (q+1)*StaticKeyBytesQuarter]
}

// ToBase64 returns a base64 string representing KeyBytes.
func (sk *StaticKey) ToBase64() string {
	return base64.StdEncoding.EncodeToString(sk.KeyBytes)
}

// ToHex returns a hex string representing KeyBytes.
func (sk *StaticKey) ToHex() string {
	return hex.EncodeToString(sk.KeyBytes)
}

// AuthDigests contains all the supported items of AuthDigest type.
var AuthDigests = []*AuthDigest{
	// Legacy digests
	{Creator: md5.New, Names: []string{"MD5", "SSL3-MD5", "md5", "ssl3-md5"}, Size: md5.Size},
	{Creator: sha1.New, Names: []string{"SHA-1", "SHA1", "SSL3-SHA1", "sha-1", "sha1", "ssl3-sha1"}, Size: sha1.Size},
	// SHA2 digests
	{Creator: sha256.New224, Names: []string{"SHA-224", "SHA2-224", "SHA224", "sha-224", "sha2-224", "sha224"}, Size: sha256.Size224},
	{Creator: sha256.New, Names: []string{"SHA-256", "SHA2-256", "SHA256", "sha-256", "sha2-256", "sha256"}, Size: sha256.Size},
	{Creator: sha512.New384, Names: []string{"SHA-384", "SHA2-384", "SHA384", "sha-384", "sha2-384", "sha384"}, Size: sha512.Size384},
	{Creator: sha512.New, Names: []string{"SHA-512", "SHA2-512", "SHA512", "sha-512", "sha2-512", "sha512"}, Size: sha512.Size},
	{Creator: sha512.New512_224, Names: []string{"SHA-512/224", "SHA2-512/224", "SHA512-224", "sha-512/224", "sha2-512/224", "sha512-224"}, Size: sha512.Size224},
	{Creator: sha512.New512_256, Names: []string{"SHA-512/256", "SHA2-512/256", "SHA512-256", "sha-512/256", "sha2-512/256", "sha512-256"}, Size: sha512.Size256},
	// SHA3 digests
	{Creator: sha3.New224, Names: []string{"SHA3-224", "sha3-224"}, Size: 28},
	{Creator: sha3.New256, Names: []string{"SHA3-256", "sha3-256"}, Size: 32},
	{Creator: sha3.New384, Names: []string{"SHA3-384", "sha3-384"}, Size: 48},
	{Creator: sha3.New512, Names: []string{"SHA3-512", "sha3-512"}, Size: 64},
	// BLAKE digests
	{
		Creator: func() hash.Hash {
			h, _ := blake2s.New256(nil)
			return h
		},
		Names: []string{"BLAKE2s-256", "BLAKE2S-256", "blake2s-256", "blake2S-256"},
		Size:  blake2s.Size,
	},
	{
		Creator: func() hash.Hash {
			h, _ := blake2b.New512(nil)
			return h
		},
		Names: []string{"BLAKE2b-512", "BLAKE2B-512", "blake2b-512", "blake2B-512"},
		Size:  blake2b.Size,
	},
	// SHAKE digests
	{
		Creator: func() hash.Hash {
			return sha3.NewShake128()
		},
		Names: []string{"SHAKE-128", "SHAKE128", "shake-128", "shake128"},
		Size:  32,
	},
	{
		Creator: func() hash.Hash {
			return sha3.NewShake256()
		},
		Names: []string{"SHAKE-256", "SHAKE256", "shake-256", "shake256"},
		Size:  64,
	},
	// Custom digests
	{
		// This MD5-SHA1 implementation outputs bytes that match many online generators. However,
		// its output never matches the HMACs of the sample packets generated on Windows and macOS.
		// Since OpenVPN uses the OpenSSL library under the hood, the reason for this hash mismatch
		// should most likely be traced there. Assuming the MD5-SHA1 digest has a very limited use,
		// there is little probability anyone will ever face this issue.
		Generator: func(key, plain []byte) []byte {
			hmacMD5 := hmac.New(md5.New, key[:md5.Size])
			hmacMD5.Write(plain)
			hmacSHA1 := hmac.New(sha1.New, key[:sha1.Size])
			hmacSHA1.Write(plain)
			result := make([]byte, 0, md5.Size+sha1.Size)
			return hmacSHA1.Sum(hmacMD5.Sum(result))
		},
		Names: []string{"MD5+SHA1", "MD5-SHA1", "MD5SHA1", "md5+sha1", "md5-sha1", "md5sha1"},
		Size:  md5.Size + sha1.Size,
	},
}

// AuthDigestSizes contains sizes of all the supported items of AuthDigest type.
var AuthDigestSizes = func() []int {
	presence := make([]bool, AuthHMACBytesMax+1)
	n := 0
	for _, ad := range AuthDigests {
		if !presence[ad.Size] {
			n++
			presence[ad.Size] = true
		}
	}
	sizes := make([]int, 0, n)
	for i, present := range presence {
		if present {
			sizes = append(sizes, i)
		}
	}
	return sizes
}()

// CryptCiphers contains all the supported items of CryptCipher type.
var CryptCiphers = []*CryptCipher{
	{
		Decryptor: func(key, iv, encrypted []byte) []byte {
			plain := make([]byte, len(encrypted))
			block, _ := aes.NewCipher(key)
			ctr := cipher.NewCTR(block, iv)
			ctr.XORKeyStream(plain, encrypted)
			return plain
		},
		Encryptor: func(key, iv, plain []byte) []byte {
			encrypted := make([]byte, len(plain))
			block, _ := aes.NewCipher(key)
			ctr := cipher.NewCTR(block, iv)
			ctr.XORKeyStream(encrypted, plain)
			return encrypted
		},
		Names:     []string{"AES-256-CTR", "aes-256-ctr"},
		SizeBlock: 16,
		SizeKey:   32,
	},
}

// AuthDigestDefault is the default AuthDigest used in the crypt and crypt2 modes (SHA-256).
var AuthDigestDefault = AuthDigestFindByName("SHA-256")

// CryptCipherDefault is the default CryptCipher used in the crypt and crypt2 modes (AES-256-CTR).
var CryptCipherDefault = CryptCipherFindByName("AES-256-CTR")

var StaticKeyFromFileBase64 = regexp.MustCompile("^(?:#.*?\\r?\\n)*" +
	"-----BEGIN OpenVPN tls-crypt-v2 (?:client|server) key-----\\r?\\n" +
	"([0-9a-zA-Z+=\\/\\r\\n]+)" +
	"-----END OpenVPN tls-crypt-v2 (?:client|server) key-----(?:\\r?\\n)?$")

var StaticKeyFromFileHex = regexp.MustCompile("^(?:#.*?\\r?\\n)*" +
	"-----BEGIN OpenVPN Static key V1-----\\r?\\n" +
	"([0-9a-fA-F\\r\\n]+)" +
	"-----END OpenVPN Static key V1-----(?:\\r?\\n)?$")

var ErrInvalidStaticKeyFileContents = errors.New("invalid static key file contents")

const (
	AuthHMACBytesMax = sha512.Size
	AuthHMACBytesMin = md5.Size

	CryptHMACBytesTotal = sha256.Size

	StaticKeyBytesTotal   = 256
	StaticKeyBytesHalf    = StaticKeyBytesTotal / 2
	StaticKeyBytesQuarter = StaticKeyBytesTotal / 4
)

// AuthDigestFindByName returns a pointer to AuthDigest having a given name or nil.
func AuthDigestFindByName(name string) *AuthDigest {
	for _, ad := range AuthDigests {
		if slices.Contains(ad.Names, name) {
			return ad
		}
	}
	return nil
}

// CryptCipherFindByName returns a pointer to CryptCipher having a given name or nil.
func CryptCipherFindByName(name string) *CryptCipher {
	for _, cc := range CryptCiphers {
		if slices.Contains(cc.Names, name) {
			return cc
		}
	}
	return nil
}

// HMACCreateAndGenerate uses a given digest creator to compute an HMAC of a given plain text with a given key.
func HMACCreateAndGenerate(creator func() hash.Hash, key, plain []byte) []byte {
	hmacDigest := hmac.New(creator, key)
	hmacDigest.Write(plain)
	return hmacDigest.Sum(nil)
}

// StaticKeyNewFromBase64 returns a pointer to StaticKey filled with bytes from a given base64 string.
func StaticKeyNewFromBase64(s string, inverse bool, bidi bool) *StaticKey {
	sk := &StaticKey{Inverse: inverse, Bidi: bidi}
	_ = sk.FromBase64(s)
	return sk
}

// StaticKeyNewFromHex returns a pointer to StaticKey filled with bytes from a given hex string.
func StaticKeyNewFromHex(s string, inverse bool, bidi bool) *StaticKey {
	sk := &StaticKey{Inverse: inverse, Bidi: bidi}
	_ = sk.FromHex(s)
	return sk
}
