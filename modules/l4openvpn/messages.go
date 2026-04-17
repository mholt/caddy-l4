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
	"encoding/base64"
	"encoding/binary"
	"errors"
	"slices"
	"time"
)

// MessageHeader is an OpenVPN message header.
type MessageHeader struct {
	// Opcode is a type of message that follows.
	Opcode uint8
	// KeyID refers to an already negotiated TLS session. It must equal zero for client reset messages.
	KeyID uint8
}

// FromBytes fills msg's internal structures from source bytes.
func (msg *MessageHeader) FromBytes(src []byte) error {
	// Any MessageHeader has exactly 1 byte.
	if len(src) != OpcodeKeyIDBytesTotal {
		return ErrInvalidSourceLength
	}

	// Opcode occupies the high 5 bits, KeyID extends over the low 3 bits.
	msg.KeyID, msg.Opcode = src[0]&KeyIDMask, src[0]>>OpcodeShift

	return nil
}

// ToBytes return a slice of bytes representing msg's internal structures.
func (msg *MessageHeader) ToBytes() []byte {
	dst := make([]byte, 0, OpcodeKeyIDBytesTotal)
	dst = append(dst, msg.KeyID|(msg.Opcode<<OpcodeShift))
	return dst
}

// MessagePlain is a P_CONTROL_HARD_RESET_CLIENT_V2-type OpenVPN message with no authentication.
type MessagePlain struct {
	MessageHeader

	// LocalSessionID contains an 8-byte session ID assigned on the client. It must be non-zero.
	LocalSessionID uint64
	// PrevPacketIDsCount indicates how many previous packet IDs will follow. It must equal zero.
	PrevPacketIDsCount uint8
	// ThisPacketID contains a 4-byte packet ID of the current message. It must equal zero.
	ThisPacketID uint32
}

// FromBytes fills msg's internal structures from a slice of bytes.
func (msg *MessagePlain) FromBytes(src []byte) error {
	// Any MessagePlain is exactly 14 bytes (with a header).
	if len(src) != MessagePlainBytesTotal {
		return ErrInvalidSourceLength
	}

	// Parse MessageHeader
	hdr := &MessageHeader{}
	if err := hdr.FromBytes(src[:OpcodeKeyIDBytesTotal]); err != nil {
		return err
	}

	// Match MessageHeader.Opcode
	if hdr.Opcode != OpcodeControlHardResetClientV2 {
		return ErrInvalidHeaderOpcode
	}

	// Parse everything else
	return msg.FromBytesHeadless(src[OpcodeKeyIDBytesTotal:], hdr)
}

// FromBytesHeadless fills msg's internal structures from a slice of bytes and uses a pre-filled header.
func (msg *MessagePlain) FromBytesHeadless(src []byte, hdr *MessageHeader) error {
	// Any MessagePlain is exactly 13 bytes long (without a header).
	if len(src) != MessagePlainBytesTotalHL {
		return ErrInvalidSourceLength
	}

	// Check for a non-empty MessageHeader.
	if hdr == nil {
		return ErrMissingReusableHeader
	}

	// Assign Header to the specified pointer.
	msg.MessageHeader = *hdr

	// Any MessagePlain has an 8-byte LocalSessionID at the beginning.
	msg.LocalSessionID = BytesOrder.Uint64(src[:SessionIDBytesTotal])

	// Any MessagePlain has a 1-byte PrevPacketIDsCount between LocalSessionID and ThisPacketID.
	msg.PrevPacketIDsCount = src[SessionIDBytesTotal]

	// Any MessagePlain has a 4-byte ThisPacketID at the end.
	msg.ThisPacketID = BytesOrder.Uint32(src[len(src)-PacketIDBytesTotal:])

	return nil
}

// Match returns true if msg's internal structures have valid values.
func (msg *MessagePlain) Match() bool {
	return msg.LocalSessionID > 0 && msg.PrevPacketIDsCount == 0 && msg.ThisPacketID == 0
}

// ToBytes return a slice of bytes representing msg's internal structures.
func (msg *MessagePlain) ToBytes() []byte {
	dst := make([]byte, 0, MessagePlainBytesTotal)
	dst = append(dst, msg.MessageHeader.ToBytes()...)
	dst = BytesOrder.AppendUint64(dst, msg.LocalSessionID)
	dst = append(dst, msg.PrevPacketIDsCount)
	dst = BytesOrder.AppendUint32(dst, msg.ThisPacketID)
	return dst
}

// MessageAuth is a P_CONTROL_HARD_RESET_CLIENT_V2-type OpenVPN message with authentication.
type MessageAuth struct {
	MessagePlain
	MessageTraitAuth
	MessageTraitReplay
}

// Authenticate returns true if msg has a valid HMAC.
func (msg *MessageAuth) Authenticate(ad *AuthDigest, sk *StaticKey) bool {
	return msg.AuthenticateOnServer(ad, sk, msg.ToBytesAuth)
}

// FromBytes fills msg's internal structures from a slice of bytes.
func (msg *MessageAuth) FromBytes(src []byte) error {
	// Any MessageAuth is between 38 and 86 bytes (with a header).
	if len(src) < MessageAuthBytesMin || len(src) > MessageAuthBytesMax {
		return ErrInvalidSourceLength
	}

	// Parse MessageHeader
	hdr := &MessageHeader{}
	if err := hdr.FromBytes(src[:OpcodeKeyIDBytesTotal]); err != nil {
		return err
	}

	// Match MessageHeader.Opcode
	if hdr.Opcode != OpcodeControlHardResetClientV2 {
		return ErrInvalidHeaderOpcode
	}

	// Parse everything else
	return msg.FromBytesHeadless(src[OpcodeKeyIDBytesTotal:], hdr)
}

// FromBytesHeadless fills msg's internal structures from a slice of bytes and uses a pre-filled header.
func (msg *MessageAuth) FromBytesHeadless(src []byte, hdr *MessageHeader) error {
	// Any MessageAuth is between 37 and 85 bytes long (without a header).
	if len(src) < MessageAuthBytesMinHL || len(src) > MessageAuthBytesMaxHL {
		return ErrInvalidSourceLength
	}

	// Check for a non-empty MessageHeader.
	if hdr == nil {
		return ErrMissingReusableHeader
	}

	// Assign Header to the specified pointer.
	msg.MessageHeader = *hdr

	// Any MessageAuth has an 8-byte LocalSessionID at the beginning.
	msg.LocalSessionID = BytesOrder.Uint64(src[:SessionIDBytesTotal])

	// Any MessageAuth has a 16-to-64-byte HMAC between LocalSessionID and ReplayPacketID.
	off1, off2 := SessionIDBytesTotal, len(src)-2*PacketIDBytesTotal-OpcodeKeyIDBytesTotal-TimestampBytesTotal
	msg.HMAC = src[off1:off2]

	// Check whether a valid HMAC length is provided.
	if !slices.Contains(AuthDigestSizes, len(msg.HMAC)) {
		return ErrInvalidHMACLength
	}

	// Any MessageAuth has a 4-byte ReplayPacketID between HMAC and ReplayTimestamp.
	off1, off2 = off2, off2+PacketIDBytesTotal
	msg.ReplayPacketID = BytesOrder.Uint32(src[off1:off2])

	// Any MessageAuth has a 4-byte ReplayTimestamp between ReplayPacketID and PrevPacketIDsCount.
	off1, off2 = off2, off2+TimestampBytesTotal
	msg.ReplayTimestamp = BytesOrder.Uint32(src[off1:off2])

	// Any MessageAuth has a 1-byte PrevPacketIDsCount between ReplayTimestamp and ThisPacketID.
	off1, off2 = off2, off2+OpcodeKeyIDBytesTotal
	msg.PrevPacketIDsCount = src[off1]

	// Any MessageAuth has a 4-byte ThisPacketID at the end.
	msg.ThisPacketID = BytesOrder.Uint32(src[off2:])

	return nil
}

// Match returns true if msg's internal structures have valid values.
func (msg *MessageAuth) Match(ignoreTimestamp, ignoreCrypto bool, ad *AuthDigest, sk *StaticKey) bool {
	return msg.MessagePlain.Match() &&
		msg.ReplayPacketID == 1 && (ignoreTimestamp || msg.ValidateReplayTimestamp(time.Now())) &&
		(ad == nil || ad.Size == len(msg.HMAC)) &&
		(ignoreCrypto || sk == nil || msg.Authenticate(ad, sk))
}

// Sign computes and fills msg's HMAC.
func (msg *MessageAuth) Sign(ad *AuthDigest, sk *StaticKey) error {
	return msg.SignOnClient(ad, sk, msg.ToBytesAuth)
}

// ToBytes returns a slice of bytes representing msg's internal structures.
func (msg *MessageAuth) ToBytes() []byte {
	dst := make([]byte, 0, MessagePlainBytesTotal+len(msg.HMAC)+PacketIDBytesTotal+TimestampBytesTotal)
	dst = append(dst, msg.MessageHeader.ToBytes()...)
	dst = BytesOrder.AppendUint64(dst, msg.LocalSessionID)
	dst = append(dst, msg.HMAC...)
	dst = BytesOrder.AppendUint32(dst, msg.ReplayPacketID)
	dst = BytesOrder.AppendUint32(dst, msg.ReplayTimestamp)
	dst = append(dst, msg.PrevPacketIDsCount)
	dst = BytesOrder.AppendUint32(dst, msg.ThisPacketID)
	return dst
}

// ToBytesAuth returns a slice of bytes representing msg's internal structures without HMAC.
func (msg *MessageAuth) ToBytesAuth() []byte {
	dst := make([]byte, 0, MessagePlainBytesTotal+PacketIDBytesTotal+TimestampBytesTotal)
	dst = BytesOrder.AppendUint32(dst, msg.ReplayPacketID)
	dst = BytesOrder.AppendUint32(dst, msg.ReplayTimestamp)
	dst = append(dst, msg.MessageHeader.ToBytes()...)
	dst = BytesOrder.AppendUint64(dst, msg.LocalSessionID)
	dst = append(dst, msg.PrevPacketIDsCount)
	dst = BytesOrder.AppendUint32(dst, msg.ThisPacketID)
	return dst
}

// MessageCrypt is a P_CONTROL_HARD_RESET_CLIENT_V2-type OpenVPN message with authentication and encryption.
type MessageCrypt struct {
	MessageAuth
	MessageTraitCrypt
}

// Authenticate returns true if msg has a valid HMAC.
func (msg *MessageCrypt) Authenticate(ad *AuthDigest, sk *StaticKey) bool {
	return msg.AuthenticateOnServer(ad, sk, msg.ToBytesAuth)
}

// DecryptAndAuthenticate decrypts msg's encrypted bytes before calling Authenticate.
func (msg *MessageCrypt) DecryptAndAuthenticate(ad *AuthDigest, sk *StaticKey) bool {
	if len(msg.Encrypted) != OpcodeKeyIDBytesTotal+PacketIDBytesTotal ||
		msg.DecryptOnServer(sk, &msg.MessageTraitAuth, msg.FromBytesCrypt) != nil {
		return false
	}
	return msg.Authenticate(ad, sk)
}

// EncryptAndSign encrypts msg's plain bytes before calling Sign.
func (msg *MessageCrypt) EncryptAndSign(ad *AuthDigest, sk *StaticKey) error {
	if err := msg.EncryptOnClient(sk, &msg.MessageTraitAuth, msg.ToBytesCrypt); err != nil {
		return err
	}
	return msg.Sign(ad, sk)
}

// FromBytes fills msg's internal structures from a slice of bytes.
func (msg *MessageCrypt) FromBytes(src []byte) error {
	// Any MessageCrypt is between 54 bytes (with a header).
	if len(src) != MessageCryptBytesTotal {
		return ErrInvalidSourceLength
	}

	// Parse MessageHeader
	hdr := &MessageHeader{}
	if err := hdr.FromBytes(src[:OpcodeKeyIDBytesTotal]); err != nil {
		return err
	}

	// Match MessageHeader.Opcode
	if hdr.Opcode != OpcodeControlHardResetClientV2 {
		return ErrInvalidHeaderOpcode
	}

	// Parse everything else
	return msg.FromBytesHeadless(src[OpcodeKeyIDBytesTotal:], hdr)
}

// FromBytesHeadless fills msg's internal structures from a slice of bytes and uses a pre-filled header.
func (msg *MessageCrypt) FromBytesHeadless(src []byte, hdr *MessageHeader) error {
	// Any MessageCrypt is exactly 53 bytes long (without a header).
	if len(src) != MessageCryptBytesTotalHL {
		return ErrInvalidSourceLength
	}

	// Check for a non-empty MessageHeader.
	if hdr == nil {
		return ErrMissingReusableHeader
	}

	// Assign Header to the specified pointer.
	msg.MessageHeader = *hdr

	// Any MessageCrypt has an 8-byte LocalSessionID at the beginning.
	msg.LocalSessionID = BytesOrder.Uint64(src[:SessionIDBytesTotal])

	// Any MessageCrypt has a 4-byte ReplayPacketID between LocalSessionID and ReplayTimestamp.
	off1, off2 := SessionIDBytesTotal, SessionIDBytesTotal+PacketIDBytesTotal
	msg.ReplayPacketID = BytesOrder.Uint32(src[off1:off2])

	// Any MessageCrypt has a 4-byte ReplayTimestamp between ReplayPacketID and HMAC.
	off1, off2 = off2, off2+TimestampBytesTotal
	msg.ReplayTimestamp = BytesOrder.Uint32(src[off1:off2])

	// Any MessageCrypt has a 32-byte SHA-256 HMAC between ReplayTimestamp and Encrypted bytes.
	off1, off2 = off2, off2+AuthDigestDefault.Size
	msg.Digest, msg.HMAC = AuthDigestDefault, src[off1:off2]

	// Any MessageCrypt has a 5-byte Encrypted part at the end.
	msg.Cipher, msg.Encrypted = CryptCipherDefault, src[off2:]

	return nil
}

// FromBytesCrypt fills msg's internal structures from a slice of bytes after decryption.
func (msg *MessageCrypt) FromBytesCrypt(plain []byte) error {
	if len(plain) != len(msg.Encrypted) {
		return ErrInvalidPlainLength
	}

	// Any MessageCrypt has a PrevPacketIDsCount at the beginning of the plain text.
	msg.PrevPacketIDsCount = plain[0]

	// Any MessageCrypt has a ThisPacketID at the end of the plain text.
	msg.ThisPacketID = BytesOrder.Uint32(plain[OpcodeKeyIDBytesTotal:])

	return nil
}

// Match returns true if msg's internal structures have valid values.
func (msg *MessageCrypt) Match(ignoreTimestamp, ignoreCrypto bool, ad *AuthDigest, sk *StaticKey) bool {
	return msg.LocalSessionID > 0 &&
		msg.ReplayPacketID == 1 && (ignoreTimestamp || msg.ValidateReplayTimestamp(time.Now())) &&
		(ignoreCrypto || sk == nil || (msg.DecryptAndAuthenticate(ad, sk) &&
			msg.PrevPacketIDsCount == 0 && msg.ThisPacketID == 0))
}

// Sign computes and fills msg's HMAC.
func (msg *MessageCrypt) Sign(ad *AuthDigest, sk *StaticKey) error {
	return msg.SignOnClient(ad, sk, msg.ToBytesAuth)
}

// ToBytes returns a slice of bytes representing msg's internal structures.
func (msg *MessageCrypt) ToBytes() []byte {
	dst := make([]byte, 0, MessagePlainBytesTotal+len(msg.HMAC)+PacketIDBytesTotal+TimestampBytesTotal)
	dst = append(dst, msg.MessageHeader.ToBytes()...)
	dst = BytesOrder.AppendUint64(dst, msg.LocalSessionID)
	dst = BytesOrder.AppendUint32(dst, msg.ReplayPacketID)
	dst = BytesOrder.AppendUint32(dst, msg.ReplayTimestamp)
	dst = append(dst, msg.HMAC...)
	dst = append(dst, msg.Encrypted...)
	return dst
}

// ToBytesAuth returns a slice of bytes representing msg's internal structures without HMAC.
func (msg *MessageCrypt) ToBytesAuth() []byte {
	dst := make([]byte, 0, MessagePlainBytesTotal+PacketIDBytesTotal+TimestampBytesTotal)
	dst = append(dst, msg.MessageHeader.ToBytes()...)
	dst = BytesOrder.AppendUint64(dst, msg.LocalSessionID)
	dst = BytesOrder.AppendUint32(dst, msg.ReplayPacketID)
	dst = BytesOrder.AppendUint32(dst, msg.ReplayTimestamp)
	dst = append(dst, msg.PrevPacketIDsCount)
	dst = BytesOrder.AppendUint32(dst, msg.ThisPacketID)
	return dst
}

// ToBytesCrypt returns a slice of bytes representing msg's internal structures before encryption.
func (msg *MessageCrypt) ToBytesCrypt() []byte {
	dst := make([]byte, 0, OpcodeKeyIDBytesTotal+PacketIDBytesTotal)
	dst = append(dst, msg.PrevPacketIDsCount)
	dst = BytesOrder.AppendUint32(dst, msg.ThisPacketID)
	return dst
}

// MessageCrypt2 is a P_CONTROL_HARD_RESET_CLIENT_V3-type OpenVPN message with authentication and encryption
// using a wrapped client key which is authenticated and encrypted with a server key.
type MessageCrypt2 struct {
	MessageCrypt
	WrappedKey
}

// DecryptAndAuthenticate decrypts and authenticates msg's encrypted bytes (WrappedKey before MessageCrypt).
func (msg *MessageCrypt2) DecryptAndAuthenticate(ad *AuthDigest, sk *StaticKey) bool {
	if !msg.WrappedKey.DecryptAndAuthenticate(ad, sk) {
		return false
	}
	return msg.MessageCrypt.DecryptAndAuthenticate(ad, &msg.StaticKey)
}

// EncryptAndSign encrypts and signs msg's plain bytes (WrappedKey before MessageCrypt).
func (msg *MessageCrypt2) EncryptAndSign(ad *AuthDigest, sk *StaticKey) error {
	if err := msg.WrappedKey.EncryptAndSign(ad, sk); err != nil {
		return err
	}
	return msg.MessageCrypt.EncryptAndSign(ad, &msg.StaticKey)
}

// FromBytes fills msg's internal structures from a slice of bytes.
func (msg *MessageCrypt2) FromBytes(src []byte) error {
	// Any MessageCrypt2 is between 344 and 600 bytes (with a header).
	if len(src) < MessageCrypt2BytesMin || len(src) > MessageCrypt2BytesMax {
		return ErrInvalidSourceLength
	}

	// Parse MessageHeader
	hdr := &MessageHeader{}
	if err := hdr.FromBytes(src[:OpcodeKeyIDBytesTotal]); err != nil {
		return err
	}

	// Match MessageHeader.Opcode
	if hdr.Opcode != OpcodeControlHardResetClientV3 {
		return ErrInvalidHeaderOpcode
	}

	// Parse everything else
	return msg.FromBytesHeadless(src[OpcodeKeyIDBytesTotal:], hdr)
}

// FromBytesHeadless fills msg's internal structures from a slice of bytes and uses a pre-filled header.
func (msg *MessageCrypt2) FromBytesHeadless(src []byte, hdr *MessageHeader) error {
	// Any MessageCrypt2 is between 343 and 1077 bytes long (without a header).
	if len(src) < MessageCrypt2BytesMinHL || len(src) > MessageCrypt2BytesMaxHL {
		return ErrInvalidSourceLength
	}

	if err := msg.MessageCrypt.FromBytesHeadless(src[:MessageCryptBytesTotalHL], hdr); err != nil {
		return err
	}

	return msg.WrappedKey.FromBytes(src[MessageCryptBytesTotalHL:])
}

// Match returns true if msg's internal structures have valid values.
func (msg *MessageCrypt2) Match(ignoreTimestamp, ignoreCrypto bool, ad *AuthDigest, sk *StaticKey, cks []*WrappedKey) bool {
	if !(msg.LocalSessionID > 0 && (msg.ReplayPacketID == 1 || msg.ReplayPacketID == 0x0f000001) && //nolint:staticcheck
		(ignoreTimestamp || msg.ValidateReplayTimestamp(time.Now()))) {
		return false
	}

	if ignoreCrypto {
		return true
	}

	if len(cks) > 0 {
		for _, ck := range cks {
			if bytes.Equal(ck.HMAC, msg.HMAC) && bytes.Equal(ck.Encrypted, msg.WrappedKey.Encrypted) {
				return msg.MessageCrypt.DecryptAndAuthenticate(ad, &ck.StaticKey) &&
					msg.PrevPacketIDsCount == 0 && msg.ThisPacketID == 0
			}
		}
		return false
	}

	return sk == nil || (msg.DecryptAndAuthenticate(ad, sk) && msg.PrevPacketIDsCount == 0 && msg.ThisPacketID == 0)
}

// ToBytes returns a slice of bytes representing msg's internal structures.
func (msg *MessageCrypt2) ToBytes() []byte {
	return slices.Concat(msg.MessageCrypt.ToBytes(), msg.WrappedKey.ToBytes())
}

// MessageTraitAuth contains fields and implements features related to authentication.
type MessageTraitAuth struct {
	// Digest is a pointer to AuthDigest to be used for authentication.
	Digest *AuthDigest
	// HMAC is a hash-based messaged authentication code used to verify message integrity.
	HMAC []byte
}

// AuthenticateOnClient returns true if msg composed on the client has a valid HMAC.
func (msg *MessageTraitAuth) AuthenticateOnClient(ad *AuthDigest, sk *StaticKey, xp func() []byte) bool {
	// No supported digest returns an HMAC of 0 bytes.
	if len(msg.HMAC) == 0 {
		return false
	}

	// Check that there is a valid StaticKey.
	// A half key may be provided as a server key to validate a WrappedKey.
	if sk == nil || !(len(sk.KeyBytes) == StaticKeyBytesTotal || len(sk.KeyBytes) == StaticKeyBytesHalf) { //nolint:staticcheck
		return false
	}

	// Obtain a slice of bytes to compute a digest of.
	plain := xp()

	// Firstly, try the given digest.
	if ad != nil {
		if len(msg.HMAC) == ad.Size && ad.HMACValidateOnClient(sk, plain, msg.HMAC) {
			msg.Digest = ad
			return true
		}
		return false
	}

	// Secondly, try the last successful one saved as Digest.
	if msg.Digest != nil && len(msg.HMAC) == msg.Digest.Size && msg.Digest.HMACValidateOnClient(sk, plain, msg.HMAC) {
		return true
	}

	// Finally, try all other supported digests one by one.
	for _, mad := range AuthDigests {
		if mad != msg.Digest && len(msg.HMAC) == mad.Size && mad.HMACValidateOnClient(sk, plain, msg.HMAC) {
			msg.Digest = mad
			return true
		}
	}

	return false
}

// AuthenticateOnServer returns true if msg composed on the server has a valid HMAC.
func (msg *MessageTraitAuth) AuthenticateOnServer(ad *AuthDigest, sk *StaticKey, xp func() []byte) bool {
	// No supported digest returns an HMAC of 0 bytes.
	if len(msg.HMAC) == 0 {
		return false
	}

	// Check that there is a valid StaticKey.
	if sk == nil || len(sk.KeyBytes) != StaticKeyBytesTotal {
		return false
	}

	// Obtain a slice of bytes to compute a digest of.
	plain := xp()

	// Firstly, try the given digest.
	if ad != nil {
		if len(msg.HMAC) == ad.Size && ad.HMACValidateOnServer(sk, plain, msg.HMAC) {
			msg.Digest = ad
			return true
		}
		return false
	}

	// Secondly, try the last successful one saved as Digest.
	if msg.Digest != nil && len(msg.HMAC) == msg.Digest.Size && msg.Digest.HMACValidateOnServer(sk, plain, msg.HMAC) {
		return true
	}

	// Finally, try all other supported digests one by one.
	for _, mad := range AuthDigests {
		if mad != msg.Digest && len(msg.HMAC) == mad.Size && mad.HMACValidateOnServer(sk, plain, msg.HMAC) {
			msg.Digest = mad
			return true
		}
	}

	return false
}

// SignOnClient computes an HMAC for msg composed on the client.
func (msg *MessageTraitAuth) SignOnClient(ad *AuthDigest, sk *StaticKey, xp func() []byte) error {
	// Check that there is a valid StaticKey.
	// A half key may be provided as a server key to sign a WrappedKey.
	if sk == nil || !(len(sk.KeyBytes) == StaticKeyBytesTotal || len(sk.KeyBytes) == StaticKeyBytesHalf) { //nolint:staticcheck
		return ErrInvalidAuthPrerequisites
	}

	// Obtain a slice of bytes to compute a digest of.
	plain := xp()

	// Firstly, try the given digest.
	if ad != nil {
		msg.HMAC = ad.HMACGenerateOnClient(sk, plain)
	}

	// Secondly, try the internal Digest.
	if msg.Digest != nil {
		msg.HMAC = msg.Digest.HMACGenerateOnClient(sk, plain)
	}

	// Finally, use the default digest.
	msg.Digest, msg.HMAC = AuthDigestDefault, AuthDigestDefault.HMACGenerateOnClient(sk, plain)

	return nil
}

// SignOnServer computes an HMAC for msg composed on the server.
func (msg *MessageTraitAuth) SignOnServer(ad *AuthDigest, sk *StaticKey, xp func() []byte) error {
	// Check that there is a valid StaticKey.
	// A half key may be provided as a server key to sign a WrappedKey.
	if sk == nil || !(len(sk.KeyBytes) == StaticKeyBytesTotal || len(sk.KeyBytes) == StaticKeyBytesHalf) { //nolint:staticcheck
		return ErrInvalidAuthPrerequisites
	}

	// Obtain a slice of bytes to compute a digest of.
	plain := xp()

	// Firstly, try the given digest.
	if ad != nil {
		msg.HMAC = ad.HMACGenerateOnServer(sk, plain)
	}

	// Secondly, try the internal Digest.
	if msg.Digest != nil {
		msg.HMAC = msg.Digest.HMACGenerateOnServer(sk, plain)
	}

	// Finally, use the default digest.
	msg.Digest, msg.HMAC = AuthDigestDefault, AuthDigestDefault.HMACGenerateOnServer(sk, plain)

	return nil
}

// MessageTraitCrypt contains fields and implements features related to en-/decryption.
type MessageTraitCrypt struct {
	// Cipher is a pointer to CryptCipher to be used for encryption.
	Cipher *CryptCipher
	// Encrypted contains a number of bytes to be decrypted.
	Encrypted []byte
}

// DecryptOnClient decrypts msg's encrypted bytes with an encryption key used by the server.
func (msg *MessageTraitCrypt) DecryptOnClient(sk *StaticKey, ta *MessageTraitAuth, xd func([]byte) error) error {
	if sk == nil || msg.Cipher == nil || ta.Digest == nil || len(ta.HMAC) != ta.Digest.Size {
		return ErrInvalidCryptPrerequisites
	}

	plain := msg.Cipher.DecryptOnClient(sk, ta.HMAC[:min(msg.Cipher.SizeBlock, ta.Digest.Size)], msg.Encrypted)

	return xd(plain)
}

// DecryptOnServer decrypts msg's encrypted bytes with an encryption key used by the client.
func (msg *MessageTraitCrypt) DecryptOnServer(sk *StaticKey, ta *MessageTraitAuth, xd func([]byte) error) error {
	if sk == nil || msg.Cipher == nil || ta.Digest == nil || len(ta.HMAC) != ta.Digest.Size {
		return ErrInvalidCryptPrerequisites
	}

	plain := msg.Cipher.DecryptOnServer(sk, ta.HMAC[:min(msg.Cipher.SizeBlock, ta.Digest.Size)], msg.Encrypted)

	return xd(plain)
}

// EncryptOnClient encrypts msg's plain bytes with a decryption key used by the server.
func (msg *MessageTraitCrypt) EncryptOnClient(sk *StaticKey, ta *MessageTraitAuth, xe func() []byte) error {
	if sk == nil || msg.Cipher == nil || ta.Digest == nil || len(ta.HMAC) != ta.Digest.Size {
		return ErrInvalidCryptPrerequisites
	}

	plain := xe()

	msg.Encrypted = msg.Cipher.EncryptOnClient(sk, ta.HMAC[:min(msg.Cipher.SizeBlock, ta.Digest.Size)], plain)
	if len(plain) != len(msg.Encrypted) {
		return ErrInvalidEncryptedLength
	}

	return nil
}

// EncryptOnServer encrypts msg's plain bytes with a decryption key used by the client.
func (msg *MessageTraitCrypt) EncryptOnServer(sk *StaticKey, ta *MessageTraitAuth, xe func() []byte) error {
	if sk == nil || msg.Cipher == nil || ta.Digest == nil || len(ta.HMAC) != ta.Digest.Size {
		return ErrInvalidCryptPrerequisites
	}

	plain := xe()

	msg.Encrypted = msg.Cipher.EncryptOnServer(sk, ta.HMAC[:min(msg.Cipher.SizeBlock, ta.Digest.Size)], plain)
	if len(plain) != len(msg.Encrypted) {
		return ErrInvalidEncryptedLength
	}

	return nil
}

// MessageTraitReplay contains fields and implements features related to replay protection.
type MessageTraitReplay struct {
	// ReplayPacketID is a 4-byte packet ID used for replay protection.
	ReplayPacketID uint32
	// ReplayTimestamp is a 4-byte timestamp used for replay protection.
	ReplayTimestamp uint32
}

// ValidateReplayTimestamp returns true if msg has a valid ReplayTimestamp (relative to the provided time).
func (msg *MessageTraitReplay) ValidateReplayTimestamp(t time.Time) bool {
	tReplay := time.Unix(int64(msg.ReplayTimestamp), 0)
	tNowLow := t.UTC().Add(-TimestampValidationInterval)
	tNowHigh := t.UTC().Add(TimestampValidationInterval)
	return tReplay.After(tNowLow) && tReplay.Before(tNowHigh)
}

// MetaData is an optional set of Type and Payload that may be included into WrappedKey.
type MetaData struct {
	// Payload contains a number of bytes of variable length corresponding to Type.
	Payload []byte
	// Type indicates how to parse Payload correctly. It may equal 0x00 for any user defined data
	// and 0x01 for a 4-byte timestamp which enables discarding old client keys on the server.
	Type uint8
}

// WrappedKey is an authenticated and encrypted client key used to encrypt MessageCrypt in the crypt2 mode.
type WrappedKey struct {
	MetaData
	StaticKey
	MessageTraitAuth
	MessageTraitCrypt
}

// Authenticate returns true if wk's HMAC is valid.
func (wk *WrappedKey) Authenticate(ad *AuthDigest, sk *StaticKey) bool {
	return wk.AuthenticateOnClient(ad, sk, wk.ToBytesAuth)
}

// DecryptAndAuthenticate decrypts wk's encrypted bytes before calling Authenticate.
func (wk *WrappedKey) DecryptAndAuthenticate(ad *AuthDigest, sk *StaticKey) bool {
	if len(wk.Encrypted) < StaticKeyBytesTotal ||
		len(wk.Encrypted) > WrappedKeyBytesMax-LengthBytesTotal-CryptHMACBytesTotal ||
		wk.DecryptOnClient(sk, &wk.MessageTraitAuth, wk.FromBytesCrypt) != nil {
		return false
	}
	return wk.Authenticate(ad, sk)
}

// EncryptAndSign encrypts wk's plain bytes before calling Sign.
func (wk *WrappedKey) EncryptAndSign(ad *AuthDigest, sk *StaticKey) error {
	if err := wk.EncryptOnServer(sk, &wk.MessageTraitAuth, wk.ToBytesCrypt); err != nil {
		return err
	}
	return wk.Sign(ad, sk)
}

// FromBase64 fills wk's internal structures (including decrypted StaticKey bytes) from a base64 string.
func (wk *WrappedKey) FromBase64(s string) error {
	src, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}

	if len(src) < WrappedKeyBytesMin+StaticKeyBytesTotal || len(src) > WrappedKeyBytesMax+StaticKeyBytesTotal {
		return ErrInvalidSourceLength
	}

	wk.KeyBytes = src[:StaticKeyBytesTotal]

	return wk.FromBytes(src[StaticKeyBytesTotal:])
}

// FromBytes fills wk's internal structures from a slice of bytes.
func (wk *WrappedKey) FromBytes(src []byte) error {
	// Any WrappedKey has a 2-byte length at the end. Ensure that it has a valid value.
	if len(src) < WrappedKeyBytesMin || len(src) > WrappedKeyBytesMax ||
		len(src) != int(BytesOrder.Uint16(src[len(src)-LengthBytesTotal:])) {
		return ErrInvalidSourceLength
	}

	// Any WrappedKey has a 32-byte SHA-256 HMAC at the beginning.
	wk.Digest, wk.HMAC = AuthDigestDefault, src[:CryptHMACBytesTotal]

	// Any WrappedKey has an Encrypted part of at least 256 bytes between HMAC and Length.
	wk.Cipher, wk.Encrypted = CryptCipherDefault, src[CryptHMACBytesTotal:len(src)-LengthBytesTotal]

	return nil
}

// FromBytesCrypt fills wk's internal structures from a slice of bytes after decryption.
func (wk *WrappedKey) FromBytesCrypt(plain []byte) error {
	if len(plain) != len(wk.Encrypted) {
		return ErrInvalidPlainLength
	}

	// Any WrappedKey has a StaticKey at the beginning of the plain text.
	wk.KeyBytes = plain[:StaticKeyBytesTotal]

	// Any WrappedKey may have a MetaData.Type between StaticKey and MetaData in the plain text.
	if len(plain) > StaticKeyBytesTotal {
		wk.Type = plain[StaticKeyBytesTotal]
	}

	// Any KeyMata may have MetaData.Payload at the end of the plain text.
	if len(plain) > StaticKeyBytesTotal+MetaDataTypeBytesTotal {
		wk.Payload = plain[StaticKeyBytesTotal+MetaDataTypeBytesTotal:]
	}

	return nil
}

// FromClientKeyFile fills wk's internal structures (including decrypted StaticKey bytes) from a given file.
func (wk *WrappedKey) FromClientKeyFile(path string) error {
	err := wk.FromFile(path, StaticKeyFromFileBase64, 0, wk.StaticKey.FromBase64)
	if err != nil {
		return err
	}

	if len(wk.KeyBytes) < WrappedKeyBytesMin || len(wk.KeyBytes) > WrappedKeyBytesMax {
		return ErrInvalidStaticKeyFileContents
	}

	err = wk.FromBytes(wk.KeyBytes[StaticKeyBytesTotal:])
	if err != nil {
		return err
	}

	wk.KeyBytes = wk.KeyBytes[:StaticKeyBytesTotal]
	return nil
}

// Sign computes and fills wk's HMAC.
func (wk *WrappedKey) Sign(ad *AuthDigest, sk *StaticKey) error {
	return wk.SignOnClient(ad, sk, wk.ToBytesAuth)
}

// ToBytes returns a slice of bytes representing wk's internal structures.
func (wk *WrappedKey) ToBytes() []byte {
	dst := make([]byte, 0, len(wk.HMAC)+len(wk.Encrypted)+LengthBytesTotal)
	dst = append(dst, wk.HMAC...)
	dst = append(dst, wk.Encrypted...)
	dst = BytesOrder.AppendUint16(dst, uint16(cap(dst))) //nolint:gosec // disable G115
	return dst
}

// ToBytesAuth returns a slice of bytes representing wk's internal structures without HMAC.
func (wk *WrappedKey) ToBytesAuth() []byte {
	if len(wk.Payload) > 0 {
		dst := make([]byte, 0, LengthBytesTotal+len(wk.KeyBytes)+MetaDataTypeBytesTotal+len(wk.Payload))
		dst = BytesOrder.AppendUint16(dst, uint16(cap(dst)+CryptHMACBytesTotal)) //nolint:gosec // disable G115
		dst = append(dst, wk.KeyBytes...)
		dst = append(dst, wk.Type)
		dst = append(dst, wk.Payload...)
		return dst
	} else {
		dst := make([]byte, 0, LengthBytesTotal+len(wk.KeyBytes))
		dst = BytesOrder.AppendUint16(dst, uint16(cap(dst)+CryptHMACBytesTotal)) //nolint:gosec // disable G115
		dst = append(dst, wk.KeyBytes...)
		return dst
	}
}

// ToBytesCrypt returns a slice of bytes representing wk's internal structures before encryption.
func (wk *WrappedKey) ToBytesCrypt() []byte {
	if len(wk.Payload) > 0 {
		dst := make([]byte, 0, len(wk.KeyBytes)+MetaDataTypeBytesTotal+len(wk.Payload))
		dst = append(dst, wk.KeyBytes...)
		dst = append(dst, wk.Type)
		dst = append(dst, wk.Payload...)
		return dst
	} else {
		return wk.KeyBytes
	}
}

var (
	BytesOrder = binary.BigEndian

	ErrInvalidAuthPrerequisites  = errors.New("invalid auth prerequisites")
	ErrInvalidCryptPrerequisites = errors.New("invalid crypt prerequisites")
	ErrInvalidEncryptedLength    = errors.New("invalid encrypted length")
	ErrInvalidHeaderOpcode       = errors.New("invalid header opcode")
	ErrInvalidHMACLength         = errors.New("invalid HMAC length")
	ErrInvalidPlainLength        = errors.New("invalid plain length")
	ErrInvalidSourceLength       = errors.New("invalid source length")
	ErrMissingReusableHeader     = errors.New("missing reusable header")
)

const (
	/*
	 *	Irrelevant MessageHeader.Opcode values:
	 *
	 *	OpcodeControlHardResetClientV1  uint8 = 1
	 *	OpcodeControlHardResetServerV1  uint8 = 2
	 *	OpcodeControlSoftResetV1        uint8 = 3
	 *	OpcodeControlV1                 uint8 = 4
	 *	OpcodeAckV1                     uint8 = 5
	 *	OpcodeDataV1                    uint8 = 6
	 *	OpcodeControlHardResetServerV2  uint8 = 8
	 *	OpcodeDataV2                    uint8 = 9
	 *	OpcodeControlWrappedClientKeyV1 uint8 = 11
	 */

	OpcodeControlHardResetClientV2 uint8 = 7
	OpcodeControlHardResetClientV3 uint8 = 10

	KeyIDMask uint8 = 0b1<<OpcodeShift - 1

	OpcodeShift = 3

	AckPacketIDsCountBytesTotal = 1
	LengthBytesTotal            = 2
	MetaDataPayloadBytesMax     = WrappedKeyBytesMax - MetaDataTypeBytesTotal - WrappedKeyBytesMin
	MetaDataTypeBytesTotal      = 1
	OpcodeKeyIDBytesTotal       = 1
	PacketIDBytesTotal          = 4
	SessionIDBytesTotal         = 8
	TimestampBytesTotal         = 4

	WrappedKeyBytesMax = 1024
	WrappedKeyBytesMin = CryptHMACBytesTotal + StaticKeyBytesTotal + LengthBytesTotal

	TimestampValidationInterval = 15 * time.Second

	MessagePlainBytesTotalHL = SessionIDBytesTotal + AckPacketIDsCountBytesTotal + PacketIDBytesTotal
	MessagePlainBytesTotal   = OpcodeKeyIDBytesTotal + MessagePlainBytesTotalHL
	MessageAuthBytesMaxHL    = MessagePlainBytesTotalHL + AuthHMACBytesMax + PacketIDBytesTotal + TimestampBytesTotal
	MessageAuthBytesMax      = OpcodeKeyIDBytesTotal + MessageAuthBytesMaxHL
	MessageAuthBytesMinHL    = MessagePlainBytesTotalHL + AuthHMACBytesMin + PacketIDBytesTotal + TimestampBytesTotal
	MessageAuthBytesMin      = OpcodeKeyIDBytesTotal + MessageAuthBytesMinHL
	MessageCryptBytesTotalHL = MessagePlainBytesTotalHL + PacketIDBytesTotal + TimestampBytesTotal + CryptHMACBytesTotal
	MessageCryptBytesTotal   = OpcodeKeyIDBytesTotal + MessageCryptBytesTotalHL
	MessageCrypt2BytesMinHL  = MessageCryptBytesTotalHL + LengthBytesTotal + CryptHMACBytesTotal + StaticKeyBytesTotal
	MessageCrypt2BytesMin    = OpcodeKeyIDBytesTotal + MessageCrypt2BytesMinHL
	MessageCrypt2BytesMaxHL  = MessageCrypt2BytesMinHL + MetaDataTypeBytesTotal + MetaDataPayloadBytesMax
	MessageCrypt2BytesMax    = OpcodeKeyIDBytesTotal + MessageCrypt2BytesMaxHL
)

// WrappedKeyNewFromBase64 returns a pointer to WrappedKey filled with bytes from a given base64 string.
func WrappedKeyNewFromBase64(s string) *WrappedKey {
	wk := &WrappedKey{}
	_ = wk.FromBase64(s)
	return wk
}

// References:
//
//	- Official manuals:
//		https://openvpn.net/community-resources/openvpn-cryptographic-layer/
//		https://openvpn.net/community-resources/openvpn-protocol/
//		https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/
//		https://openvpn.net/faq/changed-hex-bytes-in-the-static-key-the-key-still-connects-to-a-remote-peer-using-the-original-key/
//
//	- OpenVPN codebase:
//		https://github.com/OpenVPN/openvpn/
//		https://github.com/OpenVPN/openvpn3/
//
//	- Third-party solutions:
//		https://github.com/corelight/zeek-openvpn/blob/master/src/openvpn-analyzer.pac
//		https://github.com/ntop/nDPI/blob/dev/src/lib/protocols/openvpn.c
//		https://github.com/yrutschle/sslh/blob/master/probe.c
//		https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-openvpn.c
