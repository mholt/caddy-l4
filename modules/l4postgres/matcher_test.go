package l4postgres

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Unexpected error: %s\n", err)
	}
}

func buildStartupMessage(version uint32, params map[string]string) []byte {
	var payload bytes.Buffer

	// Write protocol version
	binary.Write(&payload, binary.BigEndian, version)

	// Write parameters (key\0value\0)
	for k, v := range params {
		payload.WriteString(k)
		payload.WriteByte(0) // Null terminator for key
		payload.WriteString(v)
		payload.WriteByte(0) // Null terminator for value
	}

	payload.WriteByte(0) // Final terminator

	payloadBytes := payload.Bytes()
	payloadLen := len(payloadBytes)
	totalLen := uint32(payloadLen + lenFieldSize)

	var message bytes.Buffer
	binary.Write(&message, binary.BigEndian, totalLen)
	message.Write(payloadBytes)

	return message.Bytes()
}

func buildSSLRequest() []byte {
	var message bytes.Buffer
	totalLen := uint32(8) // 4 bytes length, 4 bytes code
	payloadCode := uint32(sslRequestCode)

	binary.Write(&message, binary.BigEndian, totalLen)    // Message Length (8)
	binary.Write(&message, binary.BigEndian, payloadCode) // SSLRequest Code

	return message.Bytes()
}

func buildCancelRequest(pid, secretKey uint32) []byte {
	var message bytes.Buffer
	totalLen := uint32(16) // 4 bytes length, 4 bytes code, 4 bytes pid, 4 bytes key

	binary.Write(&message, binary.BigEndian, totalLen)                  // Message Length (16)
	binary.Write(&message, binary.BigEndian, uint32(cancelRequestCode)) // CancelRequest Code
	binary.Write(&message, binary.BigEndian, pid)                       // PID
	binary.Write(&message, binary.BigEndian, secretKey)                 // Secret Key

	return message.Bytes()
}

func TestMatchPostgres(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantMatch bool
	}{
		// Valid Message Tests
		{
			name:      "Valid SSLRequest",
			input:     buildSSLRequest(),
			wantMatch: true,
		},
		{
			name:      "Valid CancelRequest",
			input:     buildCancelRequest(12345, 67890),
			wantMatch: true,
		},
		{
			name:      "Valid StartupMessage V3 (No Params)",
			input:     buildStartupMessage(0x00030000, nil), // Protocol 3.0
			wantMatch: true,
		},
		{
			name: "Valid StartupMessage V3 (With Params)",
			input: buildStartupMessage(0x00030000, map[string]string{
				"user":     "testuser",
				"database": "testdb",
			}),
			wantMatch: true,
		},
		{
			name: "Valid StartupMessage V3 (One Param)",
			input: buildStartupMessage(0x00030000, map[string]string{
				"client_encoding": "UTF8",
			}),
			wantMatch: true,
		},
		{
			name: "Valid StartupMessage V3 (Multiple Params)",
			input: buildStartupMessage(0x00030000, map[string]string{
				"user":             "postgres",
				"database":         "mydb",
				"client_encoding":  "UTF8",
				"application_name": "pgadmin",
				"search_path":      "public,private",
			}),
			wantMatch: true,
		},
		{
			name: "Valid StartupMessage V3 (Empty Values)",
			input: buildStartupMessage(0x00030000, map[string]string{
				"user":     "",
				"database": "",
			}),
			wantMatch: true,
		},
		{
			name: "Valid StartupMessage MinorVersion V3.1",
			input: buildStartupMessage(0x00030001, map[string]string{
				"user": "testuser",
			}),
			wantMatch: true,
		},

		// Edge Case Startup Message Tests
		{
			name: "Valid StartupMessage - Unicode Characters",
			input: buildStartupMessage(0x00030000, map[string]string{
				"user":     "测试用户",
				"database": "数据库",
			}),
			wantMatch: true,
		},
		{
			name: "Valid StartupMessage - Special Characters",
			input: buildStartupMessage(0x00030000, map[string]string{
				"user":     "test!@#$%^&*()",
				"database": "db-with_special.chars",
			}),
			wantMatch: true,
		},

		// Non-Matches - Message Length Issues
		{
			name:      "Too Short (EOF reading length)",
			input:     []byte{0x00, 0x00}, // Only 2 bytes, less than length header size
			wantMatch: false,
		},
		{
			name:      "Invalid Message Length (Too Small)",
			input:     []byte{0x00, 0x00, 0x00, 0x07}, // Length 7, minimum is 8
			wantMatch: false,
		},
		{
			name:      "Zero Payload Length (Invalid)",
			input:     []byte{0x00, 0x00, 0x00, 0x04}, // Length 4 -> Payload 0
			wantMatch: false,
		},
		{
			name: "Too Short (EOF reading payload)",
			// Declares length 10, but only provides 8 bytes total (4 length + 4 payload)
			input:     append([]byte{0x00, 0x00, 0x00, 0x0A}, buildStartupMessage(0x00030000, nil)[4:8]...),
			wantMatch: false,
		},
		{
			name: "Declared Payload Too Large",
			input: func() []byte {
				largePayloadLen := uint32(maxPayloadSize + 1)
				totalLen := largePayloadLen + lenFieldSize
				header := make([]byte, 4)
				binary.BigEndian.PutUint32(header, totalLen)
				return header
			}(),
			wantMatch: false,
		},

		// Non-Matches - Protocol Version Issues
		{
			name: "Unsupported Protocol Version (V2)",
			input: buildStartupMessage(0x00020000, map[string]string{
				"user": "test",
			}),
			wantMatch: false,
		},
		{
			name: "Invalid Protocol Version (V0)",
			input: buildStartupMessage(0x00000000, map[string]string{
				"user": "test",
			}),
			wantMatch: false,
		},
		{
			name: "Invalid Protocol Version (V1)",
			input: buildStartupMessage(0x00010000, map[string]string{
				"user": "test",
			}),
			wantMatch: false,
		},
		{
			name: "Future Protocol Version (V4)",
			input: buildStartupMessage(0x00040000, map[string]string{
				"user": "test",
			}),
			wantMatch: false, // Should fail as our matcher only accepts V3
		},

		// Non-Matches - Special Message Type Issues
		{
			name:      "SSLRequest Code but Wrong Length",
			input:     append(buildSSLRequest()[:4], []byte{0x01, 0x02, 0x03, 0x04, 0x05}...), // Length OK, Code OK, Payload length incorrect
			wantMatch: false,
		},
		{
			name: "CancelRequest Code but Wrong Length",
			input: func() []byte {
				var msg bytes.Buffer
				binary.Write(&msg, binary.BigEndian, uint32(12)) // Length 12 (too short)
				binary.Write(&msg, binary.BigEndian, uint32(cancelRequestCode))
				binary.Write(&msg, binary.BigEndian, uint32(123)) // PID
				// Missing secret key
				return msg.Bytes()
			}(),
			wantMatch: false,
		},

		// Non-Matches - Malformed Startup Message Structure
		{
			name:      "StartupMessage Payload Too Short",
			input:     []byte{0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00}, // No final null byte
			wantMatch: false,
		},
		{
			name: "Malformed Startup (Missing Final Null)",
			input: func() []byte {
				msg := buildStartupMessage(0x00030000, map[string]string{"user": "test"})
				return msg[:len(msg)-1] // Remove last byte (the final null)
			}(),
			wantMatch: false,
		},
		{
			name: "Malformed Startup (Missing Value Null)",
			input: func() []byte {
				// Len, Ver, "user\0", "test" (NO NULL) , final \0
				payload := []byte{
					0x00, 0x03, 0x00, 0x00, // Version
					'u', 's', 'e', 'r', 0x00, // Key + Null
					't', 'e', 's', 't', // Value (Missing Null!)
					0x00, // Final Null
				}
				totalLen := uint32(len(payload) + lenFieldSize)
				header := make([]byte, 4)
				binary.BigEndian.PutUint32(header, totalLen)
				return append(header, payload...)
			}(),
			wantMatch: false,
		},
		{
			name: "Malformed Startup (Missing Key Null)",
			input: func() []byte {
				// Len, Ver, "user" (NO NULL), "test\0", final \0
				payload := []byte{
					0x00, 0x03, 0x00, 0x00, // Version
					'u', 's', 'e', 'r', // Key (Missing Null!)
					't', 'e', 's', 't', 0x00, // Value + Null
					0x00, // Final Null
				}
				totalLen := uint32(len(payload) + lenFieldSize)
				header := make([]byte, 4)
				binary.BigEndian.PutUint32(header, totalLen)
				return append(header, payload...)
			}(),
			wantMatch: false,
		},
		{
			name: "Malformed Startup (No Parameters at All)",
			input: func() []byte {
				// Len, Ver, (NO PARAMS, NO FINAL NULL)
				payload := []byte{
					0x00, 0x03, 0x00, 0x00, // Version only
				}
				totalLen := uint32(len(payload) + lenFieldSize)
				header := make([]byte, 4)
				binary.BigEndian.PutUint32(header, totalLen)
				return append(header, payload...)
			}(),
			wantMatch: false,
		},
		{
			name: "Malformed Startup (Double Null for Key)",
			input: func() []byte {
				// Len, Ver, "\0\0"
				payload := []byte{
					0x00, 0x03, 0x00, 0x00, // Version
					0x00, 0x00, // Two nulls (invalid)
				}
				totalLen := uint32(len(payload) + lenFieldSize)
				header := make([]byte, 4)
				binary.BigEndian.PutUint32(header, totalLen)
				return append(header, payload...)
			}(),
			wantMatch: false,
		},

		// Non-Matches - Other Protocols
		{
			name:      "Other Protocol (HTTP GET)",
			input:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			wantMatch: false,
		},
		{
			name:      "Other Protocol (HTTP POST)",
			input:     []byte("POST /api/data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\n1234567890"),
			wantMatch: false,
		},
		{
			name:      "Other Protocol (SSH)",
			input:     []byte("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"),
			wantMatch: false,
		},
		{
			name:      "Other Protocol (MySQL)",
			input:     []byte{10, 0, 0, 0, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // MySQL handshake
			wantMatch: false,
		},
		{
			name:      "Other Protocol (TLS ClientHello)",
			input:     []byte{0x16, 0x03, 0x01, 0x00, 0xfc, 0x01, 0x00, 0x00, 0xf8, 0x03, 0x03}, // TLS 1.0 ClientHello start
			wantMatch: false,
		},
		{
			name:      "Other Protocol (Random Bytes)",
			input:     []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE},
			wantMatch: false,
		},
		{
			name:      "Other Protocol (All Zeros)",
			input:     bytes.Repeat([]byte{0x00}, 20),
			wantMatch: false,
		},
	}

	_, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := &MatchPostgres{}

			in, out := net.Pipe()
			defer func() {
				_, _ = io.Copy(io.Discard, out)
				_ = out.Close()
			}()

			cx := layer4.WrapConnection(out, []byte{}, zap.NewNop())

			go func() {
				_, err := in.Write(tc.input)
				assertNoError(t, err)
				_ = in.Close()
			}()

			matched, err := m.Match(cx)
			assertNoError(t, err)

			if matched != tc.wantMatch {
				if tc.wantMatch {
					t.Fatalf("test %d: matcher did not match | %s\n", i, tc.name)
				} else {
					t.Fatalf("test %d: matcher should not match | %s\n", i, tc.name)
				}
			}
		})
	}
}
