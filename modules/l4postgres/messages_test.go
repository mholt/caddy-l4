package l4postgres

import "testing"

func TestIsSSLRequest(t *testing.T) {
	if !isSSLRequest(80877103) {
		t.Fatalf("magic SSL number is not recognised")
	}
}

func TestIsSupported(t *testing.T) {
	if isSupported(1234) {
		t.Fatalf("protocol version should require > v3.0")
	}
	if !isSupported(196608) { // v3.0
		t.Fatalf("protocol version should require > v3.0")
	}
}
