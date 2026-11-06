package l4close

import (
	"net"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

// TestHandle verifies that Handle actually closes the underlying connection.
func TestHandle(t *testing.T) {
	in, out := net.Pipe()
	defer func() { _ = in.Close() }()

	cx := layer4.WrapConnection(out, []byte{}, zap.NewNop())

	h := new(HandleClose)
	if err := h.Handle(cx, nil); err != nil {
		t.Fatalf("Handle returned an unexpected error: %s", err)
	}

	// After the handler runs the connection must be closed, so any further
	// I/O on it should fail rather than block or succeed.
	if _, err := cx.Write([]byte("x")); err == nil {
		t.Fatal("expected Write to fail on a closed connection, got nil error")
	}
}

// TestUnmarshalCaddyfile covers the happy path and the error branches of the
// close handler's Caddyfile parsing. The error branches cannot be exercised by
// the caddyfile_adapt integration tests, which only assert that a valid
// Caddyfile adapts to an expected JSON document (there is no "expect adapt to
// fail" variant).
func TestUnmarshalCaddyfile(t *testing.T) {
	valid := map[string]string{
		"bare directive": "close",
	}
	for name, input := range valid {
		t.Run(name, func(t *testing.T) {
			h := new(HandleClose)
			if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
				t.Fatalf("expected no error for %q, got: %s", name, err)
			}
		})
	}

	invalid := map[string]string{
		"same-line argument": "close arg",
		"block not allowed":  "close {\n\tfoo\n}",
	}
	for name, input := range invalid {
		t.Run(name, func(t *testing.T) {
			h := new(HandleClose)
			if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
				t.Fatalf("expected an error for %q, got nil", name)
			}
		})
	}
}
