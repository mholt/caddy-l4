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

package l4proxy

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// TestUnmarshalCaddyfileErrors covers the error branches of the proxy handler's
// Caddyfile parsing. These paths cannot be exercised by the caddyfile_adapt
// integration tests, which only assert that a valid Caddyfile adapts to an
// expected JSON document (there is no "expect adapt to fail" variant); the
// happy paths are already covered there.
func TestUnmarshalCaddyfileErrors(t *testing.T) {
	cases := map[string]string{
		"duplicate health_interval": "proxy localhost:1 {\n\thealth_interval 5s\n\thealth_interval 6s\n}",
		"bad health_interval":       "proxy localhost:1 {\n\thealth_interval nope\n}",
		"bad health_port":           "proxy localhost:1 {\n\thealth_port nope\n}",
		"bad max_fails":             "proxy localhost:1 {\n\tmax_fails nope\n}",
		"duplicate lb_try_duration": "proxy localhost:1 {\n\tlb_try_duration 1s\n\tlb_try_duration 2s\n}",
		"unknown lb_policy":         "proxy localhost:1 {\n\tlb_policy does_not_exist\n}",
		"unknown directive":         "proxy localhost:1 {\n\tnope 1\n}",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			h := new(Handler)
			if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
				t.Fatalf("expected an error for %q, got nil", name)
			}
		})
	}
}

func TestUnmarshalCaddyfileTransparentUpstream(t *testing.T) {
	u := new(Upstream)
	input := "upstream 127.0.0.1:8080 {\n\ttransparent\n}"
	if err := u.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
		t.Fatalf("unmarshal transparent upstream: %v", err)
	}
	if !u.Transparent {
		t.Fatal("transparent = false, want true")
	}
	if len(u.Dial) != 1 || u.Dial[0] != "127.0.0.1:8080" {
		t.Fatalf("dial = %v, want [127.0.0.1:8080]", u.Dial)
	}
}

func TestUnmarshalCaddyfileTransparentErrors(t *testing.T) {
	for name, input := range map[string]string{
		"arguments": "upstream 127.0.0.1:8080 {\n\ttransparent yes\n}",
		"duplicate": "upstream 127.0.0.1:8080 {\n\ttransparent\n\ttransparent\n}",
	} {
		t.Run(name, func(t *testing.T) {
			u := new(Upstream)
			if err := u.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
				t.Fatalf("expected error for %s transparent option", name)
			}
		})
	}
}
