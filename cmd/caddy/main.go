package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// plug in Caddy modules here
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/mholt/caddy-l4/layer4"
	_ "github.com/mholt/caddy-l4/modules/l4echo"
	_ "github.com/mholt/caddy-l4/modules/l4proxy"
	_ "github.com/mholt/caddy-l4/modules/l4tls"
)

func main() {
	caddycmd.Main()
}
