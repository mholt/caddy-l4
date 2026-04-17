package l4socks

import (
	"fmt"
	"net"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/things-go/go-socks5"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&Socks5Handler{})
}

// Socks5Handler is a connection handler that terminates SOCKSv5 connection.
type Socks5Handler struct {
	// Controls which socks5 methods are allowed. Possible values CONNECT, ASSOCIATE, BIND. Default: ["CONNECT", "ASSOCIATE"].
	Commands []string `json:"commands,omitempty"`
	// IP address used for bind during BIND or UDP ASSOCIATE.
	BindIP string `json:"bind_ip,omitempty"`
	// Map of username:password to active authentication. Default: no authentication.
	Credentials map[string]string `json:"credentials,omitempty"`

	server *socks5.Server
}

func (*Socks5Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.socks5",
		New: func() caddy.Module { return new(Socks5Handler) },
	}
}

func (h *Socks5Handler) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()

	rule := &socks5.PermitCommand{EnableConnect: false, EnableAssociate: false, EnableBind: false}
	if len(h.Commands) == 0 {
		rule.EnableConnect = true
		rule.EnableAssociate = true
		// BIND is currently not supported, so we don't allow it by default
	} else {
		for _, c := range h.Commands {
			switch strings.ToUpper(repl.ReplaceAll(c, "")) {
			case "CONNECT":
				rule.EnableConnect = true
			case "ASSOCIATE":
				rule.EnableAssociate = true
			case "BIND":
				rule.EnableBind = true
			default:
				return fmt.Errorf("unknown command \"%s\" has to be one of [\"CONNECT\", \"ASSOCIATE\", \"BIND\"]", c)
			}
		}
	}

	credentials := make(map[string]string, len(h.Credentials))
	for k, v := range h.Credentials {
		k, v = repl.ReplaceAll(k, ""), repl.ReplaceAll(v, "")
		if len(k) > 0 {
			credentials[k] = v
		}
	}

	authMethods := []socks5.Authenticator{socks5.NoAuthAuthenticator{}}
	if len(h.Credentials) > 0 {
		authMethods = []socks5.Authenticator{
			socks5.UserPassAuthenticator{
				Credentials: socks5.StaticCredentials(credentials),
			},
		}
	}

	h.server = socks5.NewServer(
		socks5.WithLogger(&socks5Logger{l: ctx.Logger(h)}),
		socks5.WithRule(rule),
		socks5.WithBindIP(net.ParseIP(caddy.NewReplacer().ReplaceAll(h.BindIP, ""))),
		socks5.WithAuthMethods(authMethods),
	)

	return nil
}

// Handle handles the SOCKSv5 connection.
func (h *Socks5Handler) Handle(cx *layer4.Connection, _ layer4.Handler) error {
	return h.server.ServeConn(cx)
}

// UnmarshalCaddyfile sets up the Socks5Handler from Caddyfile tokens. Syntax:
//
//	socks5 {
//		bind_ip <address>
//		commands <values...>
//		credentials <username> <password> [<username> <password>]
//	}
//
// Note: multiple commands and credentials options are supported, but bind_ip option can only be provided once.
// Only plain text passwords are currently supported.
func (h *Socks5Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// No same-line options are supported
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	var hasBindIP bool
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		switch optionName {
		case "bind_ip":
			if hasBindIP {
				return d.Errf("duplicate %s option '%s'", wrapper, optionName)
			}
			if d.CountRemainingArgs() != 1 {
				return d.ArgErr()
			}
			_, h.BindIP, hasBindIP = d.NextArg(), d.Val(), true
		case "commands":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			h.Commands = append(h.Commands, d.RemainingArgs()...)
		case "credentials":
			if d.CountRemainingArgs() == 0 || d.CountRemainingArgs()%2 != 0 {
				return d.ArgErr()
			}
			if h.Credentials == nil {
				h.Credentials = make(map[string]string)
			}
			for d.NextArg() {
				username := d.Val()
				if d.NextArg() {
					h.Credentials[username] = d.Val()
				}
			}
		default:
			return d.ArgErr()
		}

		// No nested blocks are supported
		if d.NextBlock(nesting + 1) {
			return d.Errf("malformed %s option '%s': blocks are not supported", wrapper, optionName)
		}
	}

	return nil
}

var (
	_ caddy.Provisioner     = (*Socks5Handler)(nil)
	_ caddyfile.Unmarshaler = (*Socks5Handler)(nil)
	_ layer4.NextHandler    = (*Socks5Handler)(nil)
)

type socks5Logger struct {
	l *zap.Logger
}

func (s *socks5Logger) Errorf(format string, arg ...any) {
	s.l.Error(fmt.Sprintf(format, arg...))
}

var _ socks5.Logger = (*socks5Logger)(nil)
