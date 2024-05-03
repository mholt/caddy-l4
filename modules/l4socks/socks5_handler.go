package l4socks

import (
	"fmt"
	"net"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	"github.com/things-go/go-socks5"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Socks5Handler{})
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

func (Socks5Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.socks5",
		New: func() caddy.Module { return new(Socks5Handler) },
	}
}

func (h *Socks5Handler) Provision(ctx caddy.Context) error {
	rule := &socks5.PermitCommand{EnableConnect: false, EnableAssociate: false, EnableBind: false}
	if len(h.Commands) == 0 {
		rule.EnableConnect = true
		rule.EnableAssociate = true
		// BIND is currently not supported so we dont allow it by default
	} else {
		for _, c := range h.Commands {
			switch strings.ToUpper(c) {
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

	authMethods := []socks5.Authenticator{socks5.NoAuthAuthenticator{}}
	if len(h.Credentials) > 0 {
		authMethods = []socks5.Authenticator{
			socks5.UserPassAuthenticator{
				Credentials: socks5.StaticCredentials(h.Credentials),
			},
		}
	}

	h.server = socks5.NewServer(
		socks5.WithLogger(&socks5Logger{l: ctx.Logger(h)}),
		socks5.WithRule(rule),
		socks5.WithBindIP(net.ParseIP(h.BindIP)),
		socks5.WithAuthMethods(authMethods),
	)

	return nil
}

// Handle handles the SOCKSv5 connection.
func (h *Socks5Handler) Handle(cx *layer4.Connection, _ layer4.Handler) error {
	return h.server.ServeConn(cx)
}

func (h *Socks5Handler) IsTerminal() bool {
	return true
}

var (
	_ caddy.Provisioner  = (*Socks5Handler)(nil)
	_ layer4.NextHandler = (*Socks5Handler)(nil)
)

type socks5Logger struct {
	l *zap.Logger
}

func (s *socks5Logger) Errorf(format string, arg ...interface{}) {
	s.l.Error(fmt.Sprintf(format, arg...))
}

var _ socks5.Logger = (*socks5Logger)(nil)
