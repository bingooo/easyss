//go:build tsnet
// +build tsnet

package nextproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/nange/easyss/v3/log"
	"tailscale.com/tsnet"
)

// initTSNET initializes a tsnet Server and returns a DialContext function.
// URL query params supported:
//   - hostname: node hostname to use (required)
//   - authkey: preauth key to join headscale/tailscale
//   - login_server: custom control server URL (headscale)
//   - discover_primary: if "true", periodically try to discover this node's
//     advertised (primary) subnets via `tailscale status --json` and add them
//     to the next-proxy list.
func initTSNET(u *url.URL, enableUDP bool) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	vals := u.Query()
	hostname := vals.Get("hostname")
	if hostname == "" {
		return nil, fmt.Errorf("tsnet: hostname query param required")
	}

	authkey := vals.Get("authkey")
	loginServer := vals.Get("login_server")
	discover := strings.EqualFold(vals.Get("discover_primary"), "true")

	s := &tsnet.Server{Hostname: hostname}

	// If authkey or login_server provided, set environment variables used by
	// the underlying tailscale client. tsnet will pick up environment
	// variables such as TS_AUTHKEY and TS_LOGIN_SERVER when performing login.
	if authkey != "" {
		s.AuthKey = authkey
	}
	if loginServer != "" {
		s.ControlURL = loginServer
	}

	// start the server in background
	if err := s.Start(); err != nil {
		return nil, fmt.Errorf("tsnet start: %w", err)
	}

	// provide a cleanup on process exit via goroutine (server will be closed
	// when process exits; we don't expose Close here).

	// If discovery is enabled, periodically poll `tailscale status --json`
	// and add discovered subnet routes into the nextproxy list.
	if discover {
		go func() {
			for {
				updateAdvertisedRoutes()
				time.Sleep(60 * time.Second)
			}
		}()
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return s.Dial(ctx, network, addr)
	}, nil
}

// applyDiscoveredRoute will add the discovered route string to all
// registered tsnet NextProxy instances. The route can be an IP, CIDR or domain.
func applyDiscoveredRoute(route string) {
	if route == "" {
		return
	}
	tsnetRegistryMu.Lock()
	proxies := append([]*NextProxy(nil), tsnetRegistry...)
	tsnetRegistryMu.Unlock()

	for _, np := range proxies {
		if strings.Contains(route, "/") {
			np.AddCIDR(route)
		} else if util.IsIP(route) {
			np.AddIP(route)
		} else {
			np.AddDomain(route)
		}
	}
}

// updateAdvertisedRoutes attempts to run `tailscale status --json` and parse
// advertised routes; for each route found we call AddIP to make NextProxy
// route selection include it. This is best-effort and errors are logged.
func updateAdvertisedRoutes() {
	out, err := exec.Command("tailscale", "status", "--json").CombinedOutput()
	if err != nil {
		log.Debug("tsnet: tailscale status failed", "err", err)
		return
	}
	var js map[string]interface{}
	if err := json.Unmarshal(out, &js); err != nil {
		log.Debug("tsnet: parse status json failed", "err", err)
		return
	}
	// Only add routes advertised by Self (this node's primary/advertised subnets).
	if self, ok := js["Self"].(map[string]interface{}); ok {
		if routes, ok := self["RoutableIPs"].([]interface{}); ok {
			for _, r := range routes {
				if s, ok := r.(string); ok {
					addRouteCandidate(s)
				}
			}
		}
	}
}

func addRouteCandidate(s string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return
	}
	// if contains '/', treat as CIDR and add the network address
	if strings.Contains(s, "/") {
		// For simplicity add the CIDR string directly to NextProxy via a
		// global helper function. This requires that NextProxy package
		// exposes a way to register discovered routes; here we call a
		// package-level function AddDiscoveredRoute which in turn should
		// update appropriate NextProxy instances. We'll implement it
		// as a no-op if not set.
		addDiscoveredRoute(s)
	} else {
		addDiscoveredRoute(s)
	}
}

// addDiscoveredRoute is a hook point for discovered routes. By default
// it does nothing; consumer can set it in tests or runtime if needed.
var addDiscoveredRoute = applyDiscoveredRoute
