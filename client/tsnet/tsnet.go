//go:build tsnet
// +build tsnet

package tsnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/log"
	"tailscale.com/net/netmon"
	"tailscale.com/tsnet"
)

func init() {
	netmon.RegisterInterfaceGetter(safeAndroidInterfaces)
}

func safeAndroidInterfaces() ([]netmon.Interface, error) {
	// Parse network interfaces from /proc/net/dev instead of calling net.Interfaces()
	// and supply AltAddrs to completely prevent NetlinkRIB calls in iface.Addrs().
	ifnames := getIfNamesFromProc()
	out := make([]netmon.Interface, 0, len(ifnames))
	for i, name := range ifnames {
		flags := net.FlagUp
		if name == "lo" {
			flags |= net.FlagLoopback
		} else {
			flags |= net.FlagMulticast
		}
		iface := &net.Interface{
			Index: i + 1,
			Name:  name,
			Flags: flags,
		}

		var altAddrs []net.Addr
		if name == "lo" {
			altAddrs = []net.Addr{
				&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
				&net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
			}
		} else {
			altAddrs = []net.Addr{
				&net.IPNet{IP: net.ParseIP("192.168.1.100"), Mask: net.CIDRMask(24, 32)},
			}
		}

		out = append(out, netmon.Interface{
			Interface: iface,
			AltAddrs:  altAddrs,
		})
	}
	if len(out) == 0 {
		out = []netmon.Interface{
			{
				Interface: &net.Interface{Index: 1, Name: "lo", Flags: net.FlagUp | net.FlagLoopback},
				AltAddrs: []net.Addr{
					&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
				},
			},
			{
				Interface: &net.Interface{Index: 2, Name: "wlan0", Flags: net.FlagUp | net.FlagMulticast},
				AltAddrs: []net.Addr{
					&net.IPNet{IP: net.ParseIP("192.168.1.100"), Mask: net.CIDRMask(24, 32)},
				},
			},
		}
	}
	return out, nil
}

func getIfNamesFromProc() []string {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return nil
	}
	var names []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.Contains(fields[0], ":") {
			name := strings.TrimSpace(strings.Split(fields[0], ":")[0])
			if name != "" {
				names = append(names, name)
			}
		}
	}
	return names
}

var (
	ErrTsnetNotInitialized = errors.New("tsnet: server not initialized or not running")

	// CGNAT range: 100.64.0.0/10
	_, cgnatNet, _ = net.ParseCIDR("100.64.0.0/10")
	// Tailscale IPv6 ULA: fd7a:115c:a1e0::/48
	_, tsIPv6Net, _ = net.ParseCIDR("fd7a:115c:a1e0::/48")
)

// Config holds the configuration for tsnet.
type Config struct {
	Enable       bool     `json:"enable"`
	AuthKey      string   `json:"auth_key"`
	ControlURL   string   `json:"control_url"`
	StateDir     string   `json:"state_dir"`
	Hostname     string   `json:"hostname"`
	ExtraSubnets []string `json:"extra_subnets"`
}

type Manager struct {
	mu            sync.RWMutex
	cfg           Config
	srv           *tsnet.Server
	running       bool
	subnetNets    []*net.IPNet
	selfIPs       []string
	selfHostname  string
	lastStatus    time.Time
	statusMu      sync.RWMutex
	customSubnets []*net.IPNet
	router        *router.Router
}

var globalMgr = &Manager{}

// Configure updates the tsnet manager configuration.
func Configure(cfg Config) {
	globalMgr.mu.Lock()
	defer globalMgr.mu.Unlock()

	globalMgr.cfg = cfg
	globalMgr.customSubnets = nil

	for _, s := range cfg.ExtraSubnets {
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(s))
		if err == nil && ipnet != nil {
			globalMgr.customSubnets = append(globalMgr.customSubnets, ipnet)
		}
	}
}

// IsEnabled returns true if tsnet is configured and enabled.
func IsEnabled() bool {
	globalMgr.mu.RLock()
	defer globalMgr.mu.RUnlock()
	return globalMgr.cfg.Enable
}

// Start initializes and starts the tsnet node.
func Start(r ...*router.Router) (err error) {
	globalMgr.mu.Lock()
	defer globalMgr.mu.Unlock()

	if len(r) > 0 && r[0] != nil {
		globalMgr.router = r[0]
		// Add CGNAT 100.64.0.0/10 as direct CIDR and ts.net domain suffix
		globalMgr.router.AddDirectCIDR("100.64.0.0/10")
		globalMgr.router.AddDirectDomain("ts.net")
		for _, cidr := range globalMgr.customSubnets {
			globalMgr.router.AddDirectCIDR(cidr.String())
		}
	}

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("tsnet panic recovered: %v", r)
			log.Error("[TSNET] panic during start", "err", err)
		}
	}()

	if !globalMgr.cfg.Enable {
		return nil
	}
	if globalMgr.running {
		return nil
	}

	hostname := globalMgr.cfg.Hostname
	if hostname == "" {
		hostname = "easyss-client"
	}

	stateDir := globalMgr.cfg.StateDir
	if stateDir == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			stateDir = filepath.Join(home, ".easyss", "tsnet")
		} else {
			stateDir = "./tsnet-state"
		}
	}

	if err := os.MkdirAll(stateDir, 0700); err != nil {
		log.Error("[TSNET] failed to create state dir", "dir", stateDir, "err", err)
	}

	// Disable netlink, netns and syspolicy to prevent crash in non-root app sandboxes
	os.Setenv("HOME", stateDir)
	os.Setenv("TS_LOGS_DIR", stateDir)
	os.Setenv("TAILSCALE_LOGS_DIR", stateDir)
	os.Setenv("TS_DISABLE_NETLINK", "true")
	os.Setenv("TS_DISABLE_NETNS", "true")
	os.Setenv("TS_PERMIT_CERT_VIA_HTTP", "true")
	os.Setenv("TS_LOG_TARGET", "")
	os.Setenv("TSNET_FORCE_LOGIN", "1")

	srv := &tsnet.Server{
		Hostname:   hostname,
		Dir:        stateDir,
		AuthKey:    globalMgr.cfg.AuthKey,
		ControlURL: globalMgr.cfg.ControlURL,
		Logf:       func(format string, args ...any) {},
	}

	if err := srv.Start(); err != nil {
		return fmt.Errorf("tsnet start failed: %w", err)
	}

	globalMgr.srv = srv
	globalMgr.running = true
	log.Info("[TSNET] tsnet client node started successfully", "hostname", hostname)

	// Async update of Tailscale active subnet routes
	go globalMgr.pollRoutesLoop()

	return nil
}

// Close stops the tsnet server.
func Close() error {
	globalMgr.mu.Lock()
	defer globalMgr.mu.Unlock()

	if !globalMgr.running || globalMgr.srv == nil {
		return nil
	}

	err := globalMgr.srv.Close()
	globalMgr.srv = nil
	globalMgr.running = false
	log.Info("[TSNET] tsnet client node closed")
	return err
}

// Status returns a human-readable Tailscale status string read entirely from
// cached in-memory state — no network calls, safe to call from any thread.
func Status() string {
	globalMgr.mu.RLock()
	running := globalMgr.running
	enable := globalMgr.cfg.Enable
	globalMgr.mu.RUnlock()

	if !enable {
		return ""
	}
	if !running {
		return "Tailscale: connecting..."
	}

	globalMgr.statusMu.RLock()
	ips := globalMgr.selfIPs
	hostname := globalMgr.selfHostname
	subnets := globalMgr.subnetNets
	globalMgr.statusMu.RUnlock()

	var parts []string
	if len(ips) > 0 {
		parts = append(parts, "IP: "+strings.Join(ips, ", "))
	}
	if hostname != "" {
		parts = append(parts, "Host: "+hostname)
	}
	if len(subnets) > 0 {
		var routeStrs []string
		for _, n := range subnets {
			routeStrs = append(routeStrs, n.String())
		}
		parts = append(parts, "Routes: "+strings.Join(routeStrs, ", "))
	}

	if len(parts) == 0 {
		return "Tailscale: connected"
	}
	return "Tailscale: " + strings.Join(parts, " | ")
}

func (m *Manager) pollRoutesLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Initial fetch
	m.updateSubnetRoutes()

	count := 0
	for {
		globalMgr.mu.RLock()
		running := globalMgr.running
		globalMgr.mu.RUnlock()
		if !running {
			return
		}

		<-ticker.C
		m.updateSubnetRoutes()
		count++
		if count == 6 {
			// Switch to normal 30s interval after initial quick polling
			ticker.Reset(30 * time.Second)
		}
	}
}

func (m *Manager) updateSubnetRoutes() {
	m.mu.RLock()
	srv := m.srv
	m.mu.RUnlock()

	if srv == nil {
		return
	}

	lc, err := srv.LocalClient()
	if err != nil || lc == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	st, err := lc.Status(ctx)
	if err != nil || st == nil {
		return
	}

	// If user has explicitly configured extra_subnets, skip auto-fetch —
	// the custom subnets are already registered in Start() and take priority.
	m.mu.RLock()
	hasCustomSubnets := len(m.customSubnets) > 0
	m.mu.RUnlock()

	// Cache self IP and hostname
	var selfIPs []string
	var selfHostname string
	if st.Self != nil {
		for _, ip := range st.TailscaleIPs {
			if ip.Is4() {
				selfIPs = append(selfIPs, ip.String())
			}
		}
		selfHostname = st.Self.HostName
	}

	var newNets []*net.IPNet
	routeMap := make(map[string]struct{})

	if !hasCustomSubnets {
		// Auto-fetch active PrimaryRoutes announced in Tailscale mesh
		for _, peer := range st.Peer {
			if peer.PrimaryRoutes != nil {
				for _, r := range peer.PrimaryRoutes.AsSlice() {
					if ipnet := prefixToIPNet(r); ipnet != nil {
						if _, ok := routeMap[ipnet.String()]; !ok {
							routeMap[ipnet.String()] = struct{}{}
							newNets = append(newNets, ipnet)
						}
					}
				}
			}
		}
	}

	m.statusMu.Lock()
	m.selfIPs = selfIPs
	m.selfHostname = selfHostname
	m.subnetNets = newNets
	m.lastStatus = time.Now()
	m.statusMu.Unlock()

	if m.router != nil && !hasCustomSubnets {
		for _, n := range newNets {
			m.router.AddDirectCIDR(n.String())
		}
	}

	var routeStrs []string
	for _, n := range newNets {
		routeStrs = append(routeStrs, n.String())
	}
	if hasCustomSubnets {
		log.Info("[TSNET] using user-configured extra_subnets, skipping auto-fetch")
	} else {
		log.Info("[TSNET] updated active primary subnet routes", "count", len(newNets), "routes", strings.Join(routeStrs, ", "))
	}
}

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	if !p.IsValid() || p.Bits() == 0 {
		// Ignore invalid or 0.0.0.0/0 and ::/0 exit node default routes
		return nil
	}
	_, ipnet, err := net.ParseCIDR(p.String())
	if err != nil {
		return nil
	}
	return ipnet
}

// IsTailscaleTarget checks whether a host (IP or domain) should be routed via Tailscale.
func IsTailscaleTarget(host string) bool {
	if !IsEnabled() {
		return false
	}

	// Remove port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// Domain suffix match (*.ts.net)
	if strings.HasSuffix(strings.ToLower(host), ".ts.net") {
		log.Info("[TSNET_MATCH] matched tailscale domain suffix", "host", host)
		return true
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	// Check Tailscale CGNAT IP (100.64.0.0/10)
	if cgnatNet != nil && cgnatNet.Contains(ip) {
		log.Info("[TSNET_MATCH] matched CGNAT IP", "ip", host)
		return true
	}

	// Check Tailscale IPv6 (fd7a:115c:a1e0::/48)
	if tsIPv6Net != nil && tsIPv6Net.Contains(ip) {
		log.Info("[TSNET_MATCH] matched Tailscale IPv6", "ip", host)
		return true
	}

	// Check custom configured subnets
	globalMgr.mu.RLock()
	customs := globalMgr.customSubnets
	globalMgr.mu.RUnlock()
	for _, cidr := range customs {
		if cidr.Contains(ip) {
			log.Info("[TSNET_MATCH] matched custom subnet route", "ip", host, "cidr", cidr.String())
			return true
		}
	}

	// Check active Subnet Routes announced in Tailscale mesh
	globalMgr.statusMu.RLock()
	subnets := globalMgr.subnetNets
	globalMgr.statusMu.RUnlock()
	for _, cidr := range subnets {
		if cidr.Contains(ip) {
			log.Info("[TSNET_MATCH] matched active tailscale subnet route", "ip", host, "cidr", cidr.String())
			return true
		}
	}

	log.Debug("[TSNET_NO_MATCH] target IP not matched in tailscale subnets", "ip", host)
	return false
}

// DialContext dials out via the local tsnet node.
func DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	globalMgr.mu.RLock()
	srv := globalMgr.srv
	running := globalMgr.running
	globalMgr.mu.RUnlock()

	if !running || srv == nil {
		return nil, ErrTsnetNotInitialized
	}

	log.Info("[TSNET] dialing target via tsnet", "network", network, "addr", addr)
	return srv.Dial(ctx, network, addr)
}
