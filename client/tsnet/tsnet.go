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

	"github.com/nange/easyss/v3/log"
	"tailscale.com/tsnet"
)

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
	mu           sync.RWMutex
	cfg          Config
	srv          *tsnet.Server
	running      bool
	subnetNets   []*net.IPNet
	lastStatus   time.Time
	statusMu     sync.RWMutex
	customSubnets []*net.IPNet
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
func Start() error {
	globalMgr.mu.Lock()
	defer globalMgr.mu.Unlock()

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

	srv := &tsnet.Server{
		Hostname:   hostname,
		Dir:        stateDir,
		AuthKey:    globalMgr.cfg.AuthKey,
		ControlURL: globalMgr.cfg.ControlURL,
		Logf: func(format string, args ...any) {
			log.Debug(fmt.Sprintf("[TSNET] "+format, args...))
		},
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

func (m *Manager) pollRoutesLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Initial fetch
	m.updateSubnetRoutes()

	for {
		globalMgr.mu.RLock()
		running := globalMgr.running
		globalMgr.mu.RUnlock()
		if !running {
			return
		}

		<-ticker.C
		m.updateSubnetRoutes()
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

	var newNets []*net.IPNet
	// Parse peer and route status if available
	for _, peer := range st.Peer {
		if peer.PrimaryRoutes != nil {
			for _, r := range peer.PrimaryRoutes.AsSlice() {
				if ipnet := prefixToIPNet(r); ipnet != nil {
					newNets = append(newNets, ipnet)
				}
			}
		}
	}

	m.statusMu.Lock()
	m.subnetNets = newNets
	m.lastStatus = time.Now()
	m.statusMu.Unlock()
}

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	if !p.IsValid() {
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
		return true
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	// Check Tailscale CGNAT IP (100.64.0.0/10)
	if cgnatNet != nil && cgnatNet.Contains(ip) {
		return true
	}

	// Check Tailscale IPv6 (fd7a:115c:a1e0::/48)
	if tsIPv6Net != nil && tsIPv6Net.Contains(ip) {
		return true
	}

	// Check custom configured subnets
	globalMgr.mu.RLock()
	customs := globalMgr.customSubnets
	globalMgr.mu.RUnlock()
	for _, cidr := range customs {
		if cidr.Contains(ip) {
			log.Debug("[TSNET] matched custom subnet route", "ip", ip.String(), "cidr", cidr.String())
			return true
		}
	}

	// Check active Subnet Routes announced in Tailscale mesh
	globalMgr.statusMu.RLock()
	subnets := globalMgr.subnetNets
	globalMgr.statusMu.RUnlock()
	for _, cidr := range subnets {
		if cidr.Contains(ip) {
			log.Debug("[TSNET] matched active tailscale subnet route", "ip", ip.String(), "cidr", cidr.String())
			return true
		}
	}

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
