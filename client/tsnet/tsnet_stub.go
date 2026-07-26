//go:build !tsnet
// +build !tsnet

package tsnet

import (
	"context"
	"errors"
	"net"
)

var ErrTsnetDisabled = errors.New("tsnet support not compiled: build with -tags tsnet to enable")

// Config holds the configuration for tsnet.
type Config struct {
	Enable       bool     `json:"enable"`
	AuthKey      string   `json:"auth_key"`
	ControlURL   string   `json:"control_url"`
	StateDir     string   `json:"state_dir"`
	Hostname     string   `json:"hostname"`
	ExtraSubnets []string `json:"extra_subnets"`
}

func IsEnabled() bool {
	return false
}

func Configure(cfg Config) {}

func Start() error {
	return nil
}

func Close() error {
	return nil
}

func IsTailscaleTarget(host string) bool {
	return false
}

func DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return nil, ErrTsnetDisabled
}

func Status() string {
	return ""
}

