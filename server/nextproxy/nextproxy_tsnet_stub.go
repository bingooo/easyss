//go:build !tsnet
// +build !tsnet

package nextproxy

import (
	"context"
	"fmt"
	"net"
	"net/url"
)

// initTSNET returns a dialer function for tsnet-based dialing.
// This is the default stub used when the real tsnet implementation
// is not compiled in. It returns a dialer that always errors with
// an informative message.
func initTSNET(u *url.URL, enableUDP bool) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, fmt.Errorf("tsnet support not compiled: build with -tags tsnet to enable")
	}, nil
}
