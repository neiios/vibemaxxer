package proxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"syscall"
	"time"

	"github.com/neiios/vibemaxxer/internal/policy"
)

type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

var errProhibited = errors.New("destination address prohibited")

var (
	alwaysRefused = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("fd00:ec2::/32"),
	}
	sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")
)

type guard struct {
	own   []netip.Addr
	local []netip.Prefix
}

func (g guard) allowed(addr netip.Addr, lan bool) bool {
	addr = addr.Unmap().WithZone("")
	if !addr.IsGlobalUnicast() || slices.Contains(g.own, addr) {
		return false
	}
	for _, prefix := range alwaysRefused {
		if prefix.Contains(addr) {
			return false
		}
	}
	if lan {
		return true
	}
	if addr.IsPrivate() || sharedAddressSpace.Contains(addr) {
		return false
	}
	for _, prefix := range g.local {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

func interfaces() (guard, error) {
	var g guard
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return g, err
	}
	for _, addr := range addrs {
		prefix, err := netip.ParsePrefix(addr.String())
		if err != nil {
			return g, err
		}
		g.own = append(g.own, prefix.Addr().Unmap().WithZone(""))
		g.local = append(g.local, prefix.Masked())
	}
	return g, nil
}

func Dialer(client bool) DialFunc {
	dialer := net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 30 * time.Second,
		ControlContext: func(_ context.Context, _, address string, _ syscall.RawConn) error {
			endpoint, err := netip.ParseAddrPort(address)
			if err != nil {
				return errProhibited
			}
			g, err := interfaces()
			if err != nil || !g.allowed(endpoint.Addr(), client) {
				return errProhibited
			}
			return nil
		},
	}
	local := net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		name, port, _ := net.SplitHostPort(address)
		host, _ := policy.Host(name)
		switch {
		case host != policy.Loopback:
			return dialer.DialContext(ctx, network, address)
		case !client:
			return nil, errProhibited
		}
		if _, err := netip.ParseAddr(name); err == nil {
			return local.DialContext(ctx, network, address)
		}
		conn, err := local.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		if errors.Is(err, syscall.ECONNREFUSED) {
			if conn6, err6 := local.DialContext(ctx, network, net.JoinHostPort("::1", port)); err6 == nil {
				return conn6, nil
			}
		}
		return conn, err
	}
}
