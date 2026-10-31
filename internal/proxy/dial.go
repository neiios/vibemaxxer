package proxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"
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
	allowPrivate bool
	local        []netip.Prefix
}

func (g guard) allowed(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	if !addr.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range alwaysRefused {
		if prefix.Contains(addr) {
			return false
		}
	}
	if g.allowPrivate {
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

func Dialer(allowPrivate bool) (DialFunc, error) {
	g := guard{allowPrivate: allowPrivate}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		prefix, err := netip.ParsePrefix(addr.String())
		if err != nil {
			return nil, err
		}
		g.local = append(g.local, prefix.Masked())
	}
	dialer := net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 30 * time.Second,
		ControlContext: func(_ context.Context, _, address string, _ syscall.RawConn) error {
			endpoint, err := netip.ParseAddrPort(address)
			if err != nil || !g.allowed(endpoint.Addr()) {
				return errProhibited
			}
			return nil
		},
	}
	return dialer.DialContext, nil
}
