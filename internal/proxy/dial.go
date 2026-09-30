package proxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"
)

var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

var errPrivateDestination = errors.New("private/local destination blocked")

func publicDestination(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsGlobalUnicast() && !addr.IsPrivate() && !addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast() && !sharedAddressSpace.Contains(addr)
}

func localPrefixes() ([]netip.Prefix, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var prefixes []netip.Prefix
	for _, addr := range addrs {
		prefix, err := netip.ParsePrefix(addr.String())
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

func (s *Server) allowed(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	if !publicDestination(addr) {
		return false
	}
	for _, prefix := range s.local {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

func (s *Server) dial(ctx context.Context, target string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	if !s.allowPrivate {
		dialer.ControlContext = func(_ context.Context, _, address string, _ syscall.RawConn) error {
			endpoint, err := netip.ParseAddrPort(address)
			if err != nil || !s.allowed(endpoint.Addr()) {
				return errPrivateDestination
			}
			return nil
		}
	}
	return dialer.DialContext(ctx, "tcp", target)
}
