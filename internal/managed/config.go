package managed

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"

	"github.com/neiios/vibemaxxer/internal/domain"
	"github.com/neiios/vibemaxxer/internal/identity"
	"github.com/neiios/vibemaxxer/internal/proxy"
)

type Config struct {
	Server, ServerKey, Listen     string
	Key                           []byte
	Block, Domains                domain.Rules
	BlockContents, DomainContents []byte
	Ports                         map[int]bool
	Grace                         time.Duration
	Executable                    string
}

func (c Config) Digest() string {
	data, _ := json.Marshal(c)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:20])
}

func Snapshot(server, pin, listen, keyPath, blockPath, domainPath, ports string, grace time.Duration) (Config, error) {
	c := Config{Server: server, Listen: listen, Grace: grace}
	if err := proxy.ValidEndpoint(server); err != nil {
		return c, fmt.Errorf("-server %w", err)
	}
	var err error
	if c.ServerKey, err = identity.ParseFingerprint(pin); err != nil {
		return c, fmt.Errorf("-server-key: %w", err)
	}
	bind, err := netip.ParseAddrPort(listen)
	if err != nil || !bind.Addr().IsLoopback() {
		return c, errors.New("-listen must be a loopback IP:PORT (port 0 selects a free port)")
	}
	if grace < 100*time.Millisecond || grace > time.Minute {
		return c, errors.New("-grace must be between 100ms and 1m")
	}
	if c.Ports, err = proxy.ParsePorts(ports); err != nil {
		return c, fmt.Errorf("-direct-ports: %w", err)
	}
	if c.Block, c.BlockContents, err = snapshotRules(blockPath); err != nil {
		return c, fmt.Errorf("-blocklist: %w", err)
	}
	if c.Domains, c.DomainContents, err = snapshotRules(domainPath); err != nil {
		return c, fmt.Errorf("-proxy-domains: %w", err)
	}
	id, err := identity.Load(keyPath)
	if err != nil {
		return c, err
	}
	c.Key = id.Key()
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		return c, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return c, err
	}
	c.Executable = hex.EncodeToString(h.Sum(nil))
	return c, nil
}

func snapshotRules(path string) (domain.Rules, []byte, error) {
	if path == "" {
		return nil, nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	rules, err := domain.Parse(path, string(data))
	return rules, data, err
}
