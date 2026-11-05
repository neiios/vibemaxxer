package cli

import (
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/neiios/vibemaxxer/internal/identity"
)

func TestLANStartup(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.DiscardHandler)
	dir := t.TempDir()
	key := filepath.Join(dir, "identity.pem")
	id, err := identity.Load(key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for _, mode := range []string{"client", "server"} {
		rules := filepath.Join(dir, mode+".rules")
		text := "proxy .remote.test\n"
		options := []string{"--server", "192.0.2.1:8443", "--server-key", strings.ToUpper(id.Fingerprint())}
		if mode == "server" {
			text = "allow .remote.test\n"
			options = []string{"--tls", "--client-key", id.Fingerprint(), "--client-key", id.Fingerprint()}
		}
		if err := os.WriteFile(rules, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		args := append([]string{mode, "--key", key, "--rules", rules, "--listen", listener.Addr().String()}, options...)
		if err := Run(logger, args); !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatalf("valid LAN configuration did not reach listen: %v", err)
		}
	}
}

func TestLANFlagPolicy(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	key := filepath.Join(dir, "must-not-be-created.pem")
	clientRules, serverRules := filepath.Join(dir, "client.rules"), filepath.Join(dir, "server.rules")
	for path, text := range map[string]string{clientRules: "proxy *\n", serverRules: "allow *\n"} {
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	pin := strings.Repeat("ab", 32)
	for _, tc := range []struct {
		mode string
		opts []string
	}{
		{"client", []string{"--server", "192.0.2.1:8443"}},
		{"client", []string{"--server-key", pin}},
		{"client", []string{"--server", "192.0.2.1:8443", "--server-key", "bad"}},
		{"client", []string{"--server", "192.0.2.1:8443", "--server-key", pin, "--upstream", "127.0.0.1:18080"}},
		{"client", []string{"--server", "192.0.2.1", "--server-key", pin}},
		{"client", []string{"--server", ":8443", "--server-key", pin}},
		{"client", []string{"--server", "192.0.2.1:0", "--server-key", pin}},
		{"client", []string{"--server", "0.0.0.0:8443", "--server-key", pin}},
		{"client", []string{"--server", "192.0.2.1:8443", "--server-key", pin, "--listen", "192.0.2.2:8080"}},
		{"client", []string{"--key", key}},
		{"server", []string{"--tls"}},
		{"server", []string{"--client-key", pin}},
		{"server", []string{"--tls", "--client-key", "bad"}},
		{"server", []string{"--tls", "--client-key", pin, "--listen", "0.0.0.0:8443"}},
		{"server", []string{"--tls", "--client-key", pin, "--listen", "[::]:8443"}},
		{"server", []string{"--key", key}},
	} {
		rules := clientRules
		if tc.mode == "server" {
			rules = serverRules
		}
		args := append([]string{tc.mode, "--rules", rules}, tc.opts...)
		if err := Run(slog.New(slog.DiscardHandler), args); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
	if _, err := os.Stat(key); !os.IsNotExist(err) {
		t.Fatal("invalid options created an identity")
	}
}

func TestLANListen(t *testing.T) {
	t.Parallel()
	for _, address := range []string{"192.0.2.1:8443", "192.168.1.50:8443", "127.0.0.1:8443", "[fd00::1]:8443"} {
		if err := lanListen(address); err != nil {
			t.Errorf("%s: %v", address, err)
		}
	}
	for _, address := range []string{"0.0.0.0:8443", "[::]:8443", "[::ffff:0.0.0.0]:8443", "224.0.0.1:8443", "localhost:8443", "192.168.1.50:0"} {
		if err := lanListen(address); err == nil {
			t.Errorf("accepted %s", address)
		}
	}
}
