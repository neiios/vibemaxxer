package identity

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestMutualTLS(t *testing.T) {
	t.Parallel()
	serverID, err := Load(filepath.Join(t.TempDir(), "server.pem"))
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := Load(filepath.Join(t.TempDir(), "client.pem"))
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := Load(filepath.Join(t.TempDir(), "stranger.pem"))
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.TLS.Version != tls.VersionTLS13 {
			t.Error("connection is not TLS 1.3")
		}
		io.WriteString(w, "authenticated")
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = serverID.ServerTLS(map[string]bool{clientID.Fingerprint(): true})
	server.StartTLS()
	defer server.Close()
	for _, name := range []string{"trusted", "wrong-server", "unknown-client", "missing-client", "tls12"} {
		t.Run(name, func(t *testing.T) {
			config := clientID.ClientTLS(serverID.Fingerprint())
			switch name {
			case "wrong-server":
				config = clientID.ClientTLS(stranger.Fingerprint())
			case "unknown-client":
				config = stranger.ClientTLS(serverID.Fingerprint())
			case "missing-client":
				config.Certificates = nil
			case "tls12":
				config.MinVersion, config.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
			}
			transport := &http.Transport{TLSClientConfig: config}
			defer transport.CloseIdleConnections()
			before := requests.Load()
			resp, err := (&http.Client{Transport: transport}).Get(server.URL)
			if name != "trusted" {
				if resp != nil {
					resp.Body.Close()
				}
				if err == nil || requests.Load() != before {
					t.Fatalf("unauthenticated request reached server: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			data, err := io.ReadAll(resp.Body)
			if err != nil || string(data) != "authenticated" {
				t.Fatalf("response %q: %v", data, err)
			}
		})
	}
}

func TestParseFingerprint(t *testing.T) {
	t.Parallel()
	pin := strings.Repeat("ab", 32)
	if got, err := ParseFingerprint("  " + strings.ToUpper(pin) + "  "); err != nil || got != pin {
		t.Fatalf("normalization: %q %v", got, err)
	}
	for _, invalid := range []string{"", "abcd", strings.Repeat("z", 64), pin + "00"} {
		if _, err := ParseFingerprint(invalid); err == nil {
			t.Errorf("accepted %q", invalid)
		}
	}
}
