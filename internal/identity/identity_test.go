package identity

import (
	"os"
	"path/filepath"
	"testing"
)

// The first `run` on a machine may race with other first runs (several agents
// started at once); all of them must end up with the same private, persistent key.
func TestIdentityFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "identity.pem")
	type result struct {
		id  *Identity
		err error
	}
	results := make(chan result, 32)
	for i := 0; i < 32; i++ {
		go func() { id, err := Load(path); results <- result{id, err} }()
	}
	var fingerprint string
	for i := 0; i < 32; i++ {
		r := <-results
		if r.err != nil {
			t.Fatal(r.err)
		}
		if fingerprint == "" {
			fingerprint = r.id.Fingerprint()
		}
		if r.id.Fingerprint() != fingerprint {
			t.Fatal("concurrent first loads produced different identities")
		}
	}
	if len(fingerprint) != 64 {
		t.Fatalf("fingerprint %q", fingerprint)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("key mode %o", info.Mode().Perm())
	}
	again, err := Load(path)
	if err != nil || again.Fingerprint() != fingerprint {
		t.Fatalf("identity changed between loads: %v", err)
	}
	if err := os.WriteFile(path, []byte("garbage"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("corrupt key accepted")
	}
	if _, err := Load(""); err == nil {
		t.Fatal("empty path accepted")
	}
}
