package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFingerprint(t *testing.T) {
	id, err := Load(filepath.Join(t.TempDir(), "identity.pem"))
	if err != nil {
		t.Fatal(err)
	}
	fp := id.Fingerprint()
	if len(fp) != 64 {
		t.Fatalf("fingerprint length %d", len(fp))
	}
	got, err := ParseFingerprint("  " + strings.ToUpper(fp) + "\n")
	if err != nil || got != fp {
		t.Fatalf("uppercase fingerprint: %q, %v", got, err)
	}
	for _, bad := range []string{"", "abc", fp[:63], fp + "0", strings.Repeat("zz", 32)} {
		if _, err := ParseFingerprint(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestIdentityPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "identity.pem")
	first, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint() != second.Fingerprint() {
		t.Fatal("identity changed between loads")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("key mode %o", info.Mode().Perm())
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

func TestFromKeyRejectsMalformedKeys(t *testing.T) {
	if _, err := FromKey([]byte("other")); err == nil {
		t.Fatal("accepted short key")
	}
	if _, err := FromKey(nil); err == nil {
		t.Fatal("accepted nil key")
	}
}

func TestConcurrentIdentityPublication(t *testing.T) {
	key := filepath.Join(t.TempDir(), "new.pem")
	type result struct {
		id  *Identity
		err error
	}
	results := make(chan result, 32)
	for i := 0; i < 32; i++ {
		go func() { id, err := Load(key); results <- result{id, err} }()
	}
	var fingerprint string
	for i := 0; i < 32; i++ {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		if fingerprint == "" {
			fingerprint = result.id.Fingerprint()
		}
		if result.id.Fingerprint() != fingerprint {
			t.Fatal("first sessions used different identities")
		}
	}
}
