package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "blocklist.txt")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadBlocklist(t *testing.T) {
	list, err := loadBlocklist(writeFile(t, "# comment\n\n  Example.COM. \ntelemetry.vendor.com\nexample.com\nxn--bcher-kva.example\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 || !list["example.com"] || !list["telemetry.vendor.com"] || !list["xn--bcher-kva.example"] {
		t.Fatalf("list %v", list)
	}
	if list, err := loadBlocklist(""); err != nil || list != nil {
		t.Fatalf("empty path: %v, %v", list, err)
	}
	if _, err := loadBlocklist(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
	for _, bad := range []string{"https://example.com", "example.com:443", "*.example.com", "example.com # inline", "bücher.example", "*",
		".example.com", "example..com", "example.com..", "1.2.3.4"} {
		_, err := loadBlocklist(writeFile(t, "ok.example\n"+bad+"\n"))
		if err == nil || !strings.Contains(err.Error(), ":2:") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestBlocklistMatch(t *testing.T) {
	list := domainBlocklist{"example.com": true}
	for host, want := range map[string]string{
		"example.com": "example.com", "API.Example.com.": "example.com", "a.b.example.com": "example.com",
		"notexample.com": "", "example.com.other.net": "", "com": "", "": "",
	} {
		if got := list.match(host); got != want {
			t.Errorf("%q: %q, want %q", host, got, want)
		}
	}
	if domainBlocklist(nil).match("example.com") != "" {
		t.Fatal("nil list matched")
	}
}
