package policy

import (
	"errors"
	"strings"
	"testing"
)

func TestHost(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"Example.COM":   "example.com",
		"example.com.":  "example.com",
		"xn--bcher-kva": "xn--bcher-kva",
		"a_b.example":   "a_b.example",
	} {
		if got, err := Host(in); err != nil || got != want {
			t.Errorf("Host(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"127.0.0.1", "::1", "fe80::1%eth0", "1.2.3", "example.123"} {
		if _, err := Host(in); !errors.Is(err, ErrIPLiteral) {
			t.Errorf("Host(%q) = %v; want ErrIPLiteral", in, err)
		}
	}
	for _, in := range []string{"", ".", "a..b", ".example.com", "bücher.example", "a b", "ex*mple.com", strings.Repeat("a", 64) + ".com"} {
		if _, err := Host(in); err == nil || errors.Is(err, ErrIPLiteral) {
			t.Errorf("Host(%q) = %v; want invalid hostname", in, err)
		}
	}
}

func TestPort(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"", "0", "65536", "+443", "0443", " 443", "443x", "-1"} {
		if _, err := Port(in); err == nil {
			t.Errorf("Port(%q) accepted", in)
		}
	}
	if port, err := Port("65535"); err != nil || port != 65535 {
		t.Errorf("Port(65535) = %d, %v", port, err)
	}
}

func TestClientDecisions(t *testing.T) {
	t.Parallel()
	p, err := Parse("client.rules", `
# comment
proxy  .example.com
proxy  exact.test     # trailing comment
block  ads.example.com
block  .Tracker.Example.
`, Client)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		host   string
		action Action
		rule   string
	}{
		{"example.com", Proxy, "client.rules:3"},
		{"a.b.example.com", Proxy, "client.rules:3"},
		{"badexample.com", Direct, "default"},
		{"exact.test", Proxy, "client.rules:4"},
		{"sub.exact.test", Direct, "default"},
		{"ads.example.com", Block, "client.rules:5"},
		{"x.ads.example.com", Proxy, "client.rules:3"},
		{"tracker.example", Block, "client.rules:6"},
		{"deep.tracker.example", Block, "client.rules:6"},
	} {
		if action, rule := p.Decide(c.host, 443); action != c.action || rule != c.rule {
			t.Errorf("%s: %v %s; want %v %s", c.host, action, rule, c.action, c.rule)
		}
	}
}

func TestServerDecisions(t *testing.T) {
	t.Parallel()
	p, err := Parse("server.rules", `
allow .example.com 80,443
allow api.test
deny  secret.example.com
allow *  8443
`, Server)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		host   string
		port   int
		action Action
	}{
		{"example.com", 80, Direct},
		{"www.example.com", 443, Direct},
		{"www.example.com", 22, Block},
		{"secret.example.com", 443, Block},
		{"secret.example.com", 8443, Block},
		{"api.test", 443, Direct},
		{"api.test", 80, Block},
		{"anything.else", 8443, Direct},
		{"anything.else", 443, Block},
	} {
		if action, rule := p.Decide(c.host, c.port); action != c.action {
			t.Errorf("%s:%d: %v (%s); want %v", c.host, c.port, action, rule, c.action)
		}
	}
	if _, rule := p.Decide("nothing.test", 443); rule != "default" {
		t.Errorf("unmatched rule = %q", rule)
	}
}

func TestRequiresUpstream(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		mode  Mode
		rules string
		want  bool
	}{
		{Client, "", false},
		{Client, "block .ads.example", false},
		{Client, "proxy .remote.example", true},
		{Client, "block *\nproxy .remote.example", true},
		{Server, "allow .remote.example\ndeny secret.remote.example", false},
	} {
		p, err := Parse("rules", tc.rules, tc.mode)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.RequiresUpstream(); got != tc.want {
			t.Errorf("mode %d, %q: RequiresUpstream() = %v, want %v", tc.mode, tc.rules, got, tc.want)
		}
	}
}

func TestParseRejects(t *testing.T) {
	t.Parallel()
	for mode, lines := range map[Mode][]string{
		Client: {"allow example.com", "proxy", "proxy example.com 443", "proxy 10.0.0.1", "proxy *.example.com", "block ..example.com", "direct example.com"},
		Server: {"proxy example.com", "allow example.com 0", "allow example.com 443,", "deny example.com 443", "allow example.com 443 80", "allow ::1"},
	} {
		for _, line := range lines {
			if _, err := Parse("rules", line, mode); err == nil || !strings.HasPrefix(err.Error(), "rules:1: ") {
				t.Errorf("mode %d: %q: %v", mode, line, err)
			}
		}
	}
}
