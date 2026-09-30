package domain

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

type Rules map[string]bool

func normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

func validRule(name string) bool {
	if name == "" || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..") {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	return strings.IndexFunc(name, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.')
	}) < 0
}

func Load(path string) (Rules, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return scan(path, bufio.NewScanner(file))
}

func Parse(name, data string) (Rules, error) {
	return scan(name, bufio.NewScanner(strings.NewReader(data)))
}

func scan(name string, scanner *bufio.Scanner) (Rules, error) {
	list := make(Rules)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		rule := normalize(text)
		if !validRule(rule) {
			return nil, fmt.Errorf("%s:%d: %q is not a domain rule (write example.com to cover it and its subdomains; no leading dot, no IP literals)", name, line, text)
		}
		list[rule] = true
	}
	return list, scanner.Err()
}

func (list Rules) Match(host string) string {
	host = normalize(host)
	for host != "" {
		if list[host] {
			return host
		}
		_, host, _ = strings.Cut(host, ".")
	}
	return ""
}
