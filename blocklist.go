package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// domainBlocklist matches a domain and all of its subdomains. A nil list
// matches nothing.
type domainBlocklist map[string]bool

func normalizeDomain(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

func validDomainRule(name string) bool {
	return name != "" && strings.IndexFunc(name, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.')
	}) < 0
}

// loadBlocklist reads one domain per line; blank lines and # comments are ignored.
func loadBlocklist(path string) (domainBlocklist, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	list := make(domainBlocklist)
	scanner := bufio.NewScanner(file)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		name := normalizeDomain(text)
		if !validDomainRule(name) {
			return nil, fmt.Errorf("%s:%d: %q is not a domain (use one ASCII/punycode domain per line)", path, line, text)
		}
		list[name] = true
	}
	return list, scanner.Err()
}

// match returns the rule that blocks host, or "".
func (list domainBlocklist) match(host string) string {
	host = normalizeDomain(host)
	for host != "" {
		if list[host] {
			return host
		}
		_, host, _ = strings.Cut(host, ".")
	}
	return ""
}
