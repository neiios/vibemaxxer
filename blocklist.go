package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type domainRules map[string]bool

// Keep the blocklist name for existing callers.
type domainBlocklist = domainRules

func normalizeDomain(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

func validDomainRule(name string) bool {
	return name != "" && strings.IndexFunc(name, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.')
	}) < 0
}

func loadBlocklist(path string) (domainBlocklist, error) {
	return loadDomainRules(path)
}

func loadDomainRules(path string) (domainRules, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return scanDomainRules(path, bufio.NewScanner(file))
}

func parseDomainRules(path, data string) (domainRules, error) {
	return scanDomainRules(path, bufio.NewScanner(strings.NewReader(data)))
}

func scanDomainRules(path string, scanner *bufio.Scanner) (domainRules, error) {
	list := make(domainRules)
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

func (list domainRules) match(host string) string {
	host = normalizeDomain(host)
	for host != "" {
		if list[host] {
			return host
		}
		_, host, _ = strings.Cut(host, ".")
	}
	return ""
}
