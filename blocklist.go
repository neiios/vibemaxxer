package main

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// domainBlocklist is immutable after startup. A nil list disables filtering.
type domainBlocklist map[string]struct{}

func normalizeDomain(name string) (string, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if len(name) == 0 || len(name) > 253 {
		return "", fmt.Errorf("invalid domain %q", name)
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid domain %q", name)
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("invalid domain %q (use ASCII/punycode)", name)
			}
		}
	}
	return name, nil
}

func loadBlocklist(path string) (domainBlocklist, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("load blocklist: %w", err)
	}
	defer file.Close()
	list := make(domainBlocklist)
	scanner := bufio.NewScanner(file)
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		name, err := normalizeDomain(text)
		if _, ipErr := netip.ParseAddr(name); ipErr == nil {
			err = fmt.Errorf("IP addresses are not domain rules")
		}
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		list[name] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%s:%d: %w", path, line+1, err)
	}
	return list, nil
}

func (list domainBlocklist) match(host string) string {
	for {
		if _, ok := list[host]; ok {
			return host
		}
		_, parent, found := strings.Cut(host, ".")
		if !found {
			return ""
		}
		host = parent
	}
}
