package policy

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
)

type Mode int

const (
	Client Mode = iota
	Server
)

type Action int

const (
	Direct Action = iota
	Proxy
	Block
)

func (a Action) String() string {
	return [...]string{"direct", "proxy", "block"}[a]
}

var ErrIPLiteral = errors.New("IP literal destinations are not allowed; use a hostname")

type rule struct {
	action  Action
	domain  string
	subtree bool
	ports   []int
	id      string
}

type Policy struct {
	mode  Mode
	rules []rule
}

func Load(path string, mode Mode) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(path, string(data), mode)
}

func Parse(name, data string, mode Mode) (*Policy, error) {
	p := &Policy{mode: mode}
	scanner := bufio.NewScanner(strings.NewReader(data))
	for line := 1; scanner.Scan(); line++ {
		text, _, _ := strings.Cut(scanner.Text(), "#")
		fields := strings.Fields(text)
		if len(fields) == 0 {
			continue
		}
		r, err := parseRule(mode, fields)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", name, line, err)
		}
		r.id = name + ":" + strconv.Itoa(line)
		p.rules = append(p.rules, r)
	}
	return p, scanner.Err()
}

var syntax = [...]struct {
	actions map[string]Action
	usage   string
}{
	Client: {map[string]Action{"block": Block, "proxy": Proxy}, "block DOMAIN | proxy DOMAIN"},
	Server: {map[string]Action{"deny": Block, "allow": Direct}, "deny DOMAIN | allow DOMAIN [PORT,...]"},
}

func parseRule(mode Mode, fields []string) (rule, error) {
	action, ok := syntax[mode].actions[fields[0]]
	withPorts := mode == Server && action == Direct
	if !ok || len(fields) < 2 || len(fields) > 3 || len(fields) == 3 && !withPorts {
		return rule{}, fmt.Errorf("expected %s", syntax[mode].usage)
	}
	r := rule{action: action}
	switch domain := fields[1]; {
	case domain == "*":
		r.subtree = true
	case strings.HasPrefix(domain, "*."):
		return rule{}, fmt.Errorf("write %q to match a domain and its subdomains", domain[1:])
	default:
		r.subtree = strings.HasPrefix(domain, ".")
		name, err := Host(strings.TrimPrefix(domain, "."))
		if err != nil {
			return rule{}, fmt.Errorf("domain %q: %w", domain, err)
		}
		r.domain = name
	}
	if withPorts {
		list := "443"
		if len(fields) == 3 {
			list = fields[2]
		}
		for _, text := range strings.Split(list, ",") {
			port, err := Port(text)
			if err != nil {
				return rule{}, err
			}
			r.ports = append(r.ports, port)
		}
	}
	return r, nil
}

func Host(name string) (string, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if _, err := netip.ParseAddr(name); err == nil {
		return "", ErrIPLiteral
	}
	if name == "" || len(name) > 253 {
		return "", errors.New("invalid hostname length")
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return "", errors.New("invalid hostname label")
		}
		if strings.IndexFunc(label, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_')
		}) >= 0 {
			return "", errors.New("hostname must be ASCII letters, digits, '-' or '_' (use punycode for international names)")
		}
	}
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return "", ErrIPLiteral
	}
	return name, nil
}

func Port(text string) (int, error) {
	port, err := strconv.Atoi(text)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != text {
		return 0, fmt.Errorf("invalid port %q", text)
	}
	return port, nil
}

func (r rule) matches(host string) bool {
	if r.domain == "" {
		return true
	}
	return host == r.domain || r.subtree && strings.HasSuffix(host, "."+r.domain)
}

func (p *Policy) Decide(host string, port int) (Action, string) {
	match := -1
	for i, r := range p.rules {
		if !r.matches(host) {
			continue
		}
		if r.action == Block {
			return Block, r.id
		}
		if match < 0 && (r.ports == nil || slices.Contains(r.ports, port)) {
			match = i
		}
	}
	if match >= 0 {
		return p.rules[match].action, p.rules[match].id
	}
	if p.mode == Server {
		return Block, "default"
	}
	return Direct, "default"
}
