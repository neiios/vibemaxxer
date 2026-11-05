# vibemaxxer

A tiny HTTP proxy that decides what to do with each hostname: block it, let it
through, or send it out through another machine.

It's good for keeping coding agents from phoning home, or for making their API
traffic leave from a machine you choose. It works with anything that respects
`HTTPS_PROXY`.

```text
app -> vibemaxxer client -> internet                          (direct)
                         -> 403                               (block)
                         -> vibemaxxer server -> internet     (proxy)
```

It's one static Go binary with no dependencies outside the standard library.
TLS is never intercepted. Filtering works on hostnames only, never on paths
or content.

## Quick start

Write a `client.rules`:

```text
block .ads.example
block .telemetry.example
```

Start the proxy and point something at it:

```sh
vibemaxxer client --rules client.rules

export HTTPS_PROXY=http://127.0.0.1:8080 HTTP_PROXY=http://127.0.0.1:8080
curl https://example.com
```

Blocked hosts get a 403 and everything else goes straight out. That's the
whole thing.

## Routing through another machine

Add `proxy` rules and tell the client where the server is. Traffic for those
hosts then leaves from the server's network instead of yours. The server
checks its own allowlist and doesn't trust the client's decisions. If the
server can't be reached, those requests fail rather than going out directly.

There are two ways to connect the client and server:

- **[LAN](docs/lan.md)**: built-in mutual TLS with pinned keys, for two
  machines that can reach each other directly.
- **[SSH](docs/remote.md)**: an SSH forward, optionally over frp for NAT
  traversal, for machines on different networks.

## Docs

- [Rules](docs/rules.md): syntax, matching, and what gets refused
- [vibemaxxer run](docs/run.md): start the proxy on demand around a command
- [LAN setup](docs/lan.md)
- [SSH and frp setup](docs/remote.md)

The [examples](examples/) run Claude Code through vibemaxxer in each mode:
[local](examples/claude-local/), [LAN](examples/claude-lan/), and
[remote](examples/claude-remote/).

## Caveats

This isn't a sandbox. Apps that ignore proxy variables, or hosts listed in
`NO_PROXY`, skip vibemaxxer entirely. Any local process can use the proxy.

## Building

```sh
nix build                  # or:
CGO_ENABLED=0 go build -trimpath -o vibemaxxer ./cmd/vibemaxxer
```

`go test -race ./...` runs the unit tests. `nix flake check` also boots a
three-VM end-to-end test (needs KVM) that covers every mode, including NAT
traversal and failure cases.

## License

[GPL-3.0-or-later](LICENSE)
