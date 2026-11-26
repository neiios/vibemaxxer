# vibemaxxer

vibemaxxer is a small HTTP proxy that looks at the hostname of each connection
and either blocks it, lets it through, or sends it out through another machine
you control.

It's meant for coding agents like Claude Code and Codex. With it you can stop
them from sending telemetry, and make their API traffic leave from a machine
you choose. Anything that honors `HTTPS_PROXY` and `HTTP_PROXY` works with it.

vibemaxxer never decrypts TLS, and rules only ever match hostnames and ports,
not paths or content.

## Quick start

Write a `client.rules` file:

```text
block .ads.example
block .telemetry.example
```

Start the proxy:

```sh
vibemaxxer client --rules client.rules
```

Then, in another terminal, set the proxy variables and run something through
it:

```sh
export HTTPS_PROXY=http://127.0.0.1:9878 HTTP_PROXY=http://127.0.0.1:9878
curl https://example.com
```

Blocked hosts get a 403 and everything else connects directly, including
services on your own machine like a dev server or a local MCP server.
[Rules](docs/rules.md) has the full syntax.

If you only want the proxy around one program, skip the two terminals:

```sh
vibemaxxer run --rules client.rules curl https://example.com
```

[vibemaxxer run](docs/run.md) starts a proxy for that command alone and stops
it when the command exits. With `--direct-shells` only the program itself is
proxied, and the shell commands it runs connect directly.

## Routing through another machine

Add `proxy` rules for the hosts you want to reroute, and tell the client where
the server is. Traffic for those hosts then leaves from the server's network
instead of yours.

The server has its own `allow` rules and doesn't trust the client, so a
compromised process on your machine can only reach what the server allows. If
the server is unreachable, proxied requests fail. They never quietly fall back
to a direct connection.

There are two ways to connect the two:

- If the machines can reach each other directly, use the built-in mutual TLS
  with pinned keys. See [LAN setup](docs/lan.md).
- If they're on different networks, use an SSH forward, optionally through
  frp to get past NAT. See [SSH and frp setup](docs/remote.md).

The [Claude Code example](examples/claude/) runs Claude Code through
vibemaxxer in each mode: local, LAN and remote.

## Caveats

vibemaxxer isn't a sandbox. A program that ignores the proxy variables
bypasses it, and so does anything in `NO_PROXY`. `vibemaxxer run` removes
`NO_PROXY`, but anything written in Go and most browsers still connect to your
own machine directly, so `localhost` rules don't apply to them. The proxy also doesn't authenticate
local clients, so any process on the machine can use it.

## Building

```sh
nix build                  # or:
CGO_ENABLED=0 go build -trimpath -o vibemaxxer ./cmd/vibemaxxer
```

`go test -race ./...` runs the unit tests. `nix flake check` also runs an
end-to-end test across three VMs, which needs KVM.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
