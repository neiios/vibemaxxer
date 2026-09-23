# vibemaxxer

Send **Claude Code, Codex, pi, OpenCode, and Cursor CLI** traffic through a VPN on another Linux machine. Go standard library only, one binary, no root, no SSH tunnel, no CA, no certificate management.

```text
Agent → vibemaxxer bridge (loopback) → TLS 1.3 across LAN → vibemaxxer serve (VPN host) → VPN → API
```

Both machines have a persistent Ed25519 identity. Each side pins the other's public-key fingerprint, so only your workstation can open tunnels and the bridge refuses anything but your VPN host. The agent's own HTTPS runs end to end inside that tunnel: LAN observers see traffic sizes and timing, not destinations, prompts, or credentials.

**vibemaxxer does not establish or enforce the VPN.** Outbound sockets follow the VPN host's routing. Configure the VPN, its DNS, and a kill switch separately.

## Setup

Build on both machines (see [Build](#build)), then:

### 1. Exchange fingerprints

```sh
vibemaxxer key
```

Run this on both machines. Each prints a 64-character fingerprint and creates the identity on first use. Get the workstation's fingerprint onto the VPN host and the host's onto the workstation. Fingerprints are public; paste them through any channel and compare against the screen they came from.

You can also skip the copy for the workstation's fingerprint: start `serve` without it, start the bridge, and the server logs the rejected identity with the exact `-client-key` flag to add. Compare it against the bridge's own startup line before adding it.

### 2. Start the VPN host

```sh
vibemaxxer serve -listen 192.168.1.50:8443 -client-key WORKSTATION_FINGERPRINT
```

`-listen` is required. Bind the LAN interface, not `0.0.0.0`, so the listener stays off the VPN tunnel interface. Repeat `-client-key` for each workstation. Removing one and restarting revokes it.

### 3. Start the bridge

```sh
vibemaxxer bridge -server 192.168.1.50:8443 -server-key HOST_FINGERPRINT
```

It listens on `127.0.0.1:8888`, verifies the server at startup, and logs whether the pin matched, the identity was accepted, or the server was unreachable. It never falls back to plaintext or a direct connection.

### 4. Run an agent

```sh
vibemaxxer run -- claude
```

`run` checks that the bridge is listening, sets `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, and their lowercase forms, and replaces itself with the command. Nothing else in your shell changes. Use `-bridge IP:PORT` if the bridge is not on the default address.

Verify the exit IP:

```sh
vibemaxxer run -- curl https://api.ipify.org
```

### Optional: block domains

```text
# blocked-domains.txt: domains and all their subdomains
telemetry.vendor.com
```

```sh
vibemaxxer bridge -server ... -server-key ... -blocklist ./blocked-domains.txt
```

The bridge answers `403` for a blocked CONNECT destination before contacting the VPN host, so the server never learns about it. Rules are case-insensitive, one ASCII/punycode domain per line, `#` comments allowed. `example.com` also blocks `api.example.com` but not `notexample.com`. IP-literal destinations are not subject to domain rules. The file is read once at startup.

## Commands

| Command | Purpose |
| --- | --- |
| `key` | Print this machine's fingerprint, creating the identity if needed |
| `serve` | CONNECT server on the VPN host; requires `-listen` and at least one `-client-key` |
| `bridge` | Loopback proxy on the workstation; requires `-server` and `-server-key` |
| `run` | Exec a command with proxy variables pointing at the bridge |

| Flag | Command | Default | Meaning |
| --- | --- | --- | --- |
| `-key` | all | `~/.config/vibemaxxer/identity.pem` | Identity file (`$XDG_CONFIG_HOME` honored) |
| `-listen` | serve | required | LAN `IP:PORT` |
| `-client-key` | serve | required | Allowed workstation fingerprint; repeatable |
| `-ports` | serve | `443` | Allowed destination ports, comma-separated |
| `-server` | bridge | required | VPN host `HOST:PORT` |
| `-server-key` | bridge | required | VPN host fingerprint |
| `-listen` | bridge | `127.0.0.1:8888` | Loopback `IP:PORT` for agents |
| `-blocklist` | bridge | none | Domain blocklist file |
| `-bridge` | run | `127.0.0.1:8888` | Bridge address to point agents at |

Fixed behavior: 10-second dial and header timeouts, 256 concurrent tunnels per process, and private, loopback, link-local, and CGNAT destinations are always refused. The server checks the resolved address right before connecting, so DNS rebinding cannot reach the VPN host's LAN.

## Client notes

vibemaxxer relays TCP bytes inside CONNECT and does not inspect them. HTTP/1.1, HTTP/2, gRPC, SSE, and WebSockets all work as long as the client sends them through the proxy. Start each agent with `vibemaxxer run -- COMMAND`. Keep existing credentials and API base URLs; the bridge is a forward proxy, not an API gateway.

- **Claude Code**: `vibemaxxer run -- claude`. If you use `claude setup-token`, export `CLAUDE_CODE_OAUTH_TOKEN` in the same shell. A fresh install may show "Select login method" despite a valid token; set `hasCompletedOnboarding` to `true` in `~/.claude.json` if you want to skip it.
- **Codex**: `vibemaxxer run -- codex`. Use a release whose WebSocket client honors proxy variables (0.154.0 or later). Sandboxed tools do not inherit network access from this.
- **pi**: `vibemaxxer run -- pi`. Provider-specific overrides can bypass the proxy; check pi's settings if a provider ignores it.
- **OpenCode**: `vibemaxxer run -- opencode`. Versions with a managed background service need the variables persisted with `opencode service set env` for `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy`, `NO_PROXY`, and `no_proxy`, then `opencode service start`. `run` prints nothing; copy the values from `vibemaxxer run -- env`.
- **Cursor CLI**: `vibemaxxer run -- agent`.

Verify each client, not just curl: make a small model request and watch the VPN host's `tunnel opened` log for the API destination. Then stop the bridge and confirm a fresh request fails rather than connecting directly. Then disconnect the VPN and confirm the request fails because of the host's kill switch.

## Security boundaries

- **Trust is the fingerprint exchange.** Whoever controls both fingerprints controls the tunnel. Compare them against the screen they were printed on.
- **The bridge is open to every local process.** Anything on the workstation can use the loopback port, including a compromised dependency or a misbehaving agent. The server's port and destination policy limits what such a process can reach through your VPN host.
- **Identity files are credentials.** `identity.pem` is mode 0600 in a mode 0700 directory. Do not copy one machine's identity to another. To replace a lost or leaked key, delete the file, run `key`, and update the other side's flag.
- **No TLS interception.** The VPN host sees destinations, not payloads. Agents still validate API certificates normally.
- **Logs hold metadata.** Destinations, peer addresses, fingerprints, and errors. Never prompts, credentials, or private keys.
- **Subprocesses can bypass proxies.** Browser logins, MCP servers, and shell commands spawned by agents need their own configuration or network enforcement.

## Build

```sh
nix build .            # ./result/bin/vibemaxxer
nix run . -- help
nix develop            # go, gopls, nixfmt
```

Or with Go 1.25 or newer:

```sh
CGO_ENABLED=0 go build -trimpath -o vibemaxxer .
```

Linux only. Copy the binary to the other machine, or build there.

### Background services

```sh
# VPN host
systemd-run --user --unit=vibemaxxer-server --property=Restart=on-failure \
  "$(readlink -f result)/bin/vibemaxxer" serve -listen 192.168.1.50:8443 -client-key WORKSTATION_FINGERPRINT

# Workstation
systemd-run --user --unit=vibemaxxer-bridge --property=Restart=on-failure \
  "$(readlink -f result)/bin/vibemaxxer" bridge -server 192.168.1.50:8443 -server-key HOST_FINGERPRINT
```

Fingerprints are public and can live in dotfiles. Keeping user services alive after logout may require lingering.

## Development

```sh
gofmt -l .
go vet ./...
go test -race -count=1 -timeout=60s ./...
```

Tests run entirely on loopback.
