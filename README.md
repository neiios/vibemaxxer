# vibemaxxer

Route coding-agent traffic (Claude Code, Codex, pi, OpenCode, Cursor CLI) through a VPN on another Linux machine. One static Go binary, standard library only.

```text
agent → bridge (127.0.0.1) → TLS 1.3 over LAN → serve (VPN host) → VPN → API
```

Each machine has an Ed25519 identity. The server admits listed workstation fingerprints; the bridge pins the server's. The agent's own HTTPS is tunneled unchanged, so the LAN sees traffic volume and timing, nothing else.

vibemaxxer does not set up or enforce the VPN. Configure routing, DNS, and a kill switch on the host.

## Setup

On both machines:

```sh
vibemaxxer key
```

Prints the machine's fingerprint and creates `~/.config/vibemaxxer/identity.pem` on first run. Swap the two fingerprints by any channel. They are public.

VPN host:

```sh
vibemaxxer serve -listen 192.168.1.50:8443 -client-key WORKSTATION_FP
```

Bind the LAN address, not `0.0.0.0`, so the listener stays off the tunnel interface. Repeat `-client-key` per workstation. Remove one and restart to revoke it. If a workstation connects before its key is listed, the server logs the fingerprint with the exact flag to add.

Workstation:

```sh
vibemaxxer bridge -server 192.168.1.50:8443 -server-key HOST_FP
vibemaxxer run -- claude
```

The bridge listens on `127.0.0.1:8888` and checks the server at startup. The log says whether the pin matched, the identity was accepted, or the server was unreachable. `run` sets `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` and their lowercase forms, then execs the command.

Check the exit IP:

```sh
vibemaxxer run -- curl https://api.ipify.org
```

### Blocklist

```sh
vibemaxxer bridge -server ... -server-key ... -blocklist blocked-domains.txt
```

One domain per line, `#` comments allowed. A rule covers its subdomains. Blocked CONNECTs get `403` from the bridge without contacting the server. IP literals are not matched. The file is read at startup.

### Selective routing

```sh
vibemaxxer bridge -server ... -server-key ... -proxy-domains proxy-domains.txt
```

The file uses the same format as the blocklist (one ASCII/punycode domain per line, including subdomains, case-insensitive, `#` comments). Matching CONNECT destinations go through the server; everything else connects directly from the workstation through the local bridge. IP literals use the direct route. DNS resolution happens on the server for server routes and locally for direct routes.

Omitting `-proxy-domains` preserves proxy-all behavior. An empty file routes everything directly; invalid or unreadable files fail startup. Files are read at startup. The blocklist takes precedence over both routes. Server failures never cause matching domains to fall back to direct connections.

Direct routes allow only port 443 by default; use `-direct-ports 443,8443` to change this. They retain the private/local destination protections, timeouts, and shared bridge connection limit. The server's `-ports` setting independently controls server routes. Logs identify `route=direct` or `route=server`.

Applications still use the local bridge for both routes; this does not add support for plain HTTP requests (only CONNECT is supported). Existing `NO_PROXY` entries are preserved by `run` and can bypass the bridge and its routing/blocklist rules. With selective routing, stopping the server should break matching destinations while direct destinations remain available.

## Reference

| Command | Purpose |
| --- | --- |
| `key` | Print this machine's fingerprint |
| `serve` | CONNECT server on the VPN host |
| `bridge` | Loopback proxy on the workstation |
| `run` | Exec a command with proxy variables set |

| Flag | Command | Default | Meaning |
| --- | --- | --- | --- |
| `-key` | all | `~/.config/vibemaxxer/identity.pem` | Identity file |
| `-listen` | serve | required | LAN `IP:PORT` |
| `-client-key` | serve | required | Allowed workstation fingerprint, repeatable |
| `-ports` | serve | `443` | Allowed destination ports |
| `-server` | bridge | required | VPN host `HOST:PORT` |
| `-server-key` | bridge | required | VPN host fingerprint |
| `-listen` | bridge | `127.0.0.1:8888` | Loopback `IP:PORT` |
| `-blocklist` | bridge | none | Domain blocklist file |
| `-proxy-domains` | bridge | none (proxy all) | Route only these domains through the server |
| `-direct-ports` | bridge | `443` | Allowed destination ports for direct routes |
| `-bridge` | run | `127.0.0.1:8888` | Bridge address |

Fixed: 10-second dial and header timeouts, 256 tunnels per process. Private, loopback, link-local, and CGNAT destinations are refused after DNS resolution, so a tunnel cannot reach the VPN host's LAN.

## Clients

- **Claude Code**: `vibemaxxer run -- claude`. With `claude setup-token`, export `CLAUDE_CODE_OAUTH_TOKEN` in the same shell. A fresh install may show the login picker despite a valid token; set `hasCompletedOnboarding` to `true` in `~/.claude.json`.
- **Codex**: 0.154.0 or later. Earlier WebSocket clients ignore proxy variables.
- **pi**: provider-specific settings can bypass the proxy.
- **OpenCode**: the managed service needs `opencode service set env` for `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` and their lowercase forms, then `opencode service start`.
- **Cursor CLI**: `vibemaxxer run -- agent`.

To confirm a client is proxied, make a model request and watch for `tunnel opened` in the server log. Stop the bridge and the same request must fail.

## Security

- Any local process can use the bridge. The server's port and destination rules bound what a compromised one can reach through your VPN.
- `identity.pem` is a credential. To replace one, delete it, run `key`, and update the other side's flag.
- No TLS interception. The host sees destinations, not payloads. Logs contain destinations, peer addresses, fingerprints, and errors.
- Agent subprocesses such as browsers, MCP servers, and shells are not covered.

## Build

```sh
nix build .      # ./result/bin/vibemaxxer
nix develop
```

Or with Go 1.25 or newer:

```sh
CGO_ENABLED=0 go build -trimpath -o vibemaxxer .
```

Linux only.

Background services:

```sh
systemd-run --user --unit=vibemaxxer-server --property=Restart=on-failure \
  vibemaxxer serve -listen 192.168.1.50:8443 -client-key WORKSTATION_FP

systemd-run --user --unit=vibemaxxer-bridge --property=Restart=on-failure \
  vibemaxxer bridge -server 192.168.1.50:8443 -server-key HOST_FP
```

## Development

```sh
gofmt -l .
go vet ./...
go test -race -count=1 -timeout=60s ./...
```
