# vibemaxxer

Local HTTP/HTTPS filtering proxy with optional domain-based remote routing. Block advertising and telemetry domains, forward everything else directly, and optionally send selected domains through a remote machine. One static Go binary, standard library only.

```text
app ─▶ vibemaxxer client ──DIRECT──▶ internet (local egress)
       127.0.0.1:8080    ──BLOCK───▶ 403
                         ──PROXY───▶ optional upstream ─▶ vibemaxxer server ─▶ internet (remote egress)
```

Standalone filtering needs only `vibemaxxer client` and a rules file. No remote server, SSH, frp, or systemd is required. Both `client` and the optional `server` are standard HTTP/1.1 forward proxies: `CONNECT host:port` for HTTPS and absolute-form requests for plain HTTP. TLS stays end to end; nothing is intercepted. Filtering is by hostname, not URL path or page content.

## Quick start: local filtering

Create `client.rules`:

```text
block .ads.example
block .telemetry.example
# everything else: DIRECT
```

Run the proxy:

```sh
vibemaxxer client -rules client.rules
```

Point applications at it, for example in another shell:

```sh
export HTTPS_PROXY=http://127.0.0.1:8080 HTTP_PROXY=http://127.0.0.1:8080
export https_proxy=$HTTPS_PROXY http_proxy=$HTTP_PROXY
curl https://example.com
```

The domains above are placeholders; replace them with the domains you want to block. Applications must use the proxy for filtering to apply. `NO_PROXY` entries and applications that ignore proxy settings bypass vibemaxxer.

For automatic startup around a command, see [On-demand commands](#on-demand-commands). For remote routing, configure an explicit `-upstream` and add `proxy` rules as described below.

## Rules

Each mode reads its own native rules file. One rule per line, `#` starts a comment. There are no downloaded blocklists or automatic updates.

```text
# client.rules
block .ads.example          # never connect
block .telemetry.example
# Optional: these rules require -upstream
proxy .anthropic.com        # send through the server
proxy api.openai.com
# everything else: DIRECT
```

```text
# server.rules (optional remote server)
allow .anthropic.com        # ports default to 443
allow api.openai.com 443
allow .internal.example 80,443
deny  admin.internal.example
# everything else: denied
```

- `example.com` matches only that name. `.example.com` matches `example.com` and every subdomain, not `badexample.com`. `*` matches any hostname.
- `block`/`deny` always wins, regardless of order or specificity. Otherwise the first matching `proxy`/`allow` applies. Unmatched requests go DIRECT on the client and are denied on the server.
- `allow` checks the destination port as well. `proxy` rules ignore the port; the server decides.
- Names are matched case-insensitively, without a trailing dot. Only ASCII names are accepted; write international names in punycode (`xn--…`).
- IP-literal destinations are refused in both modes. Applications must use hostnames.
- Files are validated at startup; any error stops the process. A client rules file containing `proxy` rules requires an explicit `-upstream`, even if a `block` rule shadows them. Restart to apply changes. Existing tunnels keep running until they close.

When remote routing is enabled, the two policies are independent: the server never trusts the client's decision, and the client never falls back to DIRECT when the server or tunnel fails. Blocked domains are not resolved or contacted.

## Commands

```sh
vibemaxxer client -rules client.rules [-listen 127.0.0.1:8080] [-upstream 127.0.0.1:18080] [-allow-private]
vibemaxxer server -rules server.rules [-listen 127.0.0.1:8081] [-allow-private]
vibemaxxer run [--remote] [--] COMMAND [ARG...]
```

`-listen` and, when supplied, `-upstream` must be loopback IP addresses with a nonzero port. `-listen` defaults to the addresses shown above. **There is no default upstream**: omit `-upstream` for local filtering, or set it to the local end of the SSH forward to enable `proxy` rules. Merely supplying `-upstream` does not route unmatched traffic remotely.

**Existing remote deployments:** add `-upstream 127.0.0.1:18080` to the client command; the previous implicit upstream is no longer used.

Destinations are checked after DNS resolution, on the address actually dialed. Loopback, link-local (including `169.254.169.254`), multicast, `0.0.0.0/8` and the AWS IPv6 metadata range `fd00:ec2::/32` are always refused. Private, CGNAT and the host's own interface networks (read at startup) are refused unless `-allow-private` is set (for example, to reach private VPC services from the server).

### Responses

Refusals happen before a tunnel is established and carry an [RFC 9209](https://www.rfc-editor.org/rfc/rfc9209) `Proxy-Status` header naming the mode that refused:

| Status | `Proxy-Status` error | Cause |
| --- | --- | --- |
| 400 | `http_request_error` | Malformed request, authority, port, or non-`http` absolute URL |
| 403 | `http_request_denied` | Client `block`, server `deny`, or no server `allow` for host and port |
| 403 | `destination_ip_prohibited` | IP literal, or name resolved to a refused address |
| 502 | `dns_error`, `connection_refused`, `destination_unavailable` | Destination or upstream unreachable |
| 503 | `connection_limit_reached` | 128 requests and tunnels already active |
| 504 | `connection_timeout` | Destination (10 s) or upstream (30 s) timed out |

Once a tunnel is up, failures close it; nothing is replayed. Fixed limits: 32 KiB request headers, 10 s header read, 15 minutes of tunnel inactivity.

Each request logs one line with method, host, port, action, rule (`file:line` or `default`), status, duration and error. Paths, queries, headers and payloads are never logged.

## On-demand commands

`vibemaxxer run [--remote] [--] COMMAND [ARG...]` runs a command with the proxy variables set. It requires a systemd user manager and the units below, but ordinary `vibemaxxer client` use does not.

By default it starts only `vibemaxxer.target`, waits up to 20 s for the local client on `127.0.0.1:8080`, and runs the command in its own scope. No SSH forward or remote service is started or checked. Concurrent commands share the client; it stops when the last command and its subprocesses exit. If the client does not come up, the command is not started. Command arguments, terminal access, signals, and exit status are preserved. Use `--` to separate runner options from a command whose name begins with `-`. Only the vibemaxxer binary is needed; no separate runner script is required.

```ini
# ~/.config/systemd/user/vibemaxxer.target
[Unit]
StopWhenUnneeded=yes
Wants=vibemaxxer-client.service

# ~/.config/systemd/user/vibemaxxer-client.service
[Unit]
PartOf=vibemaxxer.target
StopWhenUnneeded=yes
[Service]
ExecStart=/usr/bin/vibemaxxer client -rules %h/.config/vibemaxxer/client.rules
Restart=on-failure
```

Adjust the binary paths, create your client rules file, run `systemctl --user daemon-reload`, and do not enable the units. Then:

```sh
vibemaxxer run curl https://example.com
vibemaxxer run claude
codex() { vibemaxxer run codex "$@"; }
```

For optional remote routing, configure the client with `-upstream` and install the [remote on-demand services](#remote-on-demand-services), then use `vibemaxxer run --remote COMMAND [ARG...]`. That mode additionally starts the remote target and waits for the SSH forward on `127.0.0.1:18080`. The flag starts infrastructure; it does not change the client's rules or flags.

## Optional remote deployment

Skip this section for standalone filtering. The example uses a public coordinator `frp.example.net`, a VM running sshd, and a home machine. Proxied names are never resolved at home; the server resolves them, so names that only exist on the VM work.

vibemaxxer decides per hostname and forwards HTTP. The remote connection is handled by existing tools:

| Concern | Tool |
| --- | --- |
| NAT traversal, rendezvous, no relay | [frp](https://gofrp.org) XTCP (`frps` on a public host, `frpc` on both ends) |
| Encryption, peer authentication, key management | OpenSSH local forward to a restricted account |
| Routing by domain, destination policy, egress | vibemaxxer `client` (home) and `server` (VM) |
| Process supervision | systemd or your service manager |

Pin your frp and OpenSSH versions and check the options against them.

### Coordinator

frps only does authentication and rendezvous. frpc does not verify the server's certificate unless told to, and its login proof can be replayed, so give frps a fixed certificate and pin it on both agents:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
  -subj /CN=frp.example.net -addext subjectAltName=DNS:frp.example.net \
  -addext extendedKeyUsage=serverAuth -keyout frps.key -out frps.crt
```

```toml
# frps.toml
bindPort = 7000
auth.token = "COORDINATOR_TOKEN"
transport.tls.force = true
transport.tls.certFile = "/etc/frp/frps.crt"
transport.tls.keyFile = "/etc/frp/frps.key"
```

Copy `frps.crt` (not the key) to both agents. Open only `bindPort` in the coordinator's firewall: a token holder can register ordinary TCP proxies, and frps binds whatever ports they ask for. Without `CAP_NET_BIND_SERVICE` it cannot take privileged ports, and frps needs no loopback traffic (systemd `IPAddressDeny=localhost`), which keeps a compromised frps away from services that listen only on localhost.

frp's STUN discovery needs a server that implements RFC 5780; Google's and Cloudflare's do not. `stun.nextcloud.com:3478` and frp's default, `stun.easyvoip.com:3478`, do. Set `natHoleStunServer` in both `frpc.toml` files, and check a server from each machine with `frpc nathole discover --nat_hole_stun_server HOST:PORT`.

### VM

```toml
# frpc.toml
serverAddr = "frp.example.net"
serverPort = 7000
auth.token = "COORDINATOR_TOKEN"
transport.tls.trustedCaFile = "/etc/vibemaxxer/frps.crt"
natHoleStunServer = "stun.nextcloud.com:3478"

[[proxies]]
name = "vm-ssh"
type = "xtcp"
secretKey = "XTCP_SECRET"
localIP = "127.0.0.1"
localPort = 22
```

Create a dedicated `proxy-tunnel` account, authorize the home key for it, and restrict it in `sshd_config` (check with `sshd -t` and `sshd -T -C user=proxy-tunnel` while keeping an admin session open):

```sshconfig
Match User proxy-tunnel
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    AllowTcpForwarding local
    PermitOpen 127.0.0.1:8081
    AllowStreamLocalForwarding no
    MaxSessions 0
    PermitTTY no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
```

`MaxSessions 0` forbids shells and subsystems; `PermitOpen` limits the account to the vibemaxxer server. Administrative accounts can change the policy, so keep them separate.

Run `vibemaxxer server -rules /etc/vibemaxxer/server.rules` and `frpc` under systemd.

### Home

```toml
# frpc.toml
serverAddr = "frp.example.net"
serverPort = 7000
auth.token = "COORDINATOR_TOKEN"
transport.tls.trustedCaFile = "/home/me/.config/vibemaxxer/frps.crt"
natHoleStunServer = "stun.nextcloud.com:3478"

[[visitors]]
name = "vm-ssh-visitor"
type = "xtcp"
serverName = "vm-ssh"
secretKey = "XTCP_SECRET"
bindAddr = "127.0.0.1"
bindPort = 2222
# No fallbackTo: if the direct path fails, PROXY fails.
```

Put the VM's real host key in `known_hosts` under the alias `vm-proxy` (from a channel you trust, never by accepting it over the loopback port), then:

```sshconfig
Host vm-proxy-tunnel
    HostName 127.0.0.1
    Port 2222
    User proxy-tunnel
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    HostKeyAlias vm-proxy
    StrictHostKeyChecking yes
    BatchMode yes
    LocalForward 127.0.0.1:18080 127.0.0.1:8081
    ExitOnForwardFailure yes
    ServerAliveInterval 30
    ServerAliveCountMax 3
```

Supervise `frpc`, `ssh -N vm-proxy-tunnel` (restart on exit) and `vibemaxxer client -rules ~/.config/vibemaxxer/client.rules -upstream 127.0.0.1:18080` separately. A lost tunnel only affects PROXY requests; DIRECT keeps working. frpc honors `HTTP_PROXY`, so never start it from a shell where the proxy variables point at vibemaxxer.

### Remote on-demand services

In addition to the local units above, install these units. Add `-upstream 127.0.0.1:18080` to the client's `ExecStart` when its rules contain `proxy` entries.

```ini
# ~/.config/systemd/user/vibemaxxer-remote.target
[Unit]
StopWhenUnneeded=yes
Wants=vibemaxxer.target vibemaxxer-frpc.service vibemaxxer-ssh.service

# ~/.config/systemd/user/vibemaxxer-frpc.service
[Unit]
PartOf=vibemaxxer-remote.target
StopWhenUnneeded=yes
[Service]
ExecStart=/usr/bin/frpc -c %h/.config/vibemaxxer/frpc.toml
Restart=on-failure
RestartSec=1

# ~/.config/systemd/user/vibemaxxer-ssh.service
[Unit]
PartOf=vibemaxxer-remote.target
StopWhenUnneeded=yes
After=vibemaxxer-frpc.service
StartLimitIntervalSec=0
[Service]
ExecStart=/usr/bin/ssh -N vm-proxy-tunnel
Restart=always
RestartSec=1
```

Adjust binary paths, run `systemctl --user daemon-reload`, and do not enable the units. Use:

```sh
vibemaxxer run --remote claude
codex() { vibemaxxer run --remote codex "$@"; }
```

Concurrent remote commands share the tunnel; it stops when the last remote command and its subprocesses exit. Local-only commands can keep the client running without keeping the tunnel up. A command started without `--remote` can still use DIRECT and BLOCK rules, but requests matching `proxy` rules fail if the tunnel is down.

If migrating older on-demand units, remove the frpc/SSH dependencies from `vibemaxxer.target`, move those services' `PartOf` to `vibemaxxer-remote.target`, and use `--remote` for commands that need the tunnel.

## Applications

Point applications at the client, or start them with `vibemaxxer run`:

```sh
export HTTPS_PROXY=http://127.0.0.1:8080 HTTP_PROXY=http://127.0.0.1:8080
curl https://api.ipify.org     # exits from home or the VM depending on the rules
```

- **Claude Code**: honors the variables. With `claude setup-token`, export `CLAUDE_CODE_OAUTH_TOKEN`; a fresh install may still show the login picker, so set `hasCompletedOnboarding` to `true` in `~/.claude.json`.
- **Codex**: 0.154.0 or later; earlier WebSocket clients ignore proxy variables.
- **OpenCode**: its managed service needs the variables via `opencode service set env`.
- **Cursor CLI**, **pi**: honor the variables; provider-specific settings can bypass them.

`NO_PROXY` entries and subprocesses that ignore the variables bypass vibemaxxer entirely.

## Security

- Any local process can use the loopback listeners. The server's rules bound what a compromised one can reach through the VM.
- When remote routing is enabled, SSH authenticates both ends and encrypts the hop. frps and the STUN server see addresses and timing, never payloads. A compromised or impersonated coordinator can break rendezvous, not read or redirect the tunnel; pinning its certificate also keeps the frp token from leaking to an impostor.
- An `allow` rule authorizes a host and port, not every URL or service behind it.

## Build and test

```sh
nix build .        # ./result/bin/vibemaxxer
nix develop
CGO_ENABLED=0 go build -trimpath -o vibemaxxer ./cmd/vibemaxxer   # Go 1.27+
```

```sh
gofmt -l .
go vet ./...
go test -race -count=1 ./...
nix flake check    # includes the end-to-end test below; needs KVM
```

`nix/e2e.nix` boots three QEMU VMs (coordinator, home, VM) with public test addresses and no inbound access to home or the VM. It runs frps with an RFC 5780 STUN server, frpc XTCP without fallback, the restricted sshd account and both vibemaxxer modes. It checks:

- Standalone HTTP and HTTPS filtering with no upstream configured and SSH/frp stopped on the client.
- DIRECT and PROXY egress addresses, and names that resolve only on the VM.
- Client blocks and server denials, including port mismatches, rebinding to loopback and IP literals.
- Log redaction.
- Tunnel-account bypass attempts.
- With peer UDP blocked, PROXY fails while DIRECT keeps working, then recovers when UDP returns.
