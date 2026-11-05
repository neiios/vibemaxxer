# Claude Code through a LAN machine

Use this instead of `claude-remote` when the computers can reach each other
directly. The client connects to the egress machine over built-in, mutually
authenticated TLS 1.3. No SSH, frp, or public coordinator is needed.

```text
Claude -> client 127.0.0.1:8080 -> BLOCK: 403
                              -> DIRECT: local internet
                              -> PROXY: pinned TLS -> LAN server -> internet/VPN
```

The native rules match the remote example: block Claude Code's telemetry intake, route
Claude services through the LAN server, and connect directly for everything
else. The server permits only those Claude services on port 443. It independently
checks the policy and resolves proxied destination hostnames.

## Install and exchange fingerprints

Install vibemaxxer on both computers, for example from the repository:

```sh
mkdir -p "$HOME/.local/bin"
go build -o "$HOME/.local/bin/vibemaxxer" ./cmd/vibemaxxer
"$HOME/.local/bin/vibemaxxer" key
```

`key` creates `~/.config/vibemaxxer/identity.pem` if absent and prints its public
fingerprint. Exchange fingerprints using a trusted channel; do not exchange private PEM files.
Use `-key FILE` consistently if you want a separate identity.

## Egress machine

Copy `server.rules` to `~/.config/vibemaxxer/server.rules`, then run:

```sh
"$HOME/.local/bin/vibemaxxer" server -tls \
  -listen 192.168.1.50:8443 \
  -client-key WORKSTATION_FINGERPRINT \
  -rules "$HOME/.config/vibemaxxer/server.rules"
```

Replace the IP with this machine's LAN address. Permit that TCP port only from
trusted LAN hosts in your firewall. Wildcard binds are refused. Repeat
`-client-key` to allow more workstations. Supervise this process with your service
manager; the workstation runner does not start the remote server.

The server uses its normal routing. Configure a VPN and kill switch on that
machine separately if desired; vibemaxxer does not manage them.

## Workstation

Install the client rules from the repository root:

```sh
mkdir -p "$HOME/.config/vibemaxxer" "$HOME/.config/systemd/user"
install -m644 examples/claude-lan/client.rules "$HOME/.config/vibemaxxer/client.rules"
```

Create these systemd user units, substituting the egress machine's actual LAN
address and fingerprint:

```ini
# ~/.config/systemd/user/vibemaxxer.target
[Unit]
StopWhenUnneeded=yes
Wants=vibemaxxer-client.service
```

```ini
# ~/.config/systemd/user/vibemaxxer-client.service
[Unit]
PartOf=vibemaxxer.target
StopWhenUnneeded=yes
[Service]
ExecStart=%h/.local/bin/vibemaxxer client -rules %h/.config/vibemaxxer/client.rules -server 192.168.1.50:8443 -server-key EGRESS_MACHINE_FINGERPRINT
Restart=on-failure
```

```ini
# ~/.config/systemd/user/vibemaxxer-lan.target
[Unit]
StopWhenUnneeded=yes
Wants=vibemaxxer.target
```

Run `systemctl --user daemon-reload`, but do not enable these units. The runner
starts the local client on demand and stops it when the last wrapped command and
its subprocesses exit. It does not start or check an SSH forward. Readiness only
checks the local client listener; a request verifies the remote TLS identity.

The local, LAN, and SSH examples share a client service and port. Select one
configuration at a time and restart an already-running client after changing it.
`--lan` selects the startup target; the service configuration selects transport
and routing.

## Run Claude

```sh
examples/claude-lan/bin/claude
```

The wrapper uses `vibemaxxer run --lan`. `VIBEMAXXER_BINARY` overrides the default
`$HOME/.local/bin/vibemaxxer`, and `CLAUDE_REAL_BINARY` overrides the real Claude
path (`$HOME/.local/bin/claude`). Do not point that variable at the wrapper.

As in the other examples, Bash and `readlink` are required. If
`CLAUDE_CODE_OAUTH_TOKEN` is unset and `oo7-cli` is installed, the wrapper reads
it from `service=claude-code account=oauth-token`; otherwise Claude Code uses its
own login. Help/version bypass proxy startup. The wrapper disables telemetry and
background tasks and retains
`CLAUDE_CODE_EVEN_MORE_DANGEROUSLY_SKIP_PERMISSIONS=1`; review that setting before
use.

## Without systemd

Run the server as above. Start the client manually:

```sh
vibemaxxer client -rules examples/claude-lan/client.rules \
  -server 192.168.1.50:8443 -server-key EGRESS_MACHINE_FINGERPRINT
```

Then run the real Claude executable with authentication already configured:

```sh
HTTPS_PROXY=http://127.0.0.1:8080 HTTP_PROXY=http://127.0.0.1:8080 \
https_proxy=http://127.0.0.1:8080 http_proxy=http://127.0.0.1:8080 \
  "$HOME/.local/bin/claude"
```

A wrong identity or unavailable LAN server never falls back to DIRECT or
plaintext. Application HTTPS is not decrypted by either proxy. Applications
that ignore proxy settings and `NO_PROXY` exclusions bypass routing and filtering;
this is not a network sandbox.
