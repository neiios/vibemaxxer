# Claude Code with remote routing

This example uses the current `vibemaxxer client` / `server` commands and
`vibemaxxer run --remote`. SSH provides transport encryption and peer
authentication; this example does not use vibemaxxer identity pins. For direct
pinned-TLS connections between LAN hosts, use [claude-lan](../claude-lan/).
The old runner's `run -server`, `-blocklist`, and `-proxy-domains` flags are not
used; LAN TLS transport options belong to the `client` and `server` commands.

- `client.rules` blocks the domains in `blocked-domains.txt`, routes the domains
  in `claude-proxy-domains.txt` through the remote server, and sends all other
  traffic directly.
- `server.rules` permits those Claude domains on port 443 only; everything else
  is denied.
- The original domain lists are retained unchanged for reference. The current
  binary reads the native `.rules` files, not those lists. If you change a list,
  update the corresponding rules too. A leading `.` includes all subdomains.

## Install

Requires Bash, a systemd user manager, `readlink`, Claude Code, and `oo7-cli`
(unless `CLAUDE_CODE_OAUTH_TOKEN` is already set). Remote routing also requires
an authenticated SSH tunnel to a machine running `vibemaxxer server`.

From the repository root, on the client:

```sh
mkdir -p "$HOME/.local/bin" "$HOME/.config/vibemaxxer"
go build -o "$HOME/.local/bin/vibemaxxer" ./cmd/vibemaxxer
install -m644 examples/claude-remote/client.rules "$HOME/.config/vibemaxxer/client.rules"
```

On the remote machine, install vibemaxxer and copy `server.rules` to
`/etc/vibemaxxer/server.rules`. Run under your service manager:

```sh
vibemaxxer server -rules /etc/vibemaxxer/server.rules -listen 127.0.0.1:8081
```

Configure the restricted SSH account, pinned host key, SSH forward, and systemd
user units described in the root README's
[optional remote deployment](../../README.md#optional-remote-deployment) and
[remote on-demand services](../../README.md#remote-on-demand-services).
That guide includes frp for NAT traversal; if the SSH server is directly
reachable, connect SSH to it directly and omit the frpc service and dependency.
Do not expose the unauthenticated HTTP server to the network.

The required topology is:

```text
Claude -> client 127.0.0.1:8080
          -> BLOCK: denied
          -> DIRECT: local internet connection
          -> PROXY: SSH forward 127.0.0.1:18080 -> remote server 127.0.0.1:8081
```

In particular, the client's systemd service must use an explicit upstream:

```ini
# ~/.config/systemd/user/vibemaxxer-client.service
[Unit]
PartOf=vibemaxxer.target
StopWhenUnneeded=yes
[Service]
ExecStart=%h/.local/bin/vibemaxxer client -rules %h/.config/vibemaxxer/client.rules -upstream 127.0.0.1:18080
Restart=on-failure
```

Install the other units from the linked guide, then run
`systemctl --user daemon-reload`. Do not enable the units: the runner starts
`vibemaxxer-remote.target` on demand, waits for the client and SSH forward, and
stops the services when no wrapped commands need them. Restart an already-running
client after changing its rules or command line. The local and remote examples
share the default client port and service names; select one configuration at a
time.

## Run

```sh
examples/claude-remote/bin/claude
```

The wrapper expects the real Claude executable at `$HOME/.local/bin/claude`.
Set `CLAUDE_REAL_BINARY` to override it; it must not point to the wrapper.
Set `VIBEMAXXER_BINARY` to override `$HOME/.local/bin/vibemaxxer`.
The old `VIBEMAXXER_SERVER`, `VIBEMAXXER_SERVER_KEY`, `VIBEMAXXER_BLOCKLIST`, and
`VIBEMAXXER_PROXY_DOMAINS` variables are no longer used: configure the tunnel and
rules instead.

Authentication uses `CLAUDE_CODE_OAUTH_TOKEN` if set, otherwise `oo7-cli lookup
--secret-only service=claude-code account=oauth-token`. Help and version requests
bypass authentication and proxy startup. The wrapper disables telemetry and
background tasks and retains
`CLAUDE_CODE_EVEN_MORE_DANGEROUSLY_SKIP_PERMISSIONS=1`; review that permission
setting before use.

Claude domains never fall back to DIRECT when the tunnel fails. However,
applications that ignore proxy settings and destinations excluded by `NO_PROXY`
bypass filtering and routing. This is not a network sandbox.

## Manual operation without systemd

With the remote server running and the SSH forward established, start:

```sh
vibemaxxer client -rules examples/claude-remote/client.rules -upstream 127.0.0.1:18080
```

Then run the real Claude executable in another terminal, with authentication
already configured:

```sh
HTTPS_PROXY=http://127.0.0.1:8080 HTTP_PROXY=http://127.0.0.1:8080 \
https_proxy=http://127.0.0.1:8080 http_proxy=http://127.0.0.1:8080 \
  "$HOME/.local/bin/claude"
```
