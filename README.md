# vibemaxxer

A small HTTP CONNECT proxy for sending coding agents' HTTPS traffic through a VPN running on another Linux machine. Works with **Claude Code, Codex, pi, OpenCode, and Cursor CLI**, subject to the client configuration and version caveats below. Written in Go, with no third-party Go dependencies. No root, system-wide installation, or SSH tunnel required on a trusted LAN.

```text
Coding agent → LAN → vibemaxxer on your VPN host → VPN → API provider
```

vibemaxxer opens outbound TCP connections using the host's normal routing. It **does not establish or enforce the VPN**. Configure your VPN, DNS, and kill switch separately.

## Quick start with Nix

Clone this private repository using your GitHub credentials **on the VPN host**:

```sh
gh repo clone neiios/vibemaxxer
cd vibemaxxer

# Substitute your VPN host's LAN IP and your workstation's LAN IP.
nix run . -- -listen 192.168.1.50:8888 -allow 192.168.1.20
```

`nix run` builds and runs the program without installing it into a profile. The flake supports `x86_64-linux` and `aarch64-linux`. If flakes are not enabled, enable `nix-command` and `flakes` in your Nix configuration.

On your **workstation**, set the proxy environment in the terminal where you will launch your agent:

```sh
export HTTP_PROXY=http://192.168.1.50:8888
export HTTPS_PROXY="$HTTP_PROXY"
export http_proxy="$HTTP_PROXY"
export https_proxy="$HTTPS_PROXY"
export NO_PROXY=localhost,127.0.0.1,::1
export no_proxy="$NO_PROXY"

claude  # Or codex, pi, opencode, or agent; see Client setup below.
```

Both cases are set deliberately: clients differ in which casing takes precedence. These exports affect programs launched from this shell, not already-running agents or services. Review any existing proxy/bypass settings before replacing them.

The `http://` proxy URL is intentional: HTTPS uses an HTTP CONNECT tunnel. TLS remains end-to-end between the agent and its destination; there is no TLS interception or custom CA.

Keep loopback in `NO_PROXY` / `no_proxy` so local services and callbacks connect directly, especially OpenCode's local HTTP service. Do not add API-provider domains or `*`: that would bypass the VPN proxy. See [Client setup](#client-setup) for service configuration and other caveats.

Verify the exit address from your workstation:

```sh
curl --noproxy '' --proxy http://192.168.1.50:8888 https://api.ipify.org
echo
```

This should print the VPN's public IP. Also test your kill switch: disconnecting the VPN should make a **fresh** proxied request fail, not reveal the VPN host's ordinary public IP.

### Build without Nix

Go 1.25 or newer:

```sh
CGO_ENABLED=0 go build -trimpath -o vibemaxxer .
./vibemaxxer -listen 192.168.1.50:8888 -allow 192.168.1.20
```

The resulting binary can be copied to another Linux host of the same architecture. The VPN host does not need Go installed. To build for ARM64 from another architecture, add `GOOS=linux GOARCH=arm64` to the build command.

### Other Nix commands

```sh
nix build .                 # binary: ./result/bin/vibemaxxer
nix flake check             # build and run tests
nix develop                 # Go, gopls, and nixfmt
nix fmt
```

The checked-in `flake.lock` pins nixpkgs. Authenticate and clone the private repository first; local builds do not need a GitHub token in Nix configuration.

## Client setup

vibemaxxer is **provider- and client-independent**: it relays TCP bytes after CONNECT, without inspecting API paths, models, authentication, or payloads. No server-side mode or hostname list is needed for different agents. Default port `443` covers normal public HTTPS endpoints.

HTTP/1.1, HTTP/2 (including gRPC), SSE streaming, and secure WebSockets (`wss://`) can all travel **inside** a CONNECT tunnel. The agent must actually use the proxy for its chosen transport; proxy support for HTTPS does not automatically imply proxy support for WebSockets. vibemaxxer does not accept HTTP/2 CONNECT on its plain HTTP listener, nor does it proxy UDP/QUIC.

After applying the workstation exports above, launch the desired client:

| Client | Command | Notes |
| --- | --- | --- |
| Claude Code | `claude` | Uses standard HTTP/HTTPS proxy variables. |
| OpenAI Codex CLI | `codex` | Use a recent release with proxy-aware WebSocket transport; see below. |
| pi | `pi` | Proxy variables configure its managed HTTP clients; provider/extension overrides can differ. |
| OpenCode | `opencode` | Keep loopback bypasses; configure its managed service separately if used. |
| Cursor CLI | `agent` | `cursor-agent` is also available with some installations. This is not the Cursor desktop editor. |

Keep your existing provider credentials and API base URLs. **Do not set an API base URL to `http://192.168.1.50:8888`**: this is a forward proxy, not an OpenAI-compatible API gateway.

### Codex

Start `codex` from the configured shell. Recent Codex releases share proxy routing between HTTP and WebSocket clients; this is present in the [0.154.0 WebSocket client](https://github.com/openai/codex/blob/rust-v0.154.0/codex-rs/websocket-client/src/lib.rs).

**Older releases can bypass proxy variables for Responses WebSockets.** Upgrade rather than assuming a successful session means it is proxied. Verify a fresh model request as described below. Codex's sandbox/managed-network configuration is separate from the CLI's outbound model transport; these exports do not grant sandboxed tools network access or guarantee that every subprocess uses the VPN.

### pi

Start `pi` from the configured shell. Its [environment variables](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/environment-variables.md) include `HTTP_PROXY` and `HTTPS_PROXY`.

Alternatively, recent pi versions offer a global `httpProxy` setting. **Merge**, rather than overwrite, this field in `~/.pi/agent/settings.json`:

```json
{
  "httpProxy": "http://192.168.1.50:8888"
}
```

Keep the loopback bypass exports even when using this setting. Existing process proxy variables and provider-scoped settings can take precedence; avoid conflicting values. Custom providers and extensions can use their own network clients, so verify each provider/transport you rely on. If an older provider's WebSocket path does not honor the proxy, update pi or select `"transport": "sse"` in settings for providers that support it. See pi's [network and transport settings](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/settings.md).

### OpenCode

OpenCode uses local HTTP connections between the CLI and its service. **`NO_PROXY=localhost,127.0.0.1,::1` is required** when configuring the CLI proxy; sending these local requests to vibemaxxer will fail.

For versions with a managed background service, shell exports alone do not reconfigure an already-running service. Persist its environment and start it with the new settings:

```sh
opencode service set env HTTP_PROXY http://192.168.1.50:8888
opencode service set env HTTPS_PROXY http://192.168.1.50:8888
opencode service set env http_proxy http://192.168.1.50:8888
opencode service set env https_proxy http://192.168.1.50:8888
opencode service set env NO_PROXY localhost,127.0.0.1,::1
opencode service set env no_proxy localhost,127.0.0.1,::1
opencode service start
opencode
```

Setting a managed environment variable stops the running service; `service start` starts it again. These commands change OpenCode's persisted service configuration, not vibemaxxer. Keep the workstation exports in the CLI shell too. To remove persisted variables later, use `opencode service unset env VARIABLE` for each one and restart the service.

Alternatively, `opencode --standalone` or `opencode serve` inherits the foreground process's environment. When attaching to an existing or remote server, configure the proxy **where that server runs**, not only on the attaching client. See [OpenCode network configuration](https://opencode.ai/docs/network/).

### Cursor CLI

Start `agent` (or `cursor-agent`) from the configured shell. Current Cursor CLI builds support `HTTPS_PROXY` for API connections, including HTTP/2 connections tunneled over CONNECT. No HTTP/2-disable flag or TLS interception is needed for vibemaxxer.

Use an up-to-date CLI and verify its actual model traffic. Desktop editor proxy settings are not a substitute for the CLI's environment. Browser-based login, remote/cloud agents, MCP servers, and other subprocesses are separate network paths; a locally configured proxy does not relocate a remote agent's execution traffic.

### Verify each client, not just curl

The curl check above confirms proxy connectivity and the exit IP **for curl only**. For each CLI/provider you use:

1. Restart the client (and any background service) with the proxy environment, then make a small model request. Watch vibemaxxer's logs for `tunnel opened` entries to that client's API destinations. Startup/update traffic alone does not prove model traffic is proxied.
2. Stop vibemaxxer and repeat with a **fresh client connection and a new model request**. The request should fail, not silently switch to direct access. Use a fresh process to avoid cached results or a different service retaining old settings.
3. With vibemaxxer running, disconnect the VPN and verify that its kill switch blocks fresh requests. Reconnect the VPN afterwards.

These are practical checks, not proof that every possible connection is covered. If all traffic must be forced through the VPN, use routing/firewall enforcement rather than relying only on application proxy settings.

Compatibility guidance is based on client documentation/source, not authenticated end-to-end testing of every CLI and provider. Recheck after client updates or transport changes. An HTTP `405` means something sent an ordinary HTTP proxy request; `403` can mean a disallowed client, port, or private destination. Local HTTP model servers should usually be added explicitly to your client's bypass list; they then connect directly and do not use the VPN proxy.

## Configuration

Run `vibemaxxer -help` for flags:

| Flag | Default | Meaning |
| --- | --- | --- |
| `-listen` | `127.0.0.1:8888` | Literal IPv4 or bracketed IPv6 address and port |
| `-allow` | Loopback IPv4/IPv6 | Allowed client IP or CIDR; repeatable |
| `-ports` | `443` | Comma-separated allowed destination ports |
| `-dial-timeout` | `10s` | DNS and TCP connection establishment timeout |
| `-max-tunnels` | `128` | Maximum simultaneous tunnels, including pending dials |
| `-allow-private-destinations` | `false` | Permit private/local destination IPs |

Explicit `-allow` flags **replace** the loopback defaults. A non-loopback listener requires an explicit allowlist. Source addresses come from the TCP connection, never forwarded headers.

```sh
# Two workstations; prefer individual IPs over a whole subnet.
vibemaxxer -listen 192.168.1.50:8888 \
  -allow 192.168.1.20 -allow 192.168.1.21

# A whole trusted subnet (broader access).
vibemaxxer -listen 192.168.1.50:8888 -allow 192.168.1.0/24

# IPv6 listener and client.
vibemaxxer -listen '[fd00::50]:8888' -allow fd00::20
```

Private, loopback, link-local, unspecified, multicast, and shared CGNAT **destination** addresses are blocked by default. This also applies to hostnames resolving to those addresses and to IPv4-mapped IPv6 addresses. Actual resolved addresses are checked before connecting, preventing DNS rebinding around this policy. Client addresses can still be private, as expected for LAN use. Only enable `-allow-private-destinations` for intentional access to private services.

## Security and networking

- **Trusted LAN only.** The listener is plain HTTP with IP-based access control, not user authentication. HTTPS payloads—including prompts, responses, and API credentials—remain TLS-encrypted. CONNECT hostnames and ports are visible on the LAN. There is no HTTPS-proxy listener or proxy-password support.
- **Use a host firewall as defense in depth.** Permit the listen port only from your workstation's IP. Do not port-forward it from the internet. Binding a LAN IP alone does not restrict client access. IP allowlisting is not strong identity protection on a hostile network.
- **Keep the VPN kill switch enabled.** If the VPN goes down, host routing might otherwise fall back to ordinary internet access. The proxy cannot detect whether an outbound connection is using your intended VPN.
- **Check split tunneling.** The proxy process must be included in VPN routing. Permit incoming LAN connections and their replies in the VPN/firewall rules.
- **DNS happens on the proxy host** for hostname-based CONNECT requests. Configure that host's resolver to use the VPN as well.
- **CONNECT-only, not a general gateway.** Ordinary HTTP requests receive `405`. SOCKS is not supported. Port restrictions do not verify that tunneled bytes are TLS; trusted clients can send arbitrary TCP traffic to allowed destinations/ports.
- **Not all child processes honor proxy variables.** Browser login flows, MCP servers, shell commands, and other tools may need separate configuration. This is not whole-machine VPN routing.
- **Long-running streams are supported.** Headers and connection setup have timeouts; established tunnels deliberately have no overall or idle deadline. A finite tunnel limit bounds concurrent outbound connections.
- **Logs contain client addresses, destination hostnames, errors, and tunnel durations**, not payloads, prompts, API headers, or credentials. Treat destination metadata as sensitive.

For an untrusted network, keep the listener on loopback and add SSH:

```sh
# VPN host:
vibemaxxer

# Workstation, separate terminal:
ssh -NT -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 \
  -L 127.0.0.1:8888:127.0.0.1:8888 youruser@192.168.1.50

# Workstation:
# Use the same Client setup instructions, with the proxy URL changed to
# http://127.0.0.1:8888 in both uppercase and lowercase variables.
export HTTP_PROXY=http://127.0.0.1:8888 HTTPS_PROXY=http://127.0.0.1:8888
export http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY"
export NO_PROXY=localhost,127.0.0.1,::1 no_proxy=localhost,127.0.0.1,::1
claude  # Or codex, pi, opencode, or agent.
```

## Running in the background without a system-wide install

Keep it in a terminal or `tmux`, or build it and start a transient systemd **user** service on the VPN host:

```sh
nix build .
systemd-run --user --unit=vibemaxxer --property=Restart=on-failure \
  "$(readlink -f result)/bin/vibemaxxer" \
  -listen 192.168.1.50:8888 -allow 192.168.1.20

journalctl --user -u vibemaxxer -f
systemctl --user stop vibemaxxer
```

This is not boot persistence: the transient unit is not installed, and keeping user services alive after logout may require user lingering. Keep the `result` symlink as a Nix GC root while using that build.

SIGINT and SIGTERM stop the server, cancel pending dials, and close active CONNECT tunnels. `http.Server.Shutdown` alone would not close hijacked connections; vibemaxxer tracks those explicitly.

## Development

```sh
nix develop  # optional if Go is already installed
gofmt -w *.go
go vet ./...
go test -race -count=1 -timeout=60s ./...
```

Tests use local servers, not the internet. They cover client allowlists, destination filtering (including resolved hostnames), request validation, end-to-end verified TLS, streaming, buffered CONNECT data, TCP half-close, overload, failed connections, and shutdown. GitHub Actions also builds and tests the Nix package.
