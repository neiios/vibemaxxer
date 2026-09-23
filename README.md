# vibemaxxer

Send **Claude Code, Codex, pi, OpenCode, and Cursor CLI** traffic through a VPN on another Linux machine, with **encrypted LAN transport and one-time device pairing**. Written in Go with no third-party Go dependencies. No root, system-wide installation, SSH tunnel, private CA, or manual certificate management required.

```text
Agent → local HTTP proxy (loopback only)
      → TLS 1.3 across LAN → vibemaxxer on VPN host → VPN → API provider
```

The agent's HTTPS remains end-to-end inside the outer TLS tunnel. LAN observers cannot read CONNECT destinations, API hostnames in the inner TLS handshake, prompts, responses, or API credentials. They can still see the proxy host's IP, traffic sizes/timing, and its outer TLS hostname if you connect by DNS name.

**vibemaxxer does not establish or enforce the VPN.** Outbound sockets follow the VPN host's routing. Configure VPN routing, DNS, firewall, and kill switch separately. Application proxy settings do not force every subprocess or connection through the VPN.

## Quick start: encrypted connection

### 1. Get the program on both machines

Clone this private repository using your GitHub credentials:

```sh
gh repo clone neiios/vibemaxxer
cd vibemaxxer
nix build .
```

The commands below use `./result/bin/vibemaxxer`. Alternatively, run `nix run . -- COMMAND ...`, or build with Go as described below. Flakes support `x86_64-linux` and `aarch64-linux` and require Nix's `nix-command` and `flakes` features.

### 2. Start the VPN host

Replace the address with that machine's LAN IP:

```sh
./result/bin/vibemaxxer serve -listen 192.168.1.50:8443
```

First startup automatically generates and saves the host's identity. Only paired clients can open tunnels. Optionally add `-allow 192.168.1.20` to restrict both pairing and proxy requests to your workstation's IP as an additional safeguard.

In another terminal on the **VPN host**, generate a pairing code:

```sh
./result/bin/vibemaxxer pair-code
```

It prints the server address and a **six-digit code** (including any leading zeroes). Take both to the workstation through a trusted channel. Anyone who obtains the code before it is used can enroll their device. A code expires after **10 minutes**, works **once**, permits at most **10 incorrect attempts**, and is replaced by the next `pair-code`. Restarting `serve` cancels outstanding codes but preserves paired clients. Do not post a code publicly or paste it into a shell command.

### 3. Pair the workstation

On the **workstation**:

```sh
./result/bin/vibemaxxer pair -name workstation -server 192.168.1.50:8443
# Enter the six-digit code at the prompt, then press Enter.
```

Use the `Server:` address printed by `pair-code` for `-server`. The workstation generates its own identity, checks the server's self-signed identity certificate, and pins its public key after the code is accepted. Private keys stay on their respective machines. **A six-digit code does not protect initial pairing against an active man-in-the-middle**: pair on a trusted LAN, or independently verify the full server identity shown in the `serve` log and supply it with `pair -server-key FINGERPRINT`. Later bridge connections require the saved pin.

### 4. Start the local bridge

On the **workstation**:

```sh
./result/bin/vibemaxxer bridge
```

This listens on `127.0.0.1:8888`. It accepts connections only on loopback and forwards them to the paired host using mutually authenticated TLS. It never falls back to plaintext or direct API access if the server is unreachable or its identity changes.

### Optional: block domains on this workstation

Create a static file, for example `blocked-domains.txt`:

```text
# Domains and all their subdomains
example.com
telemetry.vendor.com
```

Start the local bridge with:

```sh
./result/bin/vibemaxxer bridge -blocklist ./blocked-domains.txt
```

The bridge returns `403 Forbidden` for blocked CONNECT destinations **before connecting to the VPN host**. The server is unchanged, and each workstation controls its own list. Allowed traffic still uses encrypted transport, with destination DNS on the VPN host and no TLS interception.

Rules are case-insensitive and ignore one trailing DNS dot. `example.com` also blocks `api.example.com`, but not `notexample.com` or `example.com.other.net`. Use one domain per line; blank lines, surrounding whitespace, duplicate entries, and whole-line `#` comments are allowed. URLs, ports, IP addresses, wildcards, and inline comments are rejected. Internationalized names must use ASCII punycode.

An unreadable or invalid file prevents startup. An empty file is valid; omitting `-blocklist` disables filtering. The file is loaded once: **restart the bridge after edits**. With filtering enabled, local CONNECT headers have a 16 KiB size limit and a 10-second read deadline.

This is an optional workstation policy, not an access-control boundary. It checks only the CONNECT hostname: direct IP addresses, alternative names/DNS aliases, another bridge configuration, or connections bypassing the proxy can evade it. It does not inspect encrypted destinations inside tunnels.

### 5. Configure your agent

In the terminal where you launch the agent:

```sh
export HTTP_PROXY=http://127.0.0.1:8888
export HTTPS_PROXY="$HTTP_PROXY"
export http_proxy="$HTTP_PROXY"
export https_proxy="$HTTPS_PROXY"
export NO_PROXY=localhost,127.0.0.1,::1
export no_proxy="$NO_PROXY"

claude  # Or codex, pi, opencode, or agent; see Client setup below.
```

The `http://` URL is intentional: this hop stays on your workstation. **The bridge encrypts everything sent across the LAN**, including the CONNECT exchange. Agents need no certificates, custom CA, API URL changes, or HTTPS-proxy support.

Both environment-variable cases are set because clients differ in precedence. Review existing values before replacing them. Exports affect new processes, not already-running agents or services. Loopback bypasses keep local HTTP services and callbacks working; they do not bypass the bridge for external API destinations. Do not add provider domains or `*` to the bypass list.

Verify the VPN exit IP:

```sh
curl --noproxy '' --proxy http://127.0.0.1:8888 https://api.ipify.org
echo
```

It should be the VPN's public IP. Also perform the [per-client and kill-switch checks](#verify-each-client-not-just-curl) below.

## Pairing and identity management

State lives in `~/.config/vibemaxxer`, or `$XDG_CONFIG_HOME/vibemaxxer`. Every command accepts `-state-dir DIR`; use the **same directory for commands on one machine**, and a **separate directory for each role** if testing server and workstation on the same machine.

- `identity.pem`: persistent Ed25519 private key, mode `0600`.
- `server.json`: advertised address, paired client public-key fingerprints/names, and the hash/expiry of at most one enrollment token.
- `bridge.json`: paired server address and public-key fingerprint.
- `.lock`: cross-process lock protecting state updates. Files are replaced atomically in a mode-`0700` directory.

Existing state with group/world permissions or symlinked identity files is rejected. Keep this directory private, outside repositories and shared/synced folders. The running processes need to write it; no CA signing key exists.

Certificates are generated automatically, valid for 90 days, and renewed on TLS handshakes when less than 30 days remain, using the same identity key. Trust is pinned to the **public key**, not a certificate's expiration date or a public CA. Certificate signatures, validity, usage, and TLS possession of the key are checked. Keep both machines' clocks reasonably accurate.

### List and revoke clients

On the VPN host:

```sh
./result/bin/vibemaxxer clients list
./result/bin/vibemaxxer clients revoke workstation
# A full identity fingerprint from 'clients list' can replace the name.
```

Revocation blocks new CONNECT requests and closes active tunnels, normally within one second. Changes apply without restarting the server. If the server cannot read its authorization state, it denies new connections and closes active tunnels rather than retaining access.

For another workstation, create a new code and pair with a different name. Names use 1–64 ASCII letters, digits, dots, underscores, or hyphens; the default is the workstation hostname.

### Change address, replace identities, or recover

- **Server LAN IP changed:** restart `serve` with the new address, generate a code, and run `pair -server NEW_HOST:PORT -replace` on the workstation. Restart `bridge` afterwards. The identity key stays unchanged.
- **DNS name or wildcard bind:** `serve -listen 0.0.0.0:8443 -advertise vpn-host.example:8443`. `-advertise` must be reachable from the workstation; wildcard addresses cannot be used with `pair -server`. Binding a single LAN IP is preferred.
- **Lost/reinstalled workstation:** revoke its old entry on the host, create a code, and pair the replacement. Revocation frees the old name.
- **Lost or compromised identity key:** revoke the affected client, or stop the affected server. Use a new private state directory and pair again via a trusted channel. Missing keys in existing state are **not silently regenerated**. Replacing a server identity requires re-pairing every workstation.
- **Backup:** a securely stored copy of the state directory preserves the identity and pairings. Treat backups as credentials. Do not copy one workstation's identity to another.

`pair -replace` explicitly permits overwriting the workstation's saved server selection; it does not revoke the old registration on a previous server. Revoke that separately if no longer needed. Restart the bridge after pairing/configuration changes. Enrollment connects directly over TLS, ignores proxy environment variables, and never follows redirects. Supply `-server-key` to verify a trusted pin during initial enrollment; otherwise the TLS identity is pinned after successful enrollment.

## Client setup

vibemaxxer is **provider- and client-independent**: it relays TCP bytes without inspecting API paths, models, authentication, or payloads. Default destination port `443` covers normal public HTTPS endpoints.

HTTP/1.1, HTTP/2 (including gRPC), SSE streaming, and secure WebSockets (`wss://`) work **inside** CONNECT. The agent must use the local proxy for its chosen transport: HTTPS proxy support does not automatically imply WebSocket proxy support. Outer CONNECT uses HTTP/1.1; UDP/QUIC is not supported.

After applying the workstation exports above:

| Client | Command | Notes |
| --- | --- | --- |
| Claude Code | `claude` | Uses standard HTTP/HTTPS proxy variables. |
| OpenAI Codex CLI | `codex` | Use a release with proxy-aware WebSocket transport; see below. |
| pi | `pi` | Its managed HTTP clients honor proxy settings; provider/extension overrides can differ. |
| OpenCode | `opencode` | Keep loopback bypasses; configure its managed service separately. |
| Cursor CLI | `agent` | `cursor-agent` is also available in some installations. This is not the desktop editor. |

Keep existing provider credentials and API base URLs. **Do not point an API base URL at the bridge**: it is a forward proxy, not an OpenAI-compatible API gateway. Point agents at the **local bridge**, not directly at the encrypted server, which requires vibemaxxer's paired client identity.

### Codex

Recent Codex releases share proxy routing between HTTP and WebSocket clients; this is present in the [0.154.0 WebSocket client](https://github.com/openai/codex/blob/rust-v0.154.0/codex-rs/websocket-client/src/lib.rs).

**Older releases can bypass proxy variables for Responses WebSockets.** Upgrade rather than assuming a successful session means it is proxied. Codex's sandbox/managed-network configuration is separate from outbound model transport; these exports do not grant sandboxed tools network access or guarantee every subprocess uses the VPN.

### pi

Start `pi` from the configured shell. Its [environment variables](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/environment-variables.md) include `HTTP_PROXY` and `HTTPS_PROXY`.

Alternatively, recent pi versions offer a global `httpProxy` setting. **Merge**, rather than overwrite, this field in `~/.pi/agent/settings.json`:

```json
{
  "httpProxy": "http://127.0.0.1:8888"
}
```

Keep the loopback bypass exports. Existing process proxy variables and provider-scoped settings can take precedence; avoid conflicting values. Custom providers and extensions can use their own network clients. If an older provider's WebSocket path ignores the proxy, update pi or select `"transport": "sse"` for providers that support it. See pi's [settings](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/settings.md).

### OpenCode

OpenCode uses local HTTP connections between its CLI and service. **Keep `NO_PROXY=localhost,127.0.0.1,::1`**: routing local HTTP service requests through the bridge will fail.

For versions with a managed background service, shell exports do not reconfigure an already-running service. Persist its environment on the workstation:

```sh
opencode service set env HTTP_PROXY http://127.0.0.1:8888
opencode service set env HTTPS_PROXY http://127.0.0.1:8888
opencode service set env http_proxy http://127.0.0.1:8888
opencode service set env https_proxy http://127.0.0.1:8888
opencode service set env NO_PROXY localhost,127.0.0.1,::1
opencode service set env no_proxy localhost,127.0.0.1,::1
opencode service start
opencode
```

Setting a managed environment variable stops the service; `service start` restarts it. Keep the workstation exports in the CLI shell too. Remove persisted variables later with `opencode service unset env VARIABLE` for each one, then restart the service.

Alternatively, `opencode --standalone` or `opencode serve` inherits its foreground environment. When attaching to an existing/remote server, run the bridge and configure proxy variables **where that server runs**, not only on the attaching client. See [OpenCode network configuration](https://opencode.ai/docs/network/).

### Cursor CLI

Start `agent` (or `cursor-agent`) from the configured shell. Current Cursor CLI builds support `HTTPS_PROXY` for API connections, including HTTP/2 tunneled over CONNECT. No HTTP/2-disable flag or TLS interception is needed.

Use an up-to-date CLI and verify actual model traffic. Desktop editor proxy settings do not configure the CLI. Browser login, remote/cloud agents, and MCP servers are separate network paths; a local proxy does not relocate remote execution traffic.

### Verify each client, not just curl

The curl check confirms connectivity and the exit IP **for curl only**. For each CLI/provider:

1. Restart the client and any service with the proxy environment, then make a small model request. Watch the VPN host's `tunnel opened` logs for the expected API destinations. Startup/update traffic alone proves nothing about model traffic.
2. Stop the bridge or VPN-host server and repeat with a **fresh client connection and a new request**. It should fail, not silently connect directly. Avoid cached results and services retaining old settings.
3. With both vibemaxxer processes running, disconnect the VPN. A fresh proxied request must fail because of the host's kill switch, not reveal its ordinary public IP. Reconnect the VPN afterwards.

These checks are not proof that every possible connection is covered. For mandatory VPN routing, use firewall/routing enforcement in addition to application settings. Client guidance is based on documentation/source, not authenticated end-to-end testing of every CLI/provider; recheck after updates.

## Commands and configuration

```sh
./result/bin/vibemaxxer help
./result/bin/vibemaxxer serve -help
./result/bin/vibemaxxer bridge -help
./result/bin/vibemaxxer pair -help
```

| Command | Purpose |
| --- | --- |
| `serve` | TLS 1.3 CONNECT server; default `127.0.0.1:8443` |
| `pair-code` | Single-use six-digit code; optional `-ttl 10m` (1m–1h) |
| `pair` | Read code from stdin; required `-server HOST:PORT`; optional `-server-key`, `-name`, `-replace` |
| `bridge` | Workstation proxy; default `127.0.0.1:8888`, loopback binds only |
| `clients list` | Show paired names and full public-key fingerprints |
| `clients revoke NAME_OR_FULL_ID` | Remove a client's access |

Running without a command prints help; flags require an explicit command. The VPN-host listener always requires paired TLS. Commands accept `-state-dir DIR`. For `clients`, place flags **after the action and before the name**, for example `clients revoke -state-dir DIR workstation`.

Server flags (`serve`):

| Flag | Default | Meaning |
| --- | --- | --- |
| `-listen` | `127.0.0.1:8443` | Literal IPv4 or bracketed IPv6 address and port |
| `-allow` | Any IP **with pairing** | Client IP/CIDR; repeatable; explicit values replace defaults |
| `-ports` | `443` | Allowed destination ports, comma-separated |
| `-dial-timeout` | `10s` | DNS and destination TCP connection establishment timeout |
| `-max-tunnels` | `128` | Concurrent tunnels, including pending destination dials (1–65536) |
| `-allow-private-destinations` | `false` | Permit private/local destination addresses |

`serve` additionally accepts `-advertise HOST:PORT`. Its total accepted connection limit is `max-tunnels + 32`, including TLS handshakes and pairing requests. Headers, pairing bodies, and TLS handshakes have deadlines; tunneled streams have no idle deadline. `bridge` accepts `-listen`, `-dial-timeout` (including upstream TLS handshake), `-max-tunnels` (including pending headers/handshakes), and optional `-blocklist FILE` for workstation-side domain filtering.

Private, loopback, link-local, unspecified, multicast, and shared CGNAT destinations are blocked by default. Actual DNS-resolved addresses are checked before connecting, including IPv4-mapped IPv6, preventing DNS rebinding around this policy. Only enable private destinations for intentional private-service access. Source allowlists use the TCP peer, never forwarded headers.

An HTTP `405` usually means something sent ordinary HTTP instead of CONNECT; `403` can mean an unauthorized client, disallowed destination, or rejected enrollment. Connection resets at the bridge can indicate failed TLS authentication or an unavailable server; check bridge logs. Local HTTP model servers should normally be explicitly bypassed in the client; those connections then do not use the VPN proxy.

## Security boundaries

- **Use a host firewall too.** Prefer binding the VPN host's LAN IP and allowing incoming connections only from your workstations. Avoid exposing the listener to the internet. Pairing is cryptographic identity; an IP allowlist alone is not.
- **Protect the local bridge.** Any process/user able to connect to your workstation's loopback port can use its paired identity. It is not per-process authorization, and loopback traffic is not encrypted. Local root or a compromised workstation is outside this protection.
- **No TLS interception.** The VPN host sees destinations and encrypted API connections, not API payloads. It can still deny or redirect traffic; agents must continue validating API server certificates normally.
- **Keep the VPN kill switch enabled.** The proxy cannot detect whether outbound sockets are using your intended VPN. Configure split tunneling to include the proxy and permit LAN connections/replies.
- **DNS for CONNECT destinations runs on the VPN host.** Configure that resolver to use the VPN. The workstation may resolve the proxy's own advertised DNS name; client code that ignores proxy settings may also perform local DNS/network requests.
- **CONNECT-only, not a general gateway.** Ordinary HTTP gets `405`; SOCKS and UDP are unsupported. Trusted clients can tunnel arbitrary TCP bytes to allowed destinations/ports; port restrictions do not verify that those bytes are TLS.
- **Subprocesses can bypass application proxies.** Browser login, MCP servers, shell commands, custom extensions, and remote agents may need separate configuration or network enforcement.
- **Logs contain metadata, not secrets:** client IPs, pairing names/public fingerprints, destinations, errors, and durations. Codes are printed only by `pair-code`; enrollment tokens, private keys, prompts, and API headers are not logged. Treat destination metadata as sensitive.

TLS uses Go's standard implementation, with pinned Ed25519 identities and SHA-256 public-key fingerprints. This is not a bespoke encryption protocol. Custom pin verification replaces Web PKI hostname/CA trust only for the outer connection; it does not disable peer authentication. No external security audit has been performed.

## Build and run without system-wide installation

With Go 1.25 or newer:

```sh
CGO_ENABLED=0 go build -trimpath -o vibemaxxer .
./vibemaxxer serve -listen 192.168.1.50:8443
```

Copy the binary to another Linux host of the same architecture; that host does not need Go. Add `GOOS=linux GOARCH=arm64` to cross-build for ARM64. State locking uses Linux/Unix file locks; the supported deployment platforms are Linux.

Other Nix commands:

```sh
nix run . -- help
nix flake check
nix develop
nix fmt
```

The checked-in `flake.lock` pins nixpkgs. Authenticate and clone the private repository first; local builds need no GitHub token in Nix configuration.

### Background services

Keep the two processes in terminals/`tmux`, or run transient systemd **user** services. Pairing commands must run as the same user with the same state directory as the relevant service.

```sh
# VPN host, from its clone after nix build:
systemd-run --user --unit=vibemaxxer-server --property=Restart=on-failure \
  "$(readlink -f result)/bin/vibemaxxer" serve -listen 192.168.1.50:8443
journalctl --user -u vibemaxxer-server -f

# Workstation, from its clone after pairing and nix build:
systemd-run --user --unit=vibemaxxer-bridge --property=Restart=on-failure \
  "$(readlink -f result)/bin/vibemaxxer" bridge
journalctl --user -u vibemaxxer-bridge -f
```

These are not boot-persistent units. Keeping user services alive after logout may require user lingering. Keep the `result` symlink as a Nix GC root while using that build. Stop with `systemctl --user stop vibemaxxer-server` or `vibemaxxer-bridge` on the corresponding host.

SIGINT/SIGTERM cancel pending dials and close active tunnels. The bridge joins its forwarding goroutines before exiting. The server explicitly closes hijacked CONNECT connections, which `http.Server.Shutdown` alone would leave open.

## Development

```sh
nix develop  # optional if Go is installed
gofmt -w *.go
go vet ./...
go test -race -count=1 -timeout=60s ./...
```

Tests use local servers, not the internet. They cover the original allowlists, resolved-destination filtering, CONNECT parsing, streaming, buffered data, half-close, limits, dial failures, and shutdown; plus pairing/replay/expiry/concurrent token consumption, private state, pinned identities, certificate renewal, authentication failures, active revocation, fail-closed behavior, HTTP/2, and WebSocket upgrade/frame transport through the encrypted bridge. A raw TCP capture check verifies that test destinations, enrollment tokens, and payloads are absent from the simulated LAN stream. CI also builds and tests the Nix package.
