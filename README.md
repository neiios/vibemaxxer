# vibemaxxer

A small HTTP CONNECT proxy for sending Claude Code's HTTPS traffic through a VPN running on another Linux machine. Written in Go, with no third-party Go dependencies. No root, system-wide installation, or SSH tunnel required on a trusted LAN.

```text
Claude Code → LAN → vibemaxxer on your VPN host → VPN → Anthropic
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

On your **workstation**:

```sh
HTTP_PROXY=http://192.168.1.50:8888 \
HTTPS_PROXY=http://192.168.1.50:8888 \
claude
```

The `http://` proxy URL is intentional: HTTPS uses an HTTP CONNECT tunnel. TLS remains end-to-end between Claude Code and its destination; there is no TLS interception or custom CA.

Check that existing `NO_PROXY` / `no_proxy` settings do not bypass the proxy for your API endpoints.

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
HTTP_PROXY=http://127.0.0.1:8888 HTTPS_PROXY=http://127.0.0.1:8888 claude
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
