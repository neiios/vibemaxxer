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

Workstation (on-demand shared bridge, no persistent service):

```sh
vibemaxxer run -server 192.168.1.50:8443 -server-key HOST_FP -- claude
# In another terminal, the same settings reuse the same bridge:
vibemaxxer run -server 192.168.1.50:8443 -server-key HOST_FP -- codex
```

The first session starts a detached bridge on a free loopback port. Each `run` prints its address and private log path. The bridge stops three seconds after the last session exits. `run` supervises the command and sets `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` and their lowercase forms. Commands keep their terminal and exit status.

Alternatively, manage the bridge yourself (existing behavior, unchanged):

```sh
vibemaxxer bridge -server 192.168.1.50:8443 -server-key HOST_FP
vibemaxxer run -bridge 127.0.0.1:8888 -- claude
```

The external bridge defaults to `127.0.0.1:8888`; external `run` checks its TCP listener then execs the command. Omitting both `-server` and `-bridge` retains this mode. Both bridge modes check the upstream and log pin, identity or reachability failures. Readiness means the local listener is available, not that the VPN host accepted the identity: upstream failures are logged and retried per connection, never silently routed directly.

Check the exit IP:

```sh
vibemaxxer run -- curl https://api.ipify.org
```

### Managed configuration

```sh
vibemaxxer run -server 192.168.1.50:8443 -server-key HOST_FP \
  -blocklist blocked-domains.txt -proxy-domains proxy-domains.txt \
  -direct-ports 443,8443 -- pi
```

Managed `run` also accepts `-key`, `-listen` (default `127.0.0.1:0`, a free port), `-grace` (default `3s`), `-startup-timeout` (default `15s`), and `-runtime-dir` (default `/tmp/vibemaxxer-UID`). Grace and startup timeout must be between `100ms` and `1m`. Managed flags require `-server` and `-server-key`; they cannot be combined with `-bridge`. Use the same flags across sessions to share. An explicit occupied port fails startup; an existing listener is never adopted.

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
| `run` | Run a command with proxy variables; optionally manage a shared bridge |

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
| `-bridge` | run (external) | `127.0.0.1:8888` | Existing bridge address; exec mode |
| `-server`, `-server-key` | run (managed) | required | Enable on-demand mode; same meaning as bridge |
| `-blocklist`, `-proxy-domains`, `-direct-ports` | run (managed) | as above | Snapshot routing configuration |
| `-listen` | run (managed) | `127.0.0.1:0` | Loopback listener, automatic free port |
| `-grace` | run (managed) | `3s` | Idle shutdown delay |
| `-startup-timeout` | run (managed) | `15s` | Bounded lock/readiness wait |
| `-runtime-dir` | run (managed) | `/tmp/vibemaxxer-UID` | Private owner-only runtime directory |

Fixed: 10-second dial and header timeouts, 256 tunnels per process. Private, loopback, link-local, and CGNAT destinations are refused after DNS resolution, so a tunnel cannot reach the VPN host's LAN.

## Clients

- **Claude Code**: `vibemaxxer run -- claude`. With `claude setup-token`, export `CLAUDE_CODE_OAUTH_TOKEN` in the same shell. A fresh install may show the login picker despite a valid token; set `hasCompletedOnboarding` to `true` in `~/.claude.json`.
- **Codex**: 0.154.0 or later. Earlier WebSocket clients ignore proxy variables.
- **pi**: provider-specific settings can bypass the proxy.
- **OpenCode**: the managed service needs `opencode service set env` for `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` and their lowercase forms, then `opencode service start`.
- **Cursor CLI**: `vibemaxxer run -- agent`.

To confirm a client is proxied, make a model request and watch for `tunnel opened` in the server log. Stop the bridge and the same request must fail.

## Managed bridge architecture and limits

- A configuration hash includes the server address/pin, actual identity key, listen address, direct ports, grace, **domain file bytes**, and executable contents. File paths alone are not keys. Absent and empty selective-routing files differ. Identical contents at different paths can share. Binary upgrades, identity replacement or rule edits create separate bridges; existing sessions retain their original snapshots. Edits are not hot-reloaded. Fixed listen ports cannot host two configurations simultaneously.
- Per-configuration Linux `flock` locks serialize startup and protect shutdown versus lease registration. A separate inherited lifetime lock reserves ownership even before readiness; stale sockets are recovered only by its owner. No PID counters or PID-based cleanup. Lock files are deliberately never unlinked, avoiding split-lock races.
- Every supervisor holds a live control Unix connection for the command's lifetime. Registration occurs under the same gate used by idle shutdown. EOF releases the lease. New leases during grace keep the bridge alive. Control descriptors are close-on-exec and are not passed to commands or their descendants.
- The daemon starts a new session with `/dev/null` stdin and private log stdout/stderr, independent of the first supervisor's terminal, pipes or lifetime. An unlinked private configuration snapshot is passed by descriptor. The runtime directory must be owned by the user, mode `0700`, with safe non-symlink ancestors. Control sockets and log/lock files are owner-validated and mode `0600`; control peers are UID-checked. Symlinks, hardlinked state files and unsafe existing files are refused. Same-UID processes are trusted.
- Logs persist after shutdown, including block rule diagnostics and upstream failures. They are not rotated automatically. Inspect the printed `.log` path; remove old logs yourself. Do not delete runtime state or its lock files while sessions/launchers are active. There is no always-running manager or persistent service.
- Startup lock/readiness waits are bounded. Local file reads and executable hashing precede that wait. A launcher that times out may leave an already-starting daemon, which exits after its idle grace. A bridge crash is reported to live supervisors; it is **not** transparently restarted for existing commands. VPN requests fail rather than fall back directly. A later new session can recover stale state and start a new bridge.
- If a supervisor is killed (including SIGKILL), its lease closes even if its command survives. Commands that daemonize or leave background children do not extend the lease: tracking is by direct supervised session, not descendant process trees. Those children may lose proxy access after grace. Similarly, stopping a supervisor with job control retains its lease until it resumes/exits. No automatic child-tree cleanup is attempted.
- Commands share the supervisor's foreground process group and inherit real terminal descriptors (no PTY emulation). Terminal input, resizing and shell job control remain available. INT/QUIT/TERM/HUP delivered to the supervisor are forwarded to its immediate command; terminal group INT/QUIT can also reach the command directly, so custom signal handlers should tolerate duplicate delivery. Exit codes are preserved; signal exits use `128 + signal`. Background descendants are not independently supervised. On bridge loss, the command remains running with a warning so users can save work.

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
go test -race -count=1 -timeout=120s ./...
```
