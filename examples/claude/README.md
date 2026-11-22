# Claude Code through vibemaxxer

This example blocks Claude Code's Datadog telemetry. In the LAN and remote
setups it also sends traffic for Anthropic and Claude domains through a server,
which allows only those domains, and only on port 443. Everything else goes out
directly.

## Setup

From the repo root:

```sh
mkdir -p ~/.local/bin ~/.config/vibemaxxer
go build -o ~/.local/bin/vibemaxxer ./cmd/vibemaxxer
```

Then pick one of the setups below.

### Local

Filtering only, with Claude's API traffic going out over your own connection:

```sh
install -m644 examples/claude/local.rules ~/.config/vibemaxxer/client.rules
```

### LAN

Follow [LAN setup](../../docs/lan.md) to exchange fingerprints, then on the
server:

```sh
install -m644 examples/claude/server.rules ~/.config/vibemaxxer/
vibemaxxer server --listen 192.168.1.50:8443 \
  --client-key WORKSTATION_FINGERPRINT --rules ~/.config/vibemaxxer/server.rules
```

Replace `192.168.1.50` with the server's LAN address, and run this under your
service manager. On your workstation:

```sh
install -m644 examples/claude/client.rules ~/.config/vibemaxxer/
export VIBEMAXXER_OPTIONS="--server 192.168.1.50:8443 --server-key SERVER_FINGERPRINT"
```

### Remote

Follow [SSH and frp setup](../../docs/remote.md) and use `server.rules` on the
VM. On your machine, bring up frpc and the SSH forward, then:

```sh
install -m644 examples/claude/client.rules ~/.config/vibemaxxer/
export VIBEMAXXER_OPTIONS="--upstream 127.0.0.1:19878"
```

## Run

```sh
examples/claude/bin/claude
```

The wrapper runs `~/.local/bin/claude` through
[`vibemaxxer run`](../../docs/run.md) with `~/.config/vibemaxxer/client.rules`
and whatever is in `VIBEMAXXER_OPTIONS`. Each Claude session gets its own
proxy, which stops when the session exits. If the server or tunnel is down,
Claude's API requests fail rather than going out directly.

Set `CLAUDE_REAL_BINARY`, `VIBEMAXXER_BINARY` or `VIBEMAXXER_RULES` if your
files live somewhere else. The wrapper also turns off Claude's telemetry,
error reporting and background tasks. And if `CLAUDE_CODE_OAUTH_TOKEN` isn't
set but `oo7-cli` is installed, it reads the token from the
`service=claude-code account=oauth-token` entry.
