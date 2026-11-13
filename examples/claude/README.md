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

Then create the systemd units from [vibemaxxer run](../../docs/run.md), with
`ExecStart` pointing at `%h/.local/bin/vibemaxxer`. Pick one of the setups
below for the rules and the rest of `ExecStart`.

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
```

```ini
ExecStart=%h/.local/bin/vibemaxxer client --rules %h/.config/vibemaxxer/client.rules --server 192.168.1.50:8443 --server-key SERVER_FINGERPRINT
```

### Remote

Follow [SSH and frp setup](../../docs/remote.md), including the
[on-demand units](../../docs/remote.md#on-demand), and use `server.rules` on
the VM. On your machine:

```sh
install -m644 examples/claude/client.rules ~/.config/vibemaxxer/
```

```ini
ExecStart=%h/.local/bin/vibemaxxer client --rules %h/.config/vibemaxxer/client.rules --upstream 127.0.0.1:19878
```

## Run

```sh
examples/claude/bin/claude
VIBEMAXXER_REMOTE=1 examples/claude/bin/claude   # remote setup
```

The wrapper runs `~/.local/bin/claude` through `vibemaxxer run`, and with
`VIBEMAXXER_REMOTE` set it uses `vibemaxxer run --remote`, which brings the
tunnel up first. When the last Claude session exits, systemd stops the proxy
and the tunnel again. If the server or tunnel is down, Claude's API requests
fail rather than going out directly.

Set `CLAUDE_REAL_BINARY` or `VIBEMAXXER_BINARY` if your binaries live somewhere
else. The wrapper also turns off Claude's telemetry, error reporting and
background tasks. And if `CLAUDE_CODE_OAUTH_TOKEN` isn't set but `oo7-cli` is
installed, it reads the token from the `service=claude-code account=oauth-token`
entry.

If you don't use systemd, run `vibemaxxer client` with the same options, bring
the tunnel up yourself for the remote setup, and set the proxy variables like
in the [quick start](../../README.md#quick-start).
