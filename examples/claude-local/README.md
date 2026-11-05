# Claude Code with local filtering

Run Claude Code through a local vibemaxxer client. The supplied rules block
Claude Code's Datadog telemetry intake; everything else (including Claude services)
uses your local internet connection. No remote server, SSH
forward, server key, or `-upstream` is needed.

## Setup

Requires Bash, a systemd user manager, `readlink`, and Claude Code. `oo7-cli`
is optional (see [Run Claude](#run-claude)).

From the repository root, install the binaries and rules:

```sh
mkdir -p "$HOME/.local/bin" "$HOME/.config/vibemaxxer"
go build -o "$HOME/.local/bin/vibemaxxer" ./cmd/vibemaxxer
install -m644 examples/claude-local/client.rules "$HOME/.config/vibemaxxer/client.rules"
```

Create these two systemd user units (adjust the binary path if needed):

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
ExecStart=%h/.local/bin/vibemaxxer client -rules %h/.config/vibemaxxer/client.rules
Restart=on-failure
```

Run `systemctl --user daemon-reload`. Do not enable the units: `vibemaxxer run`
starts them on demand and they stop after the last wrapped command exits.
If you already use these units for remote routing, remove `-upstream` and replace
any `proxy` rules before using this local-only configuration.

## Run Claude

```sh
examples/claude-local/bin/claude
```

The wrapper expects the real Claude executable at `$HOME/.local/bin/claude`.
Override it with `CLAUDE_REAL_BINARY` if necessary; do not point it at the wrapper.
`VIBEMAXXER_BINARY` overrides the path to `$HOME/.local/bin/vibemaxxer`.

Like the remote example, the wrapper disables Claude telemetry and background
tasks and sets `CLAUDE_CODE_EVEN_MORE_DANGEROUSLY_SKIP_PERMISSIONS=1`. Review that
permission setting before use.

If `CLAUDE_CODE_OAUTH_TOKEN` is unset and `oo7-cli` is installed, the wrapper
reads it from `service=claude-code account=oauth-token`; otherwise Claude Code
uses its own login. Help and version requests bypass the proxy and token lookup.

Filtering applies only to traffic that uses the HTTP proxy. Applications that
ignore proxy settings, or destinations excluded by `NO_PROXY`, bypass it. This
is not a network sandbox.

## Without systemd

Start the client in one terminal:

```sh
vibemaxxer client -rules examples/claude-local/client.rules
```

Then run the real Claude binary in another terminal (with authentication already
configured):

```sh
HTTPS_PROXY=http://127.0.0.1:8080 HTTP_PROXY=http://127.0.0.1:8080 \
https_proxy=http://127.0.0.1:8080 http_proxy=http://127.0.0.1:8080 \
  "$HOME/.local/bin/claude"
```
