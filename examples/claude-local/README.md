# Claude Code, local filtering

This example blocks Claude Code's Datadog telemetry and nothing else. Claude's
API traffic goes out over your own connection.

## Setup

From the repo root:

```sh
mkdir -p ~/.local/bin ~/.config/vibemaxxer
go build -o ~/.local/bin/vibemaxxer ./cmd/vibemaxxer
install -m644 examples/claude-local/client.rules ~/.config/vibemaxxer/
```

Then create the two systemd units from [vibemaxxer run](../../docs/run.md),
with `ExecStart` pointing at `%h/.local/bin/vibemaxxer`.

## Run

```sh
examples/claude-local/bin/claude
```

The wrapper runs `~/.local/bin/claude` through `vibemaxxer run`. Set
`CLAUDE_REAL_BINARY` or `VIBEMAXXER_BINARY` if your binaries live somewhere
else. It also turns off Claude's telemetry, error reporting and background
tasks. And if `CLAUDE_CODE_OAUTH_TOKEN` isn't set but `oo7-cli` is installed,
it reads the token from the `service=claude-code account=oauth-token` entry.

If you don't use systemd, run `vibemaxxer client` with this `client.rules`
and set the proxy variables like in the
[quick start](../../README.md#quick-start).
