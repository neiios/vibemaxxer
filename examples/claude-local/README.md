# Claude Code, local filtering

This blocks Claude Code's Datadog telemetry. Everything else, Claude's API
included, goes out over your own connection.

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

The wrapper runs `~/.local/bin/claude` through `vibemaxxer run`. You can
change both paths with `CLAUDE_REAL_BINARY` and `VIBEMAXXER_BINARY`. It also:

- turns off Claude's telemetry, error reporting and background tasks
- sets `CLAUDE_CODE_EVEN_MORE_DANGEROUSLY_SKIP_PERMISSIONS=1`, so read up on
  that before you use it
- reads `CLAUDE_CODE_OAUTH_TOKEN` from `oo7-cli`
  (`service=claude-code account=oauth-token`) if it's installed and the
  variable is unset

## Without systemd

```sh
vibemaxxer client --rules examples/claude-local/client.rules
```

and in another terminal:

```sh
HTTPS_PROXY=http://127.0.0.1:8080 HTTP_PROXY=http://127.0.0.1:8080 ~/.local/bin/claude
```
