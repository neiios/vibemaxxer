# Claude Code via a remote VM

This example blocks Claude Code's telemetry and sends traffic for Anthropic
and Claude domains through a VM over SSH. Everything else goes out directly.
The server allows only those domains, and only on port 443.

## Setup

1. Follow [SSH and frp setup](../../docs/remote.md), including the
   [on-demand units](../../docs/remote.md#on-demand), and use this example's
   `server.rules` on the VM.
2. On your machine, from the repo root:

   ```sh
   mkdir -p ~/.local/bin ~/.config/vibemaxxer
   go build -o ~/.local/bin/vibemaxxer ./cmd/vibemaxxer
   install -m644 examples/claude-remote/client.rules ~/.config/vibemaxxer/
   ```

3. Use this `ExecStart` in `vibemaxxer-client.service`:

   ```ini
   ExecStart=%h/.local/bin/vibemaxxer client --rules %h/.config/vibemaxxer/client.rules --upstream 127.0.0.1:18080
   ```

## Run

```sh
examples/claude-remote/bin/claude
```

The wrapper brings the tunnel up and then starts Claude. When the last Claude
session exits, systemd takes the tunnel down again. If the tunnel is down,
Claude's API requests fail rather than going out directly. Otherwise it's the
same wrapper as in the [local example](../claude-local/#run).

If you don't use systemd, bring the tunnel up yourself, run
`vibemaxxer client` with this `client.rules` and `--upstream 127.0.0.1:18080`,
and set the proxy variables like in the
[quick start](../../README.md#quick-start).
