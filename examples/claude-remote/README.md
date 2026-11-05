# Claude Code via a remote VM

This blocks Claude Code's telemetry and sends Claude's API traffic through a
VM over SSH. Everything else goes out directly. The server only allows
Claude's domains on port 443.

## Setup

1. Follow [SSH and frp setup](../../docs/remote.md), including the
   [on-demand units](../../docs/remote.md#on-demand). Use this example's
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

This brings up the tunnel and runs Claude. When the last session exits, the
tunnel goes down again. If the tunnel is down, Claude's API requests fail
instead of going out directly. Otherwise the wrapper behaves the same as in
the [local example](../claude-local/#run).

## Without systemd

With the tunnel up:

```sh
vibemaxxer client --rules examples/claude-remote/client.rules --upstream 127.0.0.1:18080
```

and in another terminal:

```sh
HTTPS_PROXY=http://127.0.0.1:8080 HTTP_PROXY=http://127.0.0.1:8080 ~/.local/bin/claude
```
