# Claude Code via a LAN machine

This blocks Claude Code's telemetry and sends Claude's API traffic through
another machine on your network. Everything else goes out directly. The
server only allows Claude's domains on port 443.

See [LAN setup](../../docs/lan.md) for how the TLS pinning works.

## Both machines

From the repo root:

```sh
mkdir -p ~/.local/bin ~/.config/vibemaxxer
go build -o ~/.local/bin/vibemaxxer ./cmd/vibemaxxer
~/.local/bin/vibemaxxer key
```

Swap the printed fingerprints.

## Server

```sh
install -m644 examples/claude-lan/server.rules ~/.config/vibemaxxer/
vibemaxxer server --tls --listen 192.168.1.50:8443 \
  --client-key WORKSTATION_FINGERPRINT --rules ~/.config/vibemaxxer/server.rules
```

Use the machine's real LAN address, and keep it running under your service
manager.

## Workstation

```sh
install -m644 examples/claude-lan/client.rules ~/.config/vibemaxxer/
```

Create the systemd units from [vibemaxxer run](../../docs/run.md), using this
`ExecStart`:

```ini
ExecStart=%h/.local/bin/vibemaxxer client --rules %h/.config/vibemaxxer/client.rules --server 192.168.1.50:8443 --server-key SERVER_FINGERPRINT
```

Then:

```sh
examples/claude-lan/bin/claude
```

The wrapper behaves the same as in the [local example](../claude-local/#run).

## Without systemd

```sh
vibemaxxer client --rules examples/claude-lan/client.rules \
  --server 192.168.1.50:8443 --server-key SERVER_FINGERPRINT
```

and in another terminal:

```sh
HTTPS_PROXY=http://127.0.0.1:8080 HTTP_PROXY=http://127.0.0.1:8080 ~/.local/bin/claude
```
