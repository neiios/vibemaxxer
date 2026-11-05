# Claude Code via a LAN machine

This example blocks Claude Code's telemetry and sends traffic for Anthropic
and Claude domains through another machine on your network. Everything else
goes out directly. The server allows only those domains, and only on port
443.

[LAN setup](../../docs/lan.md) explains how the key pinning works.

## On both machines

From the repo root:

```sh
mkdir -p ~/.local/bin ~/.config/vibemaxxer
go build -o ~/.local/bin/vibemaxxer ./cmd/vibemaxxer
~/.local/bin/vibemaxxer key
```

Give each machine's fingerprint to the other.

## On the server

```sh
install -m644 examples/claude-lan/server.rules ~/.config/vibemaxxer/
vibemaxxer server --tls --listen 192.168.1.50:8443 \
  --client-key WORKSTATION_FINGERPRINT --rules ~/.config/vibemaxxer/server.rules
```

Replace `192.168.1.50` with the server's LAN address, and run this under your
service manager.

## On your workstation

```sh
install -m644 examples/claude-lan/client.rules ~/.config/vibemaxxer/
```

Create the systemd units from [vibemaxxer run](../../docs/run.md) with this
`ExecStart`:

```ini
ExecStart=%h/.local/bin/vibemaxxer client --rules %h/.config/vibemaxxer/client.rules --server 192.168.1.50:8443 --server-key SERVER_FINGERPRINT
```

Then start Claude through the wrapper:

```sh
examples/claude-lan/bin/claude
```

It's the same wrapper as in the [local example](../claude-local/#run).

If you don't use systemd, run `vibemaxxer client` with this `client.rules`
and the same `--server` and `--server-key` options, and set the proxy
variables like in the [quick start](../../README.md#quick-start).
