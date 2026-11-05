# LAN setup

This is for when the client can reach the server directly, usually on the same
network. The two talk over TLS 1.3, and each side pins the other's public key.
No CA, SSH or frp is involved.

```text
app -> client 127.0.0.1:8080 -> mutual TLS -> server 192.168.1.50:8443 -> internet
```

## 1. Exchange keys

Run this on both machines:

```sh
vibemaxxer key
```

It creates `~/.config/vibemaxxer/identity.pem` if it doesn't exist yet and
prints the fingerprint. Swap fingerprints over a channel you trust. They're
public, but the PEM file isn't, so keep that one private. Use `--key FILE` to
store the identity somewhere else.

## 2. Start the server

On the machine traffic should leave from, write a `server.rules` with
`allow` rules and run:

```sh
vibemaxxer server --tls --listen 192.168.1.50:8443 \
  --client-key CLIENT_FINGERPRINT --rules server.rules
```

`--listen` has to be a specific address, not `0.0.0.0`. Repeat `--client-key`
for each machine you want to allow. Unknown keys are rejected before any HTTP
is read. It's still a good idea to firewall the port to your LAN.

## 3. Start the client

Write a `client.rules` with `proxy` rules and run:

```sh
vibemaxxer client --rules client.rules \
  --server 192.168.1.50:8443 --server-key SERVER_FINGERPRINT
```

If the key doesn't match or the server is down, proxied requests fail. They
never fall back to plaintext or to a direct connection.

## Notes

- Traffic leaves through the server's normal network. To exit through a VPN,
  set the VPN and its kill switch up on that machine yourself.
- To revoke a client, drop its `--client-key` and restart the server. To
  rotate a key, make a new identity file and update the pin on the other
  side.
- For on-demand use, add `--server` and `--server-key` to the client unit in
  [vibemaxxer run](run.md). Keep the server running under your usual service
  manager.
