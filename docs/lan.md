# LAN setup

This is for when the client can reach the server directly, usually on the
same network. The two connect over TLS 1.3, and each checks the other's key
against a fingerprint you pinned. There's no CA, SSH or frp involved.

```text
app -> client 127.0.0.1:8080 -> mutual TLS -> server 192.168.1.50:8443 -> internet
```

## 1. Exchange fingerprints

Run this on both machines:

```sh
vibemaxxer key
```

It creates `~/.config/vibemaxxer/identity.pem` if there isn't one yet and
prints the machine's fingerprint. Give each fingerprint to the other machine
over a channel you trust. Fingerprints are public, but the PEM file is the
private key, so keep that one to yourself.

If you'd rather keep the key somewhere else, pass `--key FILE` here and to the
client or server later.

## 2. Start the server

On the machine traffic should leave from, write a `server.rules` with `allow`
rules and run:

```sh
vibemaxxer server --tls --listen 192.168.1.50:8443 \
  --client-key CLIENT_FINGERPRINT --rules server.rules
```

`--listen` needs to be a real address like the machine's LAN IP, not a
wildcard like `0.0.0.0`. Repeat `--client-key` for every client you want to
let in. The server rejects unknown keys during the TLS handshake, before it
reads any HTTP.

## 3. Start the client

Write a `client.rules` with `proxy` rules and run:

```sh
vibemaxxer client --rules client.rules \
  --server 192.168.1.50:8443 --server-key SERVER_FINGERPRINT
```

If the server's key doesn't match or the server is down, proxied requests
fail. They never fall back to plaintext or to a direct connection.

## Revoking and rotating keys

To revoke a client, drop its `--client-key` and restart the server. To rotate
a key, delete the identity file, run `vibemaxxer key` again, and update the
fingerprint on the other side.
