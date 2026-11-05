# SSH and frp setup

Use this when the client and server are on different networks, say a laptop
at home and a VM somewhere else. vibemaxxer doesn't handle any of the
networking here. It relies on tools that already do it well:

- **OpenSSH** encrypts the hop and authenticates both ends.
- **[frp](https://gofrp.org) XTCP** punches through NAT, so neither side has
  to accept inbound connections. A small public coordinator helps the two
  sides find each other but never relays traffic.

If the VM's SSH port is reachable directly, skip frp and SSH to it directly.

```text
app -> client :8080 -> ssh forward :18080 === frp xtcp ===> sshd -> server :8081 -> internet
```

The examples below use `frp.example.net` as the coordinator. Pin your frp and
OpenSSH versions, and check these options against them.

## Coordinator

frps can't be trusted much: frpc doesn't check its certificate by default,
and the login token can be replayed. So give it a fixed certificate and pin
that on both sides:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
  -subj /CN=frp.example.net -addext subjectAltName=DNS:frp.example.net \
  -addext extendedKeyUsage=serverAuth -keyout frps.key -out frps.crt
```

```toml
# frps.toml
bindPort = 7000
auth.token = "COORDINATOR_TOKEN"
transport.tls.force = true
transport.tls.certFile = "/etc/frp/frps.crt"
transport.tls.keyFile = "/etc/frp/frps.key"
```

Copy `frps.crt` (not the key) to both machines. Open only `bindPort` in the
firewall, because anyone with the token can ask frps to bind ports. Running
frps without `CAP_NET_BIND_SERVICE` and with `IPAddressDeny=localhost` also
keeps it away from localhost services if it ever gets compromised.

frp needs a STUN server that supports RFC 5780. Google's and Cloudflare's
don't. `stun.nextcloud.com:3478` does. You can test one with
`frpc nathole discover --nat_hole_stun_server HOST:PORT`.

## VM

```toml
# frpc.toml
serverAddr = "frp.example.net"
serverPort = 7000
auth.token = "COORDINATOR_TOKEN"
transport.tls.trustedCaFile = "/etc/vibemaxxer/frps.crt"
natHoleStunServer = "stun.nextcloud.com:3478"

[[proxies]]
name = "vm-ssh"
type = "xtcp"
secretKey = "XTCP_SECRET"
localIP = "127.0.0.1"
localPort = 22
```

Create a `proxy-tunnel` user, authorize your home key for it, and lock it down
so the only thing it can do is reach the vibemaxxer server:

```sshconfig
Match User proxy-tunnel
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    AllowTcpForwarding local
    PermitOpen 127.0.0.1:8081
    AllowStreamLocalForwarding no
    MaxSessions 0
    PermitTTY no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
```

Check it with `sshd -t` and `sshd -T -C user=proxy-tunnel`, and keep an admin
session open while you do. Then run these two under systemd:
`vibemaxxer server --rules /etc/vibemaxxer/server.rules` and `frpc`.

## Home

```toml
# frpc.toml
serverAddr = "frp.example.net"
serverPort = 7000
auth.token = "COORDINATOR_TOKEN"
transport.tls.trustedCaFile = "/home/me/.config/vibemaxxer/frps.crt"
natHoleStunServer = "stun.nextcloud.com:3478"

[[visitors]]
name = "vm-ssh-visitor"
type = "xtcp"
serverName = "vm-ssh"
secretKey = "XTCP_SECRET"
bindAddr = "127.0.0.1"
bindPort = 2222
# no fallbackTo: if hole punching fails, requests fail instead of relaying
```

Add the VM's real host key to `known_hosts` under the alias `vm-proxy`. Get it
from somewhere you trust, never by accepting it over the tunnel. Then add:

```sshconfig
Host vm-proxy-tunnel
    HostName 127.0.0.1
    Port 2222
    User proxy-tunnel
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    HostKeyAlias vm-proxy
    StrictHostKeyChecking yes
    BatchMode yes
    LocalForward 127.0.0.1:18080 127.0.0.1:8081
    ExitOnForwardFailure yes
    ServerAliveInterval 30
    ServerAliveCountMax 3
```

Now run `frpc`, `ssh -N vm-proxy-tunnel` and the client:

```sh
vibemaxxer client --rules client.rules --upstream 127.0.0.1:18080
```

If the tunnel drops, only proxied requests fail and direct traffic keeps
working. Don't start frpc from a shell with the proxy variables set, because
it honors them.

## On demand

To have `vibemaxxer run --remote` bring the tunnel up and down for you, set up
the units from [vibemaxxer run](run.md), add `--upstream 127.0.0.1:18080` to
the client's `ExecStart`, and add:

```ini
# ~/.config/systemd/user/vibemaxxer-remote.target
[Unit]
StopWhenUnneeded=yes
Wants=vibemaxxer.target vibemaxxer-frpc.service vibemaxxer-ssh.service
```

```ini
# ~/.config/systemd/user/vibemaxxer-frpc.service
[Unit]
PartOf=vibemaxxer-remote.target
StopWhenUnneeded=yes

[Service]
ExecStart=/usr/bin/frpc -c %h/.config/vibemaxxer/frpc.toml
Restart=on-failure
RestartSec=1
```

```ini
# ~/.config/systemd/user/vibemaxxer-ssh.service
[Unit]
PartOf=vibemaxxer-remote.target
StopWhenUnneeded=yes
After=vibemaxxer-frpc.service
StartLimitIntervalSec=0

[Service]
ExecStart=/usr/bin/ssh -N vm-proxy-tunnel
Restart=always
RestartSec=1
```

```sh
vibemaxxer run --remote claude
```

The tunnel stays up while any `--remote` command is running. Commands run
without `--remote` still share the client, but their proxied requests fail
if the tunnel happens to be down.

## What each side can see

SSH encrypts everything between home and the VM. The coordinator and the
STUN server see addresses and timing, never contents. A malicious
coordinator can break the rendezvous, but it can't read or redirect the
tunnel. And because the server enforces its own `allow` rules, a compromised
local process can only reach what you've allowed.
