# SSH and frp setup

This is for when the client and server are on different networks, like a
laptop at home and a VM in the cloud. vibemaxxer doesn't do any of this
networking itself. The client talks to the server through an SSH forward, and
[frp](https://gofrp.org) XTCP gets that SSH connection through NAT with UDP
hole punching, so neither side has to accept inbound connections. A public
coordinator, frps, only helps the two sides find each other. It never relays
traffic.

If you can reach the VM's SSH port directly, you don't need frp at all. Skip
the frp parts and put the VM's real address in the SSH config below.

```text
app -> client :8080 -> ssh forward :18080 === frp xtcp ===> sshd -> server :8081 -> internet
```

The examples below use `frp.example.net` as the coordinator.

## Coordinator

Don't trust frps more than you have to. Out of the box frpc doesn't verify the
frps certificate, and anyone who sees the login token can replay it. So give
frps a fixed certificate and have both frpc instances trust only that one:

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

Copy `frps.crt` to both machines. `frps.key` stays on the coordinator. Only
open `bindPort` in the firewall, since anyone with the token can ask frps to
open more.

frp needs a STUN server that supports RFC 5780. Google's and Cloudflare's
don't, `stun.nextcloud.com:3478` does. You can check one with
`frpc nathole discover --nat_hole_stun_server HOST:PORT`.

## VM

Configure frpc to expose the VM's SSH port through the coordinator:

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

Then create a `proxy-tunnel` user, add your home machine's public key to its
`authorized_keys`, and restrict the account in `/etc/ssh/sshd_config` so it
can only forward to the vibemaxxer server:

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

Check it with `sshd -t` and `sshd -T -C user=proxy-tunnel`, then reload sshd.
Finally, run `vibemaxxer server --rules /etc/vibemaxxer/server.rules` and
`frpc` as systemd services.

## Home

Configure frpc to bring the VM's SSH port to `127.0.0.1:2222`:

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
# Leave fallbackTo unset so requests fail instead of relaying through frps
```

Add the VM's host key to `~/.ssh/known_hosts` under the name `vm-proxy`. Get
it from somewhere you trust, like the VM's console, and never by accepting it
over the tunnel. With the host key pinned, a bad coordinator can stop you from
connecting, but it can't read or redirect anything. Then add this to
`~/.ssh/config`:

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

Now start `frpc`, `ssh -N vm-proxy-tunnel` and the client:

```sh
vibemaxxer client --rules client.rules --upstream 127.0.0.1:18080
```

If the tunnel drops, proxied requests fail and direct traffic keeps working.
Don't start frpc from a shell that has the proxy variables set, or it'll send
its own traffic through vibemaxxer.

## On demand

If you want `vibemaxxer run --remote` to bring the tunnel up and down for you,
set up the units from [vibemaxxer run](run.md), add `--upstream
127.0.0.1:18080` to the client's `ExecStart`, and create these three units:

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

Then run things with `--remote`:

```sh
vibemaxxer run --remote claude
```

The tunnel stays up as long as any `--remote` command is running. Commands
started without `--remote` still share the client, but their proxied requests
fail while the tunnel is down.
