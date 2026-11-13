# vibemaxxer run

`vibemaxxer run COMMAND` starts the proxy, runs the command with the proxy
variables set, and stops the proxy again once the last command using it
exits. It needs a systemd user session. If you'd rather run
`vibemaxxer client` yourself, you can skip this page.

## Setup

1. Create the target:

   ```ini
   # ~/.config/systemd/user/vibemaxxer.target
   [Unit]
   StopWhenUnneeded=yes
   Wants=vibemaxxer-client.service
   ```

2. Create the client service:

   ```ini
   # ~/.config/systemd/user/vibemaxxer-client.service
   [Unit]
   PartOf=vibemaxxer.target
   StopWhenUnneeded=yes

   [Service]
   ExecStart=/usr/bin/vibemaxxer client --rules %h/.config/vibemaxxer/client.rules
   Restart=on-failure
   ```

3. Run `systemctl --user daemon-reload`. Leave both units disabled.
   `vibemaxxer run` starts them when something needs them.

## Usage

```sh
vibemaxxer run curl https://example.com
vibemaxxer run claude
codex() { vibemaxxer run codex "$@"; }
```

The command gets `HTTP_PROXY`, `HTTPS_PROXY` and their lowercase forms set to
`http://127.0.0.1:9878`. `NO_PROXY`, `ALL_PROXY` and their lowercase forms are
removed, so old values can't send traffic around the proxy. That includes
traffic to your own machine, which the client connects to itself so that
[rules](rules.md#your-own-machine) like `block localhost 5432` apply.

Each command runs in its own systemd scope, and any number of them can share
one client. If the client isn't up after 20 seconds, `vibemaxxer run` gives
up and doesn't start the command. Put `--` before a command whose name starts
with `-`.

To route `proxy` hosts through a server, add `--upstream` or `--server` to
`ExecStart`. For LAN TLS that's all there is to it. For SSH, also install the
[tunnel units](remote.md#on-demand) and use `vibemaxxer run --remote`, which
brings the tunnel up as well and waits for it.

## App notes

- Codex needs 0.154.0 or newer. Older versions ignore the proxy for
  WebSockets.
- OpenCode's background service needs the proxy variables set with
  `opencode service set env`.
