# vibemaxxer run

`vibemaxxer run COMMAND` starts the proxy, runs the command with the proxy
variables set, and stops the proxy when the last command using it exits.
It needs a systemd user session. You don't need any of this if you'd rather
run `vibemaxxer client` yourself.

Create two user units:

```ini
# ~/.config/systemd/user/vibemaxxer.target
[Unit]
StopWhenUnneeded=yes
Wants=vibemaxxer-client.service
```

```ini
# ~/.config/systemd/user/vibemaxxer-client.service
[Unit]
PartOf=vibemaxxer.target
StopWhenUnneeded=yes

[Service]
ExecStart=/usr/bin/vibemaxxer client --rules %h/.config/vibemaxxer/client.rules
Restart=on-failure
```

Run `systemctl --user daemon-reload` and leave the units disabled. Then:

```sh
vibemaxxer run curl https://example.com
vibemaxxer run claude
codex() { vibemaxxer run codex "$@"; }
```

The command gets its own scope and keeps its arguments, terminal, signals
and exit code. Several commands can share one proxy. If the proxy doesn't
come up within 20 seconds, the command isn't started. Use `--` before
a command whose name begins with `-`.

If you change the rules or `ExecStart` while the client is running, restart
the client to apply them.

To route remotely, put `--upstream` or `--server` in `ExecStart`. With LAN
TLS that's all you need. With SSH, also install the
[tunnel units](remote.md#on-demand) and use `vibemaxxer run --remote`, which
starts the tunnel as well and waits for it.

## App notes

- **Claude Code** works with the proxy variables. If you log in with
  `claude setup-token`, export `CLAUDE_CODE_OAUTH_TOKEN` and set
  `hasCompletedOnboarding` to `true` in `~/.claude.json` to skip the login
  screen.
- **Codex** needs 0.154.0 or newer. Older versions ignore the proxy for
  WebSockets.
- **OpenCode**'s background service needs the variables set through
  `opencode service set env`.
- **Cursor CLI** and **pi** work with the proxy variables, but some provider
  settings can bypass them.
