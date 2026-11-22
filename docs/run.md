# vibemaxxer run

`vibemaxxer run --rules FILE COMMAND` starts a proxy on a free loopback port,
runs the command with the proxy variables set, and exits with the command's
status. The proxy belongs to that one command: it comes up before the command
starts and is gone the moment it exits. There's nothing to install or keep
running.

## Usage

```sh
vibemaxxer run --rules client.rules curl https://example.com
vibemaxxer run --rules client.rules claude
codex() { vibemaxxer run --rules ~/.config/vibemaxxer/client.rules codex "$@"; }
```

The command gets `HTTP_PROXY`, `HTTPS_PROXY` and their lowercase forms set to
the proxy's address. `NO_PROXY`, `ALL_PROXY` and their lowercase forms are
removed, so old values can't send traffic around the proxy. That includes
traffic to your own machine, which the proxy connects to itself so that
[rules](rules.md#your-own-machine) like `block localhost 5432` apply.

Put `--` before a command whose name starts with `-`.

`run` takes the same routing options as `vibemaxxer client`. To send `proxy`
hosts through a server, add `--server` and `--server-key` for
[LAN TLS](lan.md), or `--upstream` for an [SSH forward](remote.md) you've
brought up yourself:

```sh
vibemaxxer run --rules client.rules --server 192.168.1.50:8443 --server-key SERVER_FINGERPRINT claude
vibemaxxer run --rules client.rules --upstream 127.0.0.1:19878 claude
```

## How the command runs

vibemaxxer stays in front of the command as its parent and tries to be
invisible there:

- The command inherits the terminal, standard streams and any other open file
  descriptors, and runs in the same process group.
- Ctrl-C, Ctrl-Z, `fg` and `bg` work as they do without the wrapper. When the
  command stops, vibemaxxer stops with it, and both continue together.
- `SIGTERM`, `SIGHUP`, `SIGUSR1` and `SIGUSR2` sent to vibemaxxer are passed
  on. So are `SIGINT` and `SIGQUIT`, unless vibemaxxer is in the terminal's
  foreground, where the terminal already delivers them to the command.
- The exit status is the command's. If a signal killed the command,
  vibemaxxer ends the same way where it can, and exits with 128 plus the
  signal number otherwise.
- If vibemaxxer itself is killed, the command gets `SIGTERM`.

Anything the command leaves running after it exits loses its proxy and fails
its requests, since the proxy variables still point at the closed port.

## Nested runs

A `vibemaxxer run` started from inside another one checks whether the outer
proxy is still up and was started with the same rules and routing options. If
so it skips starting a proxy and replaces itself with the command, which then
uses the outer proxy. If the rules differ, or the outer proxy is gone, it
starts its own.

So a tool can wrap the programs it launches in the same `vibemaxxer run` line
and still share one proxy and one log.

## Log

Requests are logged to `~/.local/state/vibemaxxer/run.log`, or under
`$XDG_STATE_HOME` if that's set. `--log FILE` picks another file. Every run
appends to the same file, and each line carries the run's process ID and
command name:

```text
time=... level=INFO msg=request pid=4242 command=claude method=CONNECT host=api.anthropic.com port=443 action=direct rule=default status=200 duration=1.2s
```

When the file is larger than 10 MiB at the start of a run, it's renamed to
`run.log.1` first, replacing the previous one.

## App notes

- Codex needs 0.154.0 or newer. Older versions ignore the proxy for
  WebSockets.
- OpenCode's background service needs the proxy variables set with
  `opencode service set env`, and it outlives the command, so point it at a
  long-running `vibemaxxer client` instead.
