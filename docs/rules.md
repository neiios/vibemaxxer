# Rules

The client and the server each have their own rules file. One rule per line,
and `#` starts a comment.

```text
# client.rules
block .telemetry.example    # never connect
block localhost 5432,6379   # keep local databases off limits
proxy .anthropic.com        # send through the server
proxy api.openai.com
# anything else goes direct
```

```text
# server.rules
allow .anthropic.com        # port 443 by default
allow api.openai.com 443
allow .internal.example 80,443
deny  admin.internal.example
private .internal.example   # may resolve to private addresses
# anything else is denied
```

## How matching works

- `example.com` matches only that name. `.example.com` matches it and every
  subdomain, but not `badexample.com`. `*` matches everything.
- A matching `block` or `deny` rule always applies, wherever it is in the
  file. Otherwise the first matching `proxy` or `allow` rule applies.
- `allow` checks the port too. Leave the port list off and it allows 443
  only. `block` and `deny` take an optional port list and match every port
  without one. `proxy` doesn't look at the port, since the server does that.
- `private` doesn't allow or block anything. It lets names it matches reach
  private addresses, which are otherwise refused (see below). It works the
  same in both files.
- Matching ignores case and a trailing dot. Names have to be ASCII, so write
  international domains in punycode (`xn--...`).

vibemaxxer only reads the rules when it starts, so restart it after you change
them. If there's a mistake in the file, it tells you the line and exits. And a
client with `proxy` rules won't start until you give it `--upstream` or
`--server`.

## Your own machine

The client connects to services on your own machine itself, so rules can cover
them. `localhost`, its subdomains, `127.0.0.0/8` and `::1` are all the same
destination, and rules match them all as `localhost`. `block localhost 5432`
refuses `localhost:5432`, `app.localhost:5432`, `127.0.0.1:5432` and
`[::1]:5432` alike, and `block localhost` refuses all of them. Anything else
on your machine is allowed.

The client never looks these names up in DNS. Names are tried on `127.0.0.1`
and then `::1`, and addresses are used as written. Loopback never goes through
the server, even with `proxy *`, and the server never connects to its own
loopback, so only `block` and `deny` rules can name `localhost`.

This only works for programs that send local traffic through the proxy.
`vibemaxxer run` removes `NO_PROXY` so they do, but anything written in Go and
most browsers still connect to loopback directly.

## What's always refused

Both sides refuse IP literals other than loopback, so programs have to connect
by hostname.

After DNS, vibemaxxer checks the address it's about to dial. It always refuses
loopback, link-local, multicast, `0.0.0.0/8`, `fd00:ec2::/32` and the
machine's own addresses. That covers the cloud metadata addresses,
`169.254.169.254` and AWS's `fd00:ec2::254`, and names that resolve to your
own machine.

It also refuses private ranges, CGNAT and the networks the machine is on,
unless the name matches a `private` rule. Names you haven't listed can't
reach your router or the rest of your LAN, whatever their DNS says.
`private *` lifts this for every name.

## Responses and logs

Every refusal comes with an [RFC 9209](https://www.rfc-editor.org/rfc/rfc9209)
`Proxy-Status` header that says which side refused and why. Connections to a
destination time out after 10 seconds, and connections to the upstream after
30. When 128 connections are already open, new ones get a 503.

Each request gets one log line: method, host, port, action, the rule that
matched, status and duration. Paths, headers and bodies never show up in the
log.
