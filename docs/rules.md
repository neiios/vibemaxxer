# Rules

The client and the server each have their own rules file. One rule per line,
and `#` starts a comment.

```text
# client.rules
block .telemetry.example    # never connect
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
# anything else is denied
```

## How matching works

- `example.com` matches only that name. `.example.com` matches it and every
  subdomain, but not `badexample.com`. `*` matches everything.
- A matching `block` or `deny` rule always applies, wherever it is in the
  file. Otherwise the first matching `proxy` or `allow` rule applies.
- `allow` checks the port too. Leave the port list off and it allows 443
  only. `proxy` doesn't look at the port, since the server does that.
- Matching ignores case and a trailing dot. Names have to be ASCII, so write
  international domains in punycode (`xn--...`).

vibemaxxer only reads the rules when it starts, so restart it after you change
them. If there's a mistake in the file, it tells you the line and exits. And a
client with `proxy` rules won't start until you give it `--upstream` or
`--server`.

## What's always refused

Both sides refuse IP literals, so programs have to connect by hostname.

After DNS, vibemaxxer checks the address it's about to dial. It always refuses
loopback, link-local, multicast, `0.0.0.0/8` and `fd00:ec2::/32`. That covers
the cloud metadata addresses, `169.254.169.254` and AWS's `fd00:ec2::254`.

It also refuses private ranges, CGNAT and the machine's own networks, unless
you pass `--allow-private`. That's useful on a server that has to reach
internal services.

## Responses and logs

Every refusal comes with an [RFC 9209](https://www.rfc-editor.org/rfc/rfc9209)
`Proxy-Status` header that says which side refused and why. Connections to a
destination time out after 10 seconds, and connections to the upstream after
30. When 128 connections are already open, new ones get a 503.

Each request gets one log line: method, host, port, action, the rule that
matched, status and duration. Paths, headers and bodies never show up in the
log.
