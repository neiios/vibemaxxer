# Rules

The client and the server each read their own rules file. Each line holds one
rule, and `#` starts a comment.

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

## Matching

- `example.com` matches only that name. `.example.com` matches it and every
  subdomain, but not `badexample.com`. `*` matches everything.
- `block` and `deny` always win, wherever they appear. Otherwise the first
  matching `proxy` or `allow` applies.
- `allow` checks the port too. `proxy` ignores it and leaves that to the
  server.
- Matching ignores case and a trailing dot. Names must be ASCII, so write
  international domains in punycode (`xn--...`).

A bad rules file stops the process at startup. Restart to pick up changes.
Open tunnels keep running until they close. A client with `proxy` rules
refuses to start until you give it `--upstream` or `--server`.

## What gets refused anyway

Both modes refuse IP-literal destinations, so apps have to use hostnames.

Hostnames are checked again after DNS, against the address actually dialed.
That address can never be loopback, link-local (including cloud metadata),
multicast, `0.0.0.0/8` or `fd00:ec2::/32`. Private, CGNAT and the machine's
own networks are also refused unless you pass `--allow-private`, which is handy
on a server that has to reach private services.

Proxied names are resolved on the server, never on the client. Blocked names
are never resolved at all.

## Responses

Every refusal comes with an [RFC 9209](https://www.rfc-editor.org/rfc/rfc9209)
`Proxy-Status` header that says which side refused and why:

| Status | Meaning |
| --- | --- |
| 400 | Malformed request |
| 403 | Blocked, denied, or a forbidden address |
| 502 | DNS failure or unreachable destination/upstream |
| 503 | Too many connections (128 at once) |
| 504 | Timed out (10 s to the destination, 30 s to the upstream) |

Once a tunnel is open, any failure just closes it. Nothing is retried.

Each request writes one log line with the host, port, action, matching rule,
status and duration. Paths, headers and bodies are never logged.
