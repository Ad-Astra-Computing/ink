# INK private-hostname classification

This document pins the host-safety decision an implementation makes before
fetching from a hostname: is the hostname a public destination, or a loopback,
private, link-local, IANA special-use, or malformed IP-shaped name that must not
be fetched? It is the SSRF gate applied to a base URL and to URL-shaped fields
inside a fetched Agent Card. It is verified by the `private-hostname`
conformance category.

## Scope

The decision is a pure function of a hostname string: `accept` means the
hostname is a public destination; `reject` means it is private, special-use, or
a malformed IP literal that must fail closed. Only the hostname is classified.
Scheme, userinfo, port, percent escapes, and the choice of URL parser are out of
scope; those belong to the endpoint URL grammar and the discovery fetch
contract. This separation keeps the classifier free of the `new URL` vs Go
`net/url` parser differential.

This is a static-literal classifier. It does NOT defend against DNS rebinding: a
public hostname that resolves to a private address at connect time still
requires connect-time IP pinning at the platform layer.

## Normalization

1. Lowercase the hostname.
2. Strip trailing dots (the FQDN root form), so `localhost.` cannot bypass.
3. An empty result rejects.
4. `localhost` and any `*.localhost` name rejects.
5. A bracketed IPv6 literal `[...]` has its brackets removed for classification.

## IPv4

A dotted-quad of four 1-3 digit decimal octets is classified. If any octet
exceeds 255 the name is a malformed IP literal and rejects (fail closed rather
than read `8.8.8.999` as a public host). Otherwise it rejects when it falls in
any block of the IANA Special-Purpose IPv4 Address Registry: `0.0.0.0/8`,
`10/8`, `100.64/10`, `127/8`, `169.254/16`, `172.16/12`, `192.0.0/24`,
`192.0.2/24`, `192.31.196/24`, `192.52.193/24`, `192.88.99/24`, `192.168/16`,
`192.175.48/24`, `198.18/15`, `198.51.100/24`, `203.0.113/24`, and `224/4` and
above. A single all-digits form (for example `2130706433`) rejects.

## IPv6

An IPv6 literal is expanded into eight 16-bit groups with a string-level
expander (no platform IP parser, so the decision is identical across runtimes).
A malformed literal rejects: more than one `::`, the wrong number of groups, a
non-hex group, or a leading or trailing single colon. A zone or scope id (a `%`
anywhere) rejects rather than being stripped, since a zone suffix is not a
routable public destination and stripping it would let a public literal bypass
the gate.

An expanded address rejects when it is `::`/`::1`, `fe80::/10`, `fc00::/7`,
`ff00::/8`, the special blocks within `2001::/16` (Teredo `2001::/32`, BMWG
`2001:2::/48`, ORCHID `2001:10::/28` and `2001:20::/28`, documentation
`2001:db8::/32`), NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, discard `100::/64`
and `100:0:0:1::/64`, BMWG `3fff::/20`, or SRv6 `5f00::/16`. An IPv4-mapped
address (`::ffff:a.b.c.d` in dotted or hex form) is classified by its embedded
IPv4. A 6to4 address (`2002::/16`) is classified by its embedded IPv4, so a 6to4
address tunnelling to a private IPv4 rejects.
