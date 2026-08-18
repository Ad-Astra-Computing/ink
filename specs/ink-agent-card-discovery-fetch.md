# INK Agent Card discovery fetch contract

**Status:** Stable base-profile spec; formal 1.0 freeze pending governance sign-off (see [`../GOVERNANCE.md`](../GOVERNANCE.md), [`../governance/releases/1.0-readiness-evidence.md`](../governance/releases/1.0-readiness-evidence.md)).

This document pins the discovery path and the response-handling contract for
retrieving an Agent Card over HTTP, so the decision is identical across
implementations and does not drift with the runtime. It is verified by the
`agent-card-fetch` conformance category.

## Discovery path

An agent's Agent Card is served at:

```
GET <base>/ink/v1/<agentId>/agent.json
```

with the `agentId` percent-encoded as a single path segment. This is the sole
normative discovery surface of the base profile, and it is the one place the
path is stated; every other document cites this section rather than restating
it. An implementation MAY additionally serve the card at
`/.well-known/ink/agent.json` as an alias for the same document, but a resolver
MUST NOT depend on that alias and MUST NOT relax any rule below for it. A
profile that derives its own card URL states that derivation as a profile-local
exception and says so in its own text; the INK Agent Authorization profile is
the one such exception in this repository.

## Scope

An implementation retrieves an Agent Card at the path above and must decide
whether the response yields a usable card bound to the agentId it asked for.
That decision has a security and interoperability surface that, if left to each
runtime's HTTP stack, diverges: status handling, content-type negotiation,
body-size limits, and identity binding.

Beyond the path, this contract covers only the **response evaluation**. It
deliberately does not cover:

- The request-side SSRF gate (https-only base URL, rejection of loopback,
  private, link-local, and IANA special-use hosts, the mechanics of URL
  construction against a parsed base, redirect refusal at the transport layer).
  That hardening stays in the fetching implementation because it depends on a
  hostname classifier and a fetch override that a pure, runtime-agnostic
  verifier cannot provide; [`ink-resolver.md`](./ink-resolver.md) §3 pins the
  construction rules a resolver follows.
- The card-content endpoint host checks (rejecting an `endpoint` that points at
  a private host). Those depend on the same classifier and are out of scope
  until both implementations share it.

## Inputs

The decision is a pure function of synthetic response metadata:

| Field | Type | Meaning |
| --- | --- | --- |
| `status` | integer | HTTP status of the discovery response |
| `contentType` | string or null | raw `Content-Type` header, null when absent |
| `contentLength` | string or null | raw `Content-Length` header, null when absent |
| `bodyRaw` | string | response body, decoded from UTF-8 bytes |
| `requestedAgentId` | string | the agentId the fetch was made for |
| `resolutionDid` | string or null | the DID under resolution when the fetch was reached through a DID document, null otherwise |

## Decision

Evaluate in order. The first failing step rejects.

1. **Status.** Reject unless `status` is exactly `200`. Discovery is served at a
   fixed path; any other status, including other `2xx` and any redirect, is not
   a card.
2. **Declared length.** If `contentLength` is present and is a base-10
   non-negative integer greater than 65536, reject. An absent or non-canonical
   value (empty, non-numeric, fractional, negative) is not decided on here; the
   actual body cap in step 4 is authoritative.
3. **Content-Type.** Reject unless `contentType` is present and unambiguous.
   Trim optional whitespace; reject an empty value or one containing a comma (a
   combined or duplicated header). The media type before the first `;`, trimmed
   and lowercased, MUST be `application/json`. Parameters are allowed; if a
   `charset` parameter is present its value MUST be `utf-8` (case-insensitive,
   optionally quoted).
4. **Body size.** Reject if the UTF-8 byte length of `bodyRaw` exceeds 65536.
5. **JSON.** Reject unless `bodyRaw` parses as JSON.
6. **Schema.** Reject unless the parsed value satisfies the Agent Card schema
   (see [`ink-agent-card.md`](./ink-agent-card.md)).
7. **Protocol.** Reject unless `protocol` is `ink/0.1`.
8. **Identity binding.** Reject unless `agentId` equals `requestedAgentId`. A
   registry that returned a different agent's card would otherwise enable a
   key-confusion attack.
9. **Owner anti-substitution.** When `resolutionDid` is non-null and the card
   carries an `ownerDid`, reject unless `ownerDid` equals `resolutionDid`. Both
   comparisons in this step and step 8 are byte for byte, with no
   canonicalization (see [`ink-identity-model.md`](./ink-identity-model.md)
   §3.3). This closes the substitution attack where a host that legitimately
   publishes a card for one DID serves it in answer to resolution of another.
   It is not owner authentication: `ownerDid` is a self-asserted field
   ([`ink-identity-model.md`](./ink-identity-model.md) §2.4), and passing this
   step proves only that the card reached through a DID document names that
   same DID, never that the owner consented to the agent. A card without an
   `ownerDid`, or a fetch not mediated by a DID, passes this step unchanged.

   `resolutionDid` is the **owner's** DID, and only ever that: it is set when
   the resolution began at a DID document belonging to the owner and followed
   it to an agent's card. A resolver that begins at the agent's own identifier,
   which is the shape every resolver in this repository implements, MUST pass
   null. Passing the agent's DID here would compare an owner field against an
   agent identifier and reject every card whose owner and agent differ, which
   is the ordinary case. No resolver in this repository performs an
   owner-mediated resolution today, so this step is inert in-tree and is
   specified for the resolvers that will.

If every step passes, accept; the card is the parsed, schema-valid document.

## Notes

The body cap is enforced twice in a fetching implementation: by `Content-Length`
before reading (step 2) and by a streamed read that aborts past the cap so a
chunked response without a length cannot force unbounded buffering. The
conformance category exercises the same cap on the already-read body (step 4).
