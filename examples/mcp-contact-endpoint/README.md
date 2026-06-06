# INK Contact Endpoint (design note + sketch)

A publicly addressable INK receiver that forwards verified, signed envelopes to a
human inbox. It is the same shape as [`examples/reference-receiver/`](../reference-receiver/),
the only difference is the terminal action: instead of returning a JSON
acknowledgement, it emails the message to a monitored address (for example
`hello@example.com`). It is meant to sit alongside a service such as an MCP
server so other agents have a real INK address to reach a human.

This directory is a **sketch plus design note**, not a wired, tested service.
The load-bearing decisions and the distinctive code are here; the shared
plumbing (`keys.ts`, `agent-card.ts`, `nonce-store.ts`, `did-web-resolver.ts`,
`audit-log.ts`) is identical to `reference-receiver` and should be lifted from
there verbatim.

## The four decisions

### 1. Publish a real DID and bind to it

The endpoint has its own DID, for example `did:web:mcp.example.com`. Serve a
DID document at `/.well-known/did.json` carrying an `INKAgentEndpoint` service
entry that points at the Agent Card, and serve the card with the signing keys.

This is not ceremony. The transport-auth signature base is

```
ink/<version>\n<METHOD>\n<PATH>\n<recipientDid>\n<JCS(body)>\n<timestamp>
```

so `recipientDid` is part of what the sender signed. Accepting `to = "any"`
discards recipient binding and lets a signature minted for one endpoint be
replayed at another. The endpoint therefore **rejects any envelope whose signed
`recipientDid` is not its own DID**. `did:web` is the least-friction choice for
a service (no PLC registration).

### 2. Reject encryption in v1

A public contact endpoint only ever handles first-contact intents
(`connection_request`, `intro_request`, `ask`). These are cold-open intents: a
stranger introducing themselves, asking for an introduction, or asking a
one-off question — none of which carry anything an unrelated party needs kept
secret, so they are plaintext by design. The intents INK requires encryption for
(`schedule_meeting`, `context_share`, `multi_party_sync`) only happen between
already-connected agents and never reach a cold contact endpoint. So v1:

- Publishes **no `keys.encryption`** set in its Agent Card, so a conformant
  sender knows up front that encryption is unsupported.
- Detects a `network.tulpa.encrypted` envelope on the **raw** object before
  schema validation (an encrypted envelope has a different shape and would
  otherwise fail `validateMessage` with a generic error) and returns a clear
  `encryption_not_supported`. Unsupported intents are rejected the same way. The
  capability signal in the card is the clean path; the runtime reject is the
  backstop.

### 3. Rate limit per IP and per DID

Both, because each covers the other's blind spot:

- **Per IP alone over-blocks.** Many legitimate agents share an egress IP
  (Cloudflare Workers, model-provider infra), so one IP can carry hundreds of
  honest DIDs.
- **Per DID alone is defeated trivially.** `did:key` is free to mint, so an
  attacker rotates a fresh `did:key` per request and sails under any per-DID cap.

Per-DID catches one identity abusing across many IPs; per-IP is the backstop
against DID rotation from a single source. Two refinements: gate
`connection_request` (the spam vector) harder than established senders, and
return **typed rejections with a `Retry-After` hint** rather than a bare 429, as
the [agent containment extension](../../specs/ink-agent-containment-and-governance-extension-spec.md)
specifies for handshake flood resistance.

### 4. Forward email labels verified vs claimed

The envelope `from` (agent DID) and its signature are verified. Everything the
sender writes into the payload is self-asserted and unverified. The forwarded
email keeps these separate:

- **Verified:** the agent DID, that the signature is valid, and
  `provenance.origin` (`human` / `agent_approved` / `agent_autonomous`) so the
  reader knows whether a human approved the message.
- **Claimed:** the sender's `profileSnapshot` (headline, skills, openTo) and the
  free-text `context`, explicitly marked unverified. INK carries no human name or
  email in a first-contact payload — so a contact endpoint has nothing verified
  to address a person by, which is the point: identity is the DID, not a name.
- The email's `Reply-To` is **never** a sender-supplied address. Any such address
  would be spoofable, and a one-click reply would send your response to an
  attacker-chosen inbox. Respond by accepting the connection through INK until a
  relationship is established.

## Receiver checklist (the boring MUSTs)

Inherited from the [compliance checklist](../../specs/ink-compliance-checklist.md);
do not skip them. The sketch satisfies each by delegating to the OSS package and
the lifted reference-receiver helpers rather than re-implementing crypto:

- Read the body under a hard byte cap before parsing (`readBoundedBody`).
- Validate envelope **and** payload with `validateMessage(raw)` before any
  signature work — never canonicalize clearly-invalid input.
- Resolve the sender's rotation-aware key set (`resolveSenderKeys` →
  `CandidateKey[]`), then call `verifyInkAuth({ ..., resolveKeySet, nonceStore })`,
  which verifies **both** the transport-auth header and the body signature, plus
  the `nonce` store and the timestamp window (5 minutes past, 30 seconds future),
  and selects the body-signature domain from the signed `protocol` field
  (`ink/0.1` / `ink/0.2`).
- Confirm `auth.senderAgentId` matches the envelope `from` (reject a forged
  `from`), and bind `recipientDid` to our DID (decision 1).
- `did:web` sender resolution runs behind the discovery SSRF guards (the
  reference receiver's `resolveSenderKeys`); a `did:web` host must be a real
  hostname, not an IP literal in any encoding.

## Files

| File | Status |
|------|--------|
| `src/inbound.ts` | Sketch. The verify-then-forward flow with the four decisions inline. |
| `src/forward-email.ts` | Sketch. Composes the forwarded email with verified-vs-claimed labeling. |
| `src/rate-limit.ts` | Sketch. The dual per-IP and per-DID limiter. |
| `keys.ts`, `agent-card.ts`, `nonce-store.ts`, `did-web-resolver.ts`, `audit-log.ts` | Lift from `../reference-receiver/` unchanged. |
