# INK Agent Card discovery fetch contract

This document pins the response-handling contract for retrieving an Agent Card
over HTTP, so the decision is identical across implementations and does not
drift with the runtime. It is verified by the `agent-card-fetch` conformance
category.

## Scope

An implementation retrieves an Agent Card with `GET <base>/ink/v1/<agentId>/agent.json`
and must decide whether the response yields a usable card bound to the agentId
it asked for. That decision has a security and interoperability surface that, if
left to each runtime's HTTP stack, diverges: status handling, content-type
negotiation, body-size limits, and identity binding.

This contract covers only the **response evaluation**. It deliberately does not
cover:

- The request-side SSRF gate (https-only base URL, rejection of loopback,
  private, link-local, and IANA special-use hosts, URL construction, redirect
  refusal at the transport layer). That hardening stays in the fetching
  implementation because it depends on a hostname classifier and a fetch
  override that a pure, runtime-agnostic verifier cannot provide.
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

If every step passes, accept; the card is the parsed, schema-valid document.

## Notes

The body cap is enforced twice in a fetching implementation: by `Content-Length`
before reading (step 2) and by a streamed read that aborts past the cap so a
chunked response without a length cannot force unbounded buffering. The
conformance category exercises the same cap on the already-read body (step 4).
