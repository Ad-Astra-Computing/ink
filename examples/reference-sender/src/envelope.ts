/**
 * Envelope construction.
 *
 * Builds a canonical INK message envelope, attaches the domain-separated
 * body-level signature, then validates the result with the package's own
 * `validateMessage` so a malformed envelope can never leave the process.
 *
 * Two signatures ride on an INK request and they are NOT the same thing:
 *
 *   1. The body-level `signature` field (this module). It commits to the
 *      canonical envelope fields via `signMessage` and travels inside the
 *      JSON. It is what proves the envelope content was authored by the
 *      `from` key, independent of transport.
 *   2. The transport Authorization header (see `transport.ts`). It signs
 *      `{ method, path, recipientDid, body, timestamp }` per INK §3.3 and
 *      binds the request to one endpoint, freshness window, and nonce.
 *
 * The transport signature is computed over the FULL envelope including the
 * body `signature` field, so the body signature must be attached first.
 *
 * `timestamp` and `nonce` live alongside the canonical fields because the
 * receiver's `verifyInkAuth` reads them from the body for the §3.3
 * freshness and replay checks. The envelope schema does not reject them.
 */

import { signMessage, validateMessage, type MessageEnvelope } from "@adastracomputing/ink";
import type { SenderIdentity } from "./identity.ts";

/** Intents a first-contact-friendly receiver typically accepts. */
export type FirstContactIntent = "connection_request" | "intro_request" | "ping" | "ask";

export interface BuildEnvelopeInput {
  identity: SenderIdentity;
  /** Recipient DID. Goes in `to`. */
  to: string;
  intent: string;
  /** Intent-specific payload. Validated against the intent's schema. */
  payload: Record<string, unknown>;
  /** Protocol version literal. Selects the body-signature domain. */
  protocol?: "ink/0.1" | "ink/0.2";
  /** Injectable clock for deterministic tests. */
  now?: () => Date;
  /** Injectable id factory for deterministic tests. */
  newId?: () => string;
}

function defaultId(): string {
  return crypto.randomUUID();
}

/**
 * Build a fully signed, schema-valid envelope.
 *
 * Throws (via `validateMessage`) if the assembled envelope or its payload
 * does not satisfy the package schemas — the example never emits an
 * envelope it would itself reject.
 */
export async function buildSignedEnvelope(input: BuildEnvelopeInput): Promise<MessageEnvelope> {
  const now = input.now ? input.now() : new Date();
  const newId = input.newId ?? defaultId;
  const createdAt = now.toISOString();

  // Canonical fields plus the §3.3 freshness/replay fields. No `signature`
  // yet — the body signature is computed over exactly these fields.
  const unsigned: Record<string, unknown> = {
    protocol: input.protocol ?? "ink/0.1",
    id: newId(),
    correlationId: newId(),
    createdAt,
    from: input.identity.did,
    to: input.to,
    intent: input.intent,
    payload: input.payload,
    timestamp: createdAt,
    nonce: newId(),
  };

  const signature = await signMessage(unsigned, input.identity.privateKey);
  const envelope = { ...unsigned, signature };

  // Guarantee the envelope and its payload satisfy the package schemas.
  // This throws on any drift, so the sender fails before the network.
  return validateMessage(envelope);
}

/** Default `ping` payload — minimal liveness poke. */
export function pingPayload(note?: string): Record<string, unknown> {
  return note ? { note } : {};
}

/**
 * Default `connection_request` payload — the foreign first-contact intent.
 * `profileSnapshot` is the minimal shape the payload schema requires:
 * a headline plus the (possibly empty) skills, interests, and openTo
 * arrays.
 */
export function connectionRequestPayload(opts: {
  context: string;
  headline: string;
  skills?: string[];
  interests?: string[];
  openTo?: string[];
  method?: "qr" | "intro" | "discovery" | "import";
}): Record<string, unknown> {
  return {
    method: opts.method ?? "discovery",
    context: opts.context,
    profileSnapshot: {
      headline: opts.headline,
      skills: opts.skills ?? [],
      interests: opts.interests ?? [],
      openTo: opts.openTo ?? [],
    },
  };
}
