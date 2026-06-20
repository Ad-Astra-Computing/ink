/**
 * Public surface of the reference sender example.
 *
 * A consumer can lift any single module — identity, envelope, discovery,
 * transport — or use `sendIntent` to run the whole flow: resolve the
 * recipient inbox, build and sign an envelope, then POST it with an INK
 * Authorization header.
 */

export * from "./identity.ts";
export * from "./envelope.ts";
export * from "./discovery.ts";
export * from "./transport.ts";

import type { SenderIdentity } from "./identity.ts";
import { buildSignedEnvelope } from "./envelope.ts";
import { resolveInboxEndpoint, type DiscoveryError } from "./discovery.ts";
import { deliverEnvelope, type DeliverResult } from "./transport.ts";

export interface SendIntentInput {
  identity: SenderIdentity;
  recipientDid: string;
  intent: string;
  payload: Record<string, unknown>;
  /** Explicit inbox endpoint; required for did:key recipients. */
  endpoint?: string;
  protocol?: "ink/0.1" | "ink/0.2";
  fetchImpl?: typeof fetch;
  allowPrivateHosts?: boolean;
  now?: () => Date;
  newId?: () => string;
}

export type SendIntentResult =
  | { ok: false; stage: "discovery"; reason: DiscoveryError }
  | ({ stage: "delivery" } & DeliverResult);

/**
 * End-to-end: discover the inbox, build + sign the envelope, deliver it.
 * Returns the discovery failure as-is, or the delivery result tagged with
 * its stage so a caller can tell a routing problem from a transport one.
 */
export async function sendIntent(input: SendIntentInput): Promise<SendIntentResult> {
  const resolution = await resolveInboxEndpoint({
    recipientDid: input.recipientDid,
    explicitEndpoint: input.endpoint,
    fetchImpl: input.fetchImpl,
    allowPrivateHosts: input.allowPrivateHosts,
  });
  if (!resolution.ok) {
    return { ok: false, stage: "discovery", reason: resolution.reason };
  }

  const envelope = await buildSignedEnvelope({
    identity: input.identity,
    to: input.recipientDid,
    intent: input.intent,
    payload: input.payload,
    protocol: input.protocol,
    now: input.now,
    newId: input.newId,
  });

  const delivery = await deliverEnvelope({
    identity: input.identity,
    targetUrl: resolution.endpoint,
    recipientDid: input.recipientDid,
    envelope: envelope as unknown as Record<string, unknown>,
    fetchImpl: input.fetchImpl,
    now: input.now,
    allowPrivateHosts: input.allowPrivateHosts,
  });
  return { stage: "delivery", ...delivery };
}
