import { z } from "zod";
import { dualWireType } from "./wire-type.js";
import { AgentCardVisibilitySchema } from "./ink-handshake.js";
import { isInkTimestamp } from "../crypto/timestamp.js";
import { isWithinBounds, signMessage, verifyMessage } from "../crypto/sign.js";

// Caps mirror the DID/agent-id bound used across INK payloads and the discovery
// descriptor's tag constraints (#188), so a query cannot express more than a
// card's descriptor advertises.
const ID_MAX = 512;
const NONCE_MIN = 16;
const NONCE_MAX = 256;
const TAG_MAX_LEN = 64;
const TAGS_MAX = 32;
const LIMIT_MAX = 100;

// The bounded set of facts a requester may ask a directory to match on. It
// reuses the discovery descriptor's scope enum and tag shape so a query can
// never request a scope or tag form a card could not have advertised. It
// carries no ranking, response, consent, or field-release semantics: those are
// the directory's responsibility and are deliberately out of scope here.
export const DiscoveryQuerySchema = z
  .object({
    tags: z.array(z.string().min(1).max(TAG_MAX_LEN)).min(1).max(TAGS_MAX).optional(),
    scope: AgentCardVisibilitySchema.optional(),
    limit: z.number().int().min(1).max(LIMIT_MAX).optional(),
  })
  .strict();

export type DiscoveryQuery = z.infer<typeof DiscoveryQuerySchema>;

// A requester-signed request to look up discoverable agents at a directory. The
// signature covers every field except `signature` itself (protocol, type, from,
// to, nonce, timestamp, query), so a directory can bind the request to the
// requester's key and reject replay or tampering. The wire `type` accepts the
// vendor-neutral network.ink spelling alongside the legacy network.tulpa one.
export const DiscoveryQueryEnvelopeSchema = z
  .object({
    protocol: z.literal("ink/0.1"),
    type: dualWireType("discovery_query"),
    from: z.string().min(1).max(ID_MAX),
    to: z.string().min(1).max(ID_MAX),
    nonce: z.string().min(NONCE_MIN).max(NONCE_MAX),
    timestamp: z.string().refine(isInkTimestamp, { message: "invalid INK timestamp" }),
    query: DiscoveryQuerySchema,
    signature: z.string().min(1),
  })
  .strict();

export type DiscoveryQueryEnvelope = z.infer<typeof DiscoveryQueryEnvelopeSchema>;

const UnsignedDiscoveryQueryEnvelopeSchema = DiscoveryQueryEnvelopeSchema.omit({ signature: true });

export interface DiscoveryQueryInput {
  /** Defaults to the legacy `network.tulpa.discovery_query` spelling. */
  type?: "network.tulpa.discovery_query" | "network.ink.discovery_query";
  from: string;
  to: string;
  nonce: string;
  timestamp: string;
  query: DiscoveryQuery;
}

// Build a signed discovery query envelope. The unsigned envelope is validated
// before signing, so a malformed query is rejected at build time rather than
// producing a signature over an out-of-profile request.
export async function buildDiscoveryQueryEnvelope(
  input: DiscoveryQueryInput,
  privateKey: Uint8Array,
): Promise<DiscoveryQueryEnvelope> {
  const unsigned = {
    protocol: "ink/0.1" as const,
    type: input.type ?? ("network.tulpa.discovery_query" as const),
    from: input.from,
    to: input.to,
    nonce: input.nonce,
    timestamp: input.timestamp,
    query: input.query,
  };
  UnsignedDiscoveryQueryEnvelopeSchema.parse(unsigned);
  const signature = await signMessage(unsigned, privateKey);
  return { ...unsigned, signature };
}

// Verify a discovery query envelope against the requester's public key. The key
// is caller-supplied: resolving `from` to a key is the directory's job. Returns
// false (fails closed) on a structural violation or a bad signature, and never
// throws. Freshness and replay windows are directory policy and are not checked
// here.
export async function verifyDiscoveryQueryEnvelope(
  raw: unknown,
  requesterPublicKey: Uint8Array,
): Promise<boolean> {
  // Fail closed on anything, including a hostile object whose getters or proxy
  // traps throw during bounds checking or parsing.
  try {
    if (!isWithinBounds(raw)) {
      return false;
    }
    const parsed = DiscoveryQueryEnvelopeSchema.safeParse(raw);
    if (!parsed.success) {
      return false;
    }
    return await verifyMessage(parsed.data, requesterPublicKey);
  } catch {
    return false;
  }
}
