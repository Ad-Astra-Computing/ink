import type { AgentCard } from "../models/agent-card.js";
import { AgentCardSchema } from "../models/agent-card.js";

/**
 * Agent Card discovery fetch contract.
 *
 * The retrieval of an Agent Card from `GET <base>/ink/v1/<agentId>/agent.json`
 * has a security- and interop-relevant response contract that, before this
 * module, lived only inside the TypeScript `fetchAgentCard` and so could differ
 * across runtimes. This pure evaluator pins the RESPONSE-handling decision (the
 * part a second implementation must reproduce) so it is verified by the shared
 * `agent-card-fetch` conformance category in both implementations.
 *
 * It does NOT cover the request-side SSRF gate (https-only base URL, private
 * host rejection, URL construction) or the card-content endpoint host checks:
 * those depend on a hostname classifier the Go implementation does not yet
 * share, and stay in `fetchAgentCard`'s transport hardening. See
 * specs/ink-agent-card-discovery-fetch.md.
 */

/** Maximum Agent Card body, by Content-Length and by actual decoded bytes. */
export const MAX_AGENT_CARD_BYTES = 64 * 1024;

export interface AgentCardFetchInput {
  /** HTTP status of the discovery response. */
  status: number;
  /** Raw Content-Type header value, or null when absent. */
  contentType: string | null;
  /** Raw Content-Length header value, or null when absent. */
  contentLength: string | null;
  /** The response body as a string (already decoded from UTF-8 bytes). */
  bodyRaw: string;
  /** The agentId the fetch was made for, for identity binding. */
  requestedAgentId: string;
  /**
   * The owner's DID, set only when the resolution began at an owner's DID
   * document and followed it to this card. Null (or absent) for every other
   * resolution, including one that reached the card through the agent's own
   * DID document. Drives the owner anti-substitution step: a host that
   * legitimately publishes a card for one owner must not be able to serve it
   * in answer to resolution of another. Passing an agent identifier here
   * rejects every card whose owner and agent differ.
   */
  resolutionDid?: string | null;
}

export interface AgentCardFetchResult {
  accepted: boolean;
  /** The validated card when accepted, else null. */
  card: AgentCard | null;
}

/** UTF-8 byte length of a string, the unit the body cap is measured in. */
function utf8ByteLength(s: string): number {
  return new TextEncoder().encode(s).length;
}

/**
 * True when a Content-Length header declares a size over the cap. The
 * comparison is done on the digit string itself, not via a parsed integer, so
 * a value larger than any fixed-width integer type still classifies
 * identically across implementations (a `Number()` / `ParseInt` would diverge
 * on overflow). A non-canonical value (absent, non-digit) is not decided on
 * here; the actual body cap is authoritative.
 */
export function contentLengthExceedsCap(header: string | null): boolean {
  if (header === null) return false;
  const trimmed = header.trim();
  if (!/^\d+$/.test(trimmed)) return false;
  return digitsGreaterThan(trimmed, String(MAX_AGENT_CARD_BYTES));
}

/** Compare two ASCII decimal digit strings numerically without parsing them
 *  into a bounded integer. Both inputs are non-empty all-digit strings. */
function digitsGreaterThan(value: string, cap: string): boolean {
  let v = value.replace(/^0+/, "");
  if (v === "") v = "0";
  if (v.length !== cap.length) return v.length > cap.length;
  return v > cap;
}

/**
 * Decide whether a discovery response yields a valid Agent Card bound to the
 * requested agentId. Steps are ordered; the first failing step rejects.
 *
 *   1. status MUST be exactly 200.
 *   2. If Content-Length is a base-10 non-negative integer and exceeds the
 *      cap, reject. An absent or non-canonical value is not decided on here
 *      (the actual body cap in step 4 is authoritative).
 *   3. Content-Type MUST be present, single-valued (no comma), and its media
 *      type MUST be application/json (case-insensitive); a charset parameter,
 *      when present, MUST be utf-8.
 *   4. The body's UTF-8 byte length MUST NOT exceed the cap.
 *   5. The body MUST parse as JSON.
 *   6. The parsed value MUST satisfy AgentCardSchema.
 *   7. card.protocol MUST be "ink/0.1".
 *   8. card.agentId MUST equal the requested agentId (identity binding).
 *   9. When resolutionDid is non-null and the card carries an ownerDid,
 *      card.ownerDid MUST equal resolutionDid (owner anti-substitution).
 */
export function evaluateAgentCardFetch(input: AgentCardFetchInput): AgentCardFetchResult {
  const reject: AgentCardFetchResult = { accepted: false, card: null };

  // 1. Status.
  if (input.status !== 200) return reject;

  // 2. Declared length.
  if (contentLengthExceedsCap(input.contentLength)) return reject;

  // 3. Content-Type.
  if (!isJsonContentType(input.contentType)) return reject;

  // 4. Actual body size.
  if (utf8ByteLength(input.bodyRaw) > MAX_AGENT_CARD_BYTES) return reject;

  // 5. JSON parse.
  let parsed: unknown;
  try {
    parsed = JSON.parse(input.bodyRaw);
  } catch {
    return reject;
  }

  // 6. Schema.
  const result = AgentCardSchema.safeParse(parsed);
  if (!result.success) return reject;
  const card = result.data;

  // 7. Protocol literal (also enforced by the schema; explicit for the contract).
  if (card.protocol !== "ink/0.1") return reject;

  // 8. Identity binding.
  if (card.agentId !== input.requestedAgentId) return reject;

  // 9. Owner anti-substitution. Byte-for-byte, no canonicalization, and only
  // when the fetch was mediated by a DID and the card actually carries an
  // ownerDid. Passing proves the card names the DID it was reached through,
  // never that the owner consented to the agent: ownerDid is self-asserted.
  const resolutionDid = input.resolutionDid ?? null;
  if (resolutionDid !== null && card.ownerDid !== undefined && card.ownerDid !== resolutionDid) {
    return reject;
  }

  return { accepted: true, card };
}

/**
 * True when the header names exactly the application/json media type with no
 * ambiguity. Rejects absent, empty, a value carrying a comma (a combined or
 * duplicated header), a non-json media type, or a non-utf-8 charset parameter.
 */
function isJsonContentType(value: string | null): boolean {
  if (value === null) return false;
  const header = value.trim();
  if (header.length === 0) return false;
  // A comma means more than one Content-Type was sent (or combined by an
  // intermediary); the media type is then ambiguous, so reject.
  if (header.includes(",")) return false;

  const parts = header.split(";");
  const mediaType = (parts[0] ?? "").trim().toLowerCase();
  if (mediaType !== "application/json") return false;

  for (let i = 1; i < parts.length; i++) {
    const param = parts[i]!.trim();
    if (param.length === 0) continue;
    const eq = param.indexOf("=");
    if (eq === -1) continue;
    const name = param.slice(0, eq).trim().toLowerCase();
    if (name === "charset") {
      let charset = param.slice(eq + 1).trim().toLowerCase();
      if (charset.startsWith('"') && charset.endsWith('"') && charset.length >= 2) {
        charset = charset.slice(1, -1);
      }
      if (charset !== "utf-8") return false;
    }
  }
  return true;
}
