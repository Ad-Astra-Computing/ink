/**
 * Transport-bound authorization for INK delegation chains.
 *
 * Ensures delegation tokens are only valid on the transports they were
 * issued for. Implements §7 of the INK Containment spec with version-gated
 * migration for legacy tokens.
 */

import type { InkTransport } from "../models/ink-handshake.js";

/**
 * Permissive transport set for legacy tokens during the 90-day migration window.
 * Matches the set of transports that existed before transport scoping was introduced.
 */
export const LEGACY_MIGRATION_TRANSPORTS: InkTransport[] = [
  "ink_http",
  "extension_api",
  "voice",
  "line_phone",
];

/**
 * Hard deadline for the legacy transport migration window.
 * After this date, tokens without tokenVersion get the strict default.
 */
export const LEGACY_MIGRATION_DEADLINE = new Date("2026-07-01T00:00:00Z");

/**
 * Resolve the effective allowed transports for a delegation token.
 *
 * Rules (per spec §1.2):
 * - Explicit allowedTransports always wins
 * - v0.3+ tokens without allowedTransports default to ["ink_http"]
 * - Legacy tokens (no tokenVersion) default to permissive set before the
 *   migration deadline (2026-07-01), then ["ink_http"] after
 */
export function resolveEffectiveTransports(
  allowedTransports: InkTransport[] | undefined,
  tokenVersion: string | undefined,
  now: Date = new Date(),
): InkTransport[] {
  // Distinguish "field absent" from "field present and empty". An
  // explicit empty array is a "this token allows no transports"
  // statement — it MUST stay empty, never fall through to the legacy
  // permissive set. Treating [] as "absent" would broaden a token that
  // its issuer intended to deny.
  if (Array.isArray(allowedTransports)) {
    return [...allowedTransports];
  }

  // v0.3+ token without explicit transports: strict default.
  // Distinguish "field absent" (undefined) from "field present but
  // malformed/empty". A token that supplies `tokenVersion: ""` is not
  // a legacy token — it is a malformed new token. Treat anything
  // present-and-not-undefined as a new token so a bad version string
  // can't broaden transport scope during the migration window.
  if (tokenVersion !== undefined) {
    return ["ink_http"];
  }

  // Legacy token (tokenVersion truly absent): check against hard
  // migration deadline.
  if (now >= LEGACY_MIGRATION_DEADLINE) {
    return ["ink_http"];
  }
  return [...LEGACY_MIGRATION_TRANSPORTS];
}

/**
 * Check if the current invocation transport is allowed by the delegation token.
 */
export function checkTransportAllowed(
  currentTransport: InkTransport,
  allowedTransports: InkTransport[],
): { allowed: true } | { allowed: false; reason: "transport_scope_violation" } {
  if (allowedTransports.includes(currentTransport)) {
    return { allowed: true };
  }
  return { allowed: false, reason: "transport_scope_violation" };
}

/**
 * Check that a child delegation hop's transports are a subset of the parent's.
 * Each hop can only narrow, never widen the transport scope.
 */
export function checkTransportAttenuation(
  parentTransports: InkTransport[],
  childTransports: InkTransport[],
): { valid: true } | { valid: false; addedTransports: InkTransport[] } {
  const parentSet = new Set(parentTransports);
  const added = childTransports.filter((t) => !parentSet.has(t));
  if (added.length > 0) {
    return { valid: false, addedTransports: added };
  }
  return { valid: true };
}
