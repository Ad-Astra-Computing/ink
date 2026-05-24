/**
 * Public-surface drift check. When something changes in this script,
 * the matching doc in ink-site MUST be updated in the same PR.
 */
import { InkAuditEventTypeSchema } from "../src/models/ink-audit.js";
import { KeyEntrySchema } from "../src/models/key-entry.js";

const DOCUMENTED_WIRE_TYPES = new Set<string>([
  "network.tulpa.intent",
  "network.tulpa.challenge",
  "network.tulpa.rejection",
  "network.tulpa.resolution",
  "network.tulpa.encrypted",
  "network.tulpa.receipt",
  "network.tulpa.audit_query",
  "network.tulpa.audit_response",
  "network.tulpa.audit_submit",
  "network.tulpa.audit_inclusion",
  "network.tulpa.introduction_receipt",
  "network.tulpa.agent_card_query",
  "network.tulpa.agent_card_response",
  "network.tulpa.agent_card_denied",
]);

const DOCUMENTED_AUDIT_EVENT_TYPES = new Set<string>([
  "message.sent", "message.received", "message.queued", "message.delivered",
  "message.acted", "message.rejected", "message.expired", "message.retracted",
  "receipt.sent", "receipt.received",
  "delegation.granted", "delegation.used", "delegation.revoked", "delegation.expired",
  "connection.requested", "connection.accepted", "connection.declined",
  "signature.verified", "signature.verified_retired",
  "signature.failed", "signature.revoked_rejected",
  "replay.detected",
  "key.rotated", "key.revoked",
  "introduction.requested", "introduction.approved", "introduction.declined",
  "introduction.forwarded", "introduction.completed", "introduction.expired",
  "introduction.receipt_sent", "introduction.receipt_received",
  "enclave.requested", "enclave.authorized", "enclave.opened",
  "enclave.operation_submitted", "enclave.resolved", "enclave.expired",
  "enclave.aborted", "enclave.receipt_sent", "enclave.receipt_received",
  "transport_scope_violation", "handshake_rate_limited",
  "handshake_budget_exhausted", "discovery_query_received",
  "discovery_query_granted", "discovery_query_denied",
]);

const DOCUMENTED_KEY_ENTRY_FIELDS = new Set<string>([
  "keyId",
  "algorithm",
  "publicKeyMultibase",
  "status",
  "validFrom",
  "validUntil",
  "revokedAt",
  "revokeReason",
]);

function diff<T>(label: string, documented: Set<T>, actual: Set<T>): string[] {
  const errors: string[] = [];
  const missing = [...documented].filter((x) => !actual.has(x));
  const added = [...actual].filter((x) => !documented.has(x));
  if (missing.length) {
    errors.push(`${label}: documented but absent from schema: ${JSON.stringify(missing)}`);
  }
  if (added.length) {
    errors.push(`${label}: present in schema but not documented: ${JSON.stringify(added)}`);
  }
  return errors;
}

const errors: string[] = [];

errors.push(
  ...diff("InkAuditEventType", DOCUMENTED_AUDIT_EVENT_TYPES, new Set(InkAuditEventTypeSchema.options)),
);

const keyEntryFields = new Set(Object.keys(KeyEntrySchema.shape));
errors.push(
  ...diff("KeyEntry schema fields", DOCUMENTED_KEY_ENTRY_FIELDS, keyEntryFields),
);

void DOCUMENTED_WIRE_TYPES;

if (errors.length) {
  console.error("Public surface drift detected:");
  for (const e of errors) console.error("  -", e);
  console.error("");
  console.error("Update scripts/check-public-surface.ts AND the matching ink-site/* doc.");
  process.exit(1);
}

console.log("Public surface OK.");
