import { z } from "zod";

// ── INK Audit Event Types (INK Auditability §2) ──

export const InkAuditEventTypeSchema = z.enum([
  // Message lifecycle
  "message.sent",
  "message.received",
  "message.queued",
  "message.delivered",
  "message.acted",
  "message.rejected",
  "message.expired",
  "message.retracted",
  // Receipt lifecycle
  "receipt.sent",
  "receipt.received",
  // Delegation
  "delegation.granted",
  "delegation.used",
  "delegation.revoked",
  "delegation.expired",
  // Connection
  "connection.requested",
  "connection.accepted",
  "connection.declined",
  // Verification
  "signature.verified",
  "signature.verified_retired",
  "signature.failed",
  "signature.revoked_rejected",
  "replay.detected",
  // Key lifecycle
  "key.rotated",
  "key.revoked",
  // Introduction lifecycle
  "introduction.requested",
  "introduction.approved",
  "introduction.declined",
  "introduction.forwarded",
  "introduction.completed",
  "introduction.expired",
  "introduction.receipt_sent",
  "introduction.receipt_received",
  // Enclave lifecycle
  "enclave.requested",
  "enclave.authorized",
  "enclave.opened",
  "enclave.operation_submitted",
  "enclave.resolved",
  "enclave.expired",
  "enclave.aborted",
  "enclave.receipt_sent",
  "enclave.receipt_received",
  // Containment (Phase 1)
  "transport_scope_violation",
  "handshake_rate_limited",
  "handshake_budget_exhausted",
  "discovery_query_received",
  "discovery_query_granted",
  "discovery_query_denied",
]);

export type InkAuditEventType = z.infer<typeof InkAuditEventTypeSchema>;

// ── INK Audit Event (hash-chained, signed) ──

export const InkAuditEventSchema = z.object({
  id: z.string().min(1).max(256),
  version: z.literal("ink-audit/1"),
  agentId: z.string().min(1).max(512),
  agentSignature: z.string().min(1).max(256),
  sequence: z.number().int().positive(),
  previousEventHash: z.string().regex(/^[0-9a-f]{64}$/).nullable(),
  eventType: InkAuditEventTypeSchema,
  timestamp: z.string().datetime(),
  messageId: z.string().min(1).max(256).optional(),
  correlationId: z.string().min(1).max(256).optional(),
  counterpartyId: z.string().min(1).max(512).optional(),
  signingKeyId: z.string().min(1).max(128).optional(),
  data: z.record(z.string(), z.unknown()).optional(),
});

export type InkAuditEvent = z.infer<typeof InkAuditEventSchema>;

// ── Receipt (INK Auditability §1) ──

export const InkReceiptDispositionSchema = z.enum([
  "received",
  "delivered",
  "acted",
  "rejected",
  "expired",
]);

export type InkReceiptDisposition = z.infer<typeof InkReceiptDispositionSchema>;

export const InkReceiptSchema = z.object({
  protocol: z.literal("ink/0.1"),
  type: z.literal("network.tulpa.receipt"),
  from: z.string().max(512),
  to: z.string().max(512),
  messageId: z.string().max(256),
  disposition: InkReceiptDispositionSchema,
  dispositionAt: z.string().datetime(),
  note: z.string().max(500).optional(),
  messageHash: z.string().max(256),
  nonce: z.string().max(256),
  timestamp: z.string().datetime(),
  signature: z.string().max(256),
});

export type InkReceipt = z.infer<typeof InkReceiptSchema>;

// ── Audit Query (INK Auditability §3) ──

export const InkAuditQuerySchema = z.object({
  protocol: z.literal("ink/0.1"),
  type: z.literal("network.tulpa.audit_query"),
  from: z.string().max(512),
  to: z.string().max(512),
  messageId: z.string().max(256),
  nonce: z.string().max(256),
  timestamp: z.string().datetime(),
});

export type InkAuditQuery = z.infer<typeof InkAuditQuerySchema>;

// ── Audit Response (INK Auditability §3) ──

export const InkAuditResponseSchema = z.object({
  protocol: z.literal("ink/0.1"),
  type: z.literal("network.tulpa.audit_response"),
  messageId: z.string().max(256),
  // Bound both the event count and (via InkAuditEventSchema's per-field caps)
  // each event, so an audit response from an untrusted witness cannot force
  // unbounded buffering. A single response that needs more than this should
  // page rather than return one giant array.
  events: z.array(InkAuditEventSchema).max(1000),
  responseSignature: z.string().max(256),
});

export type InkAuditResponse = z.infer<typeof InkAuditResponseSchema>;

// ── Third-Party Audit Submit (INK Auditability §7.2) ──

export const InkAuditSubmitSchema = z.object({
  protocol: z.literal("ink/0.1"),
  type: z.literal("network.tulpa.audit_submit"),
  from: z.string().max(256),
  to: z.string().max(256),
  event: InkAuditEventSchema,
  nonce: z.string().min(16).max(256),
  timestamp: z.string().datetime(),
});

export type InkAuditSubmit = z.infer<typeof InkAuditSubmitSchema>;

// ── Third-Party Audit Inclusion Receipt (INK Auditability §7.2) ──

export const InkAuditInclusionSchema = z.object({
  protocol: z.literal("ink/0.1"),
  type: z.literal("network.tulpa.audit_inclusion"),
  eventId: z.string().max(256),
  treeSize: z.number().int().positive(),
  leafIndex: z.number().int().min(0),
  rootHash: z.string().max(128),
  /** Optional Merkle inclusion proof — array of 64-character lowercase hex
   *  hash siblings on the path from the leaf to the root. Consumers that
   *  verify proofs (third-party auditor clients) read this field; consumers
   *  that only check signatures can ignore it. Bounds mirror the verifier's
   *  own input validation (`src/audit/inclusion-receipt.ts`): max 64 entries,
   *  each exactly 64 lowercase hex chars, so a malicious witness cannot
   *  force the parser to allocate megabytes of garbage proof data. */
  inclusionProof: z.array(z.string().regex(/^[0-9a-f]{64}$/)).max(64).optional(),
  timestamp: z.string().datetime(),
  serviceSignature: z.string().max(256),
});

export type InkAuditInclusion = z.infer<typeof InkAuditInclusionSchema>;

// ── Introduction Receipt (INK Introduction Receipts Extension §4) ──

export const InkIntroductionReceiptStatusSchema = z.enum([
  "approved",
  "declined",
  "forwarded",
  "completed",
  "expired",
]);

export type InkIntroductionReceiptStatus = z.infer<typeof InkIntroductionReceiptStatusSchema>;

export const InkIntroductionReceiptSchema = z.object({
  protocol: z.literal("ink/0.1"),
  type: z.literal("network.tulpa.introduction_receipt"),
  id: z.string().max(256),
  correlationId: z.string().max(256),
  from: z.string().max(512),
  to: z.string().max(512),
  requesterDid: z.string().max(512),
  introducerDid: z.string().max(512),
  beneficiaryDid: z.string().max(512),
  targetDid: z.string().max(512),
  status: InkIntroductionReceiptStatusSchema,
  purpose: z.string().min(1).max(500),
  nonce: z.string().max(256),
  timestamp: z.string().datetime(),
  relatedIntentId: z.string().max(256).optional(),
  relatedResolutionId: z.string().max(256).optional(),
  note: z.string().max(500).optional(),
  contextHash: z.string().max(256).optional(),
  authorizationChainRef: z.string().max(512).optional(),
  expiresAt: z.string().datetime().optional(),
});

export type InkIntroductionReceipt = z.infer<typeof InkIntroductionReceiptSchema>;
