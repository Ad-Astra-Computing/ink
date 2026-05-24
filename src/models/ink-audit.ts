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
  id: z.string(),
  version: z.literal("ink-audit/1"),
  agentId: z.string(),
  agentSignature: z.string(),
  sequence: z.number().int().positive(),
  previousEventHash: z.string().nullable(),
  eventType: InkAuditEventTypeSchema,
  timestamp: z.string().datetime(),
  messageId: z.string().optional(),
  correlationId: z.string().optional(),
  counterpartyId: z.string().optional(),
  signingKeyId: z.string().optional(),
  data: z.record(z.unknown()).optional(),
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
  from: z.string(),
  to: z.string(),
  messageId: z.string(),
  disposition: InkReceiptDispositionSchema,
  dispositionAt: z.string().datetime(),
  note: z.string().max(500).optional(),
  messageHash: z.string(),
  nonce: z.string(),
  timestamp: z.string().datetime(),
  signature: z.string(),
});

export type InkReceipt = z.infer<typeof InkReceiptSchema>;

// ── Audit Query (INK Auditability §3) ──

export const InkAuditQuerySchema = z.object({
  protocol: z.literal("ink/0.1"),
  type: z.literal("network.tulpa.audit_query"),
  from: z.string(),
  to: z.string(),
  messageId: z.string(),
  nonce: z.string(),
  timestamp: z.string().datetime(),
});

export type InkAuditQuery = z.infer<typeof InkAuditQuerySchema>;

// ── Audit Response (INK Auditability §3) ──

export const InkAuditResponseSchema = z.object({
  protocol: z.literal("ink/0.1"),
  type: z.literal("network.tulpa.audit_response"),
  messageId: z.string(),
  events: z.array(InkAuditEventSchema),
  responseSignature: z.string(),
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
  eventId: z.string(),
  treeSize: z.number().int().positive(),
  leafIndex: z.number().int().min(0),
  rootHash: z.string(),
  timestamp: z.string().datetime(),
  serviceSignature: z.string(),
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
  id: z.string(),
  correlationId: z.string(),
  from: z.string(),
  to: z.string(),
  requesterDid: z.string(),
  introducerDid: z.string(),
  beneficiaryDid: z.string(),
  targetDid: z.string(),
  status: InkIntroductionReceiptStatusSchema,
  purpose: z.string().min(1).max(500),
  nonce: z.string(),
  timestamp: z.string().datetime(),
  relatedIntentId: z.string().optional(),
  relatedResolutionId: z.string().optional(),
  note: z.string().max(500).optional(),
  contextHash: z.string().optional(),
  authorizationChainRef: z.string().optional(),
  expiresAt: z.string().datetime().optional(),
});

export type InkIntroductionReceipt = z.infer<typeof InkIntroductionReceiptSchema>;
