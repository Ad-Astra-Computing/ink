// Public entry point for the @adastracomputing/ink package.
// Re-exports the stable surface so consumers can import from the package root.

// Crypto: signing, verification, key encoding
export {
  signInkMessage,
  verifyInkSignature,
  buildSignatureBase,
  buildAuthHeader,
  computeMessageHash,
  computeEventHash,
  computeAuditMerkleLeafHash,
  signAuditEvent,
  verifyAuditEventSignature,
  signAuditResponse,
  verifyAuditResponseSignature,
  verifyAuditEventChain,
  signAuditQueryResponse,
  verifyAuditQueryResponseSignature,
  encryptInkPayload,
  decryptInkPayload,
  checkReplay,
  base64urlEncode,
  base64urlDecode,
  hexToBytes,
  bytesToHex,
  jcsCanonicalize,
  MAX_TIMESTAMP_AGE_MS,
  MAX_FUTURE_TIMESTAMP_MS,
} from "./crypto/ink.js";
export { signMessage, verifyMessage } from "./crypto/sign.js";
export { verifyInkSignatureWithKeys } from "./crypto/multi-key-verify.js";
export {
  generateKeypair,
  generateEncryptionKeypair,
  deriveAgentId,
  encodePublicKeyMultibase,
  encodeEncryptionKeyMultibase,
  decodePublicKeyMultibase,
  decodeEncryptionKeyMultibase,
  extractPublicKeyFromAgentId,
} from "./crypto/keys.js";

// Discovery: Agent Card fetch + candidate-key extraction
export {
  fetchAgentCard,
  extractCandidateKeys,
  resolveBaseUrl,
} from "./discovery/agent-card.js";

// Middleware: transport-level INK auth
export { verifyInkAuth, type NonceStore } from "./middleware/ink-auth.js";

// Audit: inclusion-receipt + audit-query-response verification
export {
  verifyInclusionReceipt,
  verifyAuditQueryResponse,
  type InclusionReceipt,
  type InclusionReceiptVerifyResult,
  type AuditQueryResponse,
  type AuditQueryResponseVerifyResult,
  type VerifyStep,
} from "./audit/inclusion-receipt.js";

// Optional containment / governance primitives
export { HandshakeBudgetTracker } from "./ink/handshake-budget.js";

// Receipts: build and send INK delivery receipts
export {
  buildReceipt,
  shouldSendReceipt,
  sendReceiptFireAndForget,
} from "./ink/receipts.js";

// Transport-auth: token-level transport allowlist for extension tokens
export {
  resolveEffectiveTransports,
  checkTransportAllowed,
} from "./ink/transport-auth.js";

// Discovery-gating: visibility-aware Agent Card redaction
export {
  buildRedactedCard,
  shouldRedactOnGet,
  AgentCardQuerySchema,
} from "./ink/discovery-gating.js";

// Checkpoint parsing for transparency-log signed checkpoints
export {
  parseCheckpoint,
  formatCheckpoint,
} from "./ink/checkpoint.js";
export type { CheckpointData } from "./ink/checkpoint.js";

// Audit event schemas + types for receipts, query, inclusion proofs
export {
  InkAuditEventTypeSchema,
  InkAuditEventSchema,
  InkAuditInclusionSchema,
  InkReceiptSchema,
  InkAuditQuerySchema,
  InkIntroductionReceiptSchema,
} from "./models/ink-audit.js";
export type {
  InkAuditEventType,
  InkAuditEvent,
  InkAuditInclusion,
  InkReceipt,
  InkAuditQuery,
  InkAuditResponse,
  InkIntroductionReceiptStatus,
} from "./models/ink-audit.js";

// Handshake message schemas
export {
  InkChallengeSchema,
  InkRejectionSchema,
  InkResolutionSchema,
} from "./models/ink-handshake.js";
export type {
  AgentCardVisibility,
} from "./models/ink-handshake.js";

// Agent Card schema (the canonical .well-known/ink/agent.json document)
export { AgentCardSchema } from "./models/agent-card.js";

// Envelope validation: full Zod-backed parse of the canonical
// MessageEnvelope shape. Adopters building receivers need this to
// reject malformed envelopes before signature verification; without
// it they have to re-implement the schema check or import from a
// non-public path.
export { validateMessage, MessageEnvelopeSchema } from "./models/intent.js";
export type { MessageEnvelope } from "./models/intent.js";

// Type re-exports
export type { InkSignInput } from "./crypto/ink.js";
export type { CandidateKey } from "./models/key-entry.js";
export { resolveAgentInbox } from "./models/agent-card.js";
export type { AgentCard } from "./models/agent-card.js";
export type {
  BudgetCheckResult,
  HandshakeBudgetConfig,
} from "./ink/handshake-budget.js";
