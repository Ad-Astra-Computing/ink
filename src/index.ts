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
export { parseInkTimestampMs, isInkTimestamp, MAX_TIMESTAMP_LENGTH } from "./crypto/timestamp.js";
export { containsLoneSurrogateEscape, hasUnpairedSurrogate } from "./crypto/surrogate.js";
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
  canonicalAgentPrincipal,
  AGENT_ID_KEY_PREFIXES,
} from "./crypto/keys.js";

// Discovery: Agent Card fetch + candidate-key extraction
export {
  fetchAgentCard,
  extractCandidateKeys,
  resolveBaseUrl,
  isPrivateHostname,
} from "./discovery/agent-card.js";
export { evaluateAgentCardFetch, MAX_AGENT_CARD_BYTES } from "./discovery/agent-card-fetch.js";
export type { AgentCardFetchInput, AgentCardFetchResult } from "./discovery/agent-card-fetch.js";

// Middleware: transport-level INK auth
export { verifyInkAuth, type NonceStore } from "./middleware/ink-auth.js";

// Audit: inclusion-receipt + audit-query-response verification
export {
  verifyInclusionReceipt,
  verifyInclusionProof,
  verifyConsistencyProof,
  verifyAuditQueryResponse,
  type InclusionReceipt,
  type InclusionReceiptVerifyResult,
  type AuditQueryResponse,
  type AuditQueryResponseVerifyResult,
  type VerifyStep,
} from "./audit/inclusion-receipt.js";

// Optional containment / governance primitives
export { HandshakeBudgetTracker } from "./ink/handshake-budget.js";

// Receipts: build, verify, and send INK delivery receipts
export {
  buildReceipt,
  verifyReceipt,
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

// Checkpoint parsing and signature verification for transparency-log checkpoints
export {
  parseCheckpoint,
  formatCheckpoint,
  verifyCheckpoint,
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
  InkTransportSchema,
} from "./models/ink-handshake.js";
export type {
  AgentCardVisibility,
  InkChallenge,
  InkRejection,
  InkResolution,
  InkTransport,
} from "./models/ink-handshake.js";

// Agent Card schema (the canonical .well-known/ink/agent.json document)
export { AgentCardSchema } from "./models/agent-card.js";
export { isInkEndpointUrl } from "./models/endpoint-url.js";

// Envelope validation: full Zod-backed parse of the canonical
// MessageEnvelope shape. Adopters building receivers need this to
// reject malformed envelopes before signature verification; without
// it they have to re-implement the schema check or import from a
// non-public path.
export {
  validateMessage,
  getPayloadSchema,
  MessageEnvelopeSchema,
  ProtocolVersionSchema,
  INK_PROTOCOL_VERSIONS,
  IntentTypeSchema,
  ScheduleMeetingPayloadSchema,
  ScheduleMeetingResponsePayloadSchema,
  IntroRequestPayloadSchema,
  IntroResponsePayloadSchema,
  OpportunityPayloadSchema,
  OpportunityResponsePayloadSchema,
  ConnectionRequestPayloadSchema,
  ConnectionResponsePayloadSchema,
  FollowUpPayloadSchema,
  AskPayloadSchema,
  AskResponsePayloadSchema,
  PingPayloadSchema,
  RetractPayloadSchema,
  ContextSharePayloadSchema,
  MultiPartySyncPayloadSchema,
} from "./models/intent.js";
export type {
  MessageEnvelope,
  ProtocolVersion,
  IntentType,
} from "./models/intent.js";

// Key-entry types and schemas for adopters wiring their own key-set
// storage and rotation. `CandidateKey` was already root-exported via
// the verifier surface; this batch adds the persistence shapes.
export {
  KeyStatusSchema,
  KeyRoleSchema,
  KeyEntrySchema,
} from "./models/key-entry.js";
export type {
  KeyStatus,
  KeyRole,
  KeyEntry,
  StoredKey,
} from "./models/key-entry.js";

// Type re-exports
export type { InkSignInput } from "./crypto/ink.js";
export type { CandidateKey } from "./models/key-entry.js";
export { resolveAgentInbox, agentSupportedProtocolVersions, isDiscoverable, effectiveDiscoveryScope, DiscoveryDescriptorSchema } from "./models/agent-card.js";
export type { AgentCard, DiscoveryDescriptor } from "./models/agent-card.js";

// Authenticated discovery query envelope (#200): a requester-signed request a
// directory can verify. Protocol primitive only; no directory service here.
export {
  DiscoveryQuerySchema,
  DiscoveryQueryEnvelopeSchema,
  buildDiscoveryQueryEnvelope,
  verifyDiscoveryQueryEnvelope,
} from "./models/discovery-query.js";
export type { DiscoveryQuery, DiscoveryQueryEnvelope, DiscoveryQueryInput } from "./models/discovery-query.js";
export type {
  BudgetCheckResult,
  HandshakeBudgetConfig,
} from "./ink/handshake-budget.js";
