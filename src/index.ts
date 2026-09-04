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
  verifyAuditEventSignatureWithKeys,
  signAuditResponse,
  verifyAuditResponseSignature,
  verifyAuditResponseSignatureWithKeys,
  verifyAuditEventChain,
  signAuditQueryResponse,
  verifyAuditQueryResponseSignature,
  verifyAuditQueryResponseSignatureWithKeys,
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
export { containsOutOfRangeNumberLiteral } from "./crypto/number-literal.js";
export { containsEscapedMemberName, hasUnsafeObjectKey } from "./crypto/member-name.js";
export { hasEscapedMemberNameDefect } from "./crypto/member-name-defect.js";
export {
  parseSignedBodyBytes,
  parseSignedBodyText,
  ParseSignedBodyError,
} from "./crypto/parse-signed-body.js";
export type { ParseSignedBodyReason } from "./crypto/parse-signed-body.js";
export {
  verifyInkSignatureWithKeys,
  verifyDetachedSignatureWithKeys,
  isKeyValidAtTime,
  type MultiKeyVerifyResult,
} from "./crypto/multi-key-verify.js";
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
export {
  verifyInkAuth,
  parseInkAuthHeader,
  INK_AUTH_HEADER_RE,
  type NonceStore,
  type InkAuthHeaderParse,
} from "./middleware/ink-auth.js";

// Audit: inclusion-receipt + audit-query-response verification
export {
  verifyInclusionReceipt,
  verifyInclusionReceiptWithKeys,
  verifyInclusionProof,
  verifyConsistencyProof,
  verifyAuditQueryResponse,
  type InclusionReceipt,
  type InclusionReceiptVerifyResult,
  type InclusionReceiptVerifyWithKeysResult,
  type AuditQueryResponse,
  type AuditQueryResponseVerifyResult,
  type VerifyStep,
} from "./audit/inclusion-receipt.js";

// Optional containment / governance primitives
export { HandshakeBudgetTracker } from "./ink/handshake-budget.js";

// Protocol §3.4 encryption requirement gate for plaintext intents
export {
  CONFIDENTIAL_INTENTS,
  intentRequiresEncryption,
  checkEncryptionRequired,
} from "./ink/encryption-policy.js";
export type {
  ConfidentialIntent,
  EncryptionRequirementResult,
  EncryptionRequirementOptions,
} from "./ink/encryption-policy.js";

// Receipts: build, verify, and send INK delivery receipts
export {
  buildReceipt,
  verifyReceipt,
  verifyReceiptWithKeys,
  shouldSendReceipt,
  sendReceiptFireAndForget,
  type VerifyReceiptWithKeysResult,
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
  verifyCheckpointWithKeys,
} from "./ink/checkpoint.js";
export type { CheckpointData, CheckpointVerifyWithKeysResult } from "./ink/checkpoint.js";

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

// Agent Card schema (the document served at /ink/v1/<agentId>/agent.json)
export { AgentCardSchema } from "./models/agent-card.js";
export { isInkEndpointUrl } from "./models/endpoint-url.js";

// Self-authenticating Agent Card (ink-agent-card-signature.md, Phase A). The
// OPTIONAL card proof and its rotation-chain schemas, the producer signing
// helpers, and the pure §5 verifier a receiver enforces.
export {
  CardSignatureSchema,
  RotationChainSigningEntrySchema,
  RotationChainLinkSchema,
  RotationChainSchema,
} from "./models/agent-card.js";
export type {
  CardSignature,
  RotationChainSigningEntry,
  RotationChainLink,
  RotationChain,
} from "./models/agent-card.js";
export {
  signAgentCard,
  signRotationLink,
  verifyAgentCardSignature,
  CARD_SIGNATURE_DOMAIN,
  CARD_ROTATION_DOMAIN,
} from "./crypto/agent-card-signature.js";
export type {
  AgentCardVerifyResult,
  AgentCardVerifyReason,
  AgentCardVerifyOptions,
  DidResolution,
} from "./crypto/agent-card-signature.js";

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
  MAX_DISCOVERY_QUERY_AGE_MS,
  MAX_DISCOVERY_QUERY_SKEW_MS,
  MAX_DISCOVERY_QUERY_BODY_BYTES,
} from "./models/discovery-query.js";
export type {
  DiscoveryQuery,
  DiscoveryQueryEnvelope,
  DiscoveryQueryInput,
  DiscoveryQueryKey,
  DiscoveryQueryReason,
  DiscoveryQueryVerifyContext,
  DiscoveryQueryVerifyResult,
} from "./models/discovery-query.js";

// Minimal authorization grant, the "Sign in with INK" primitive (#160). An
// issuer signs a scoped, audience-bound, expiring grant a subject presents to a
// service; the service verifies it fails-closed with typed rejection reasons.
// Not a permissions framework: no delegation chain or policy language.
export {
  AuthorizationGrantSchema,
  buildAuthorizationGrant,
  verifyAuthorizationGrant,
  AuthorizationGrantError,
  MAX_GRANT_LIFETIME_MS,
  MAX_GRANT_BODY_BYTES,
} from "./models/authorization-grant.js";
export type {
  AuthorizationGrant,
  AuthorizationGrantInput,
  AuthorizationGrantReason,
  AuthorizationGrantVerifyContext,
  AuthorizationGrantVerifyResult,
  GrantKey,
  VerifiedOwnerStatus,
} from "./models/authorization-grant.js";

// Attestation, the evidence primitive of ink-attestation.md: a signed claim by
// one principal about another, verified from raw bytes, judged only by
// receiver policy.
export {
  AttestationSchema,
  ClaimTypeSchema,
  EvidencePolicySchema,
  EvidenceRefusalSchema,
  buildAttestation,
  verifyAttestation,
  verifyAttestationWithKeys,
  parseEvidenceRefusal,
  MAX_ATTESTATION_BODY_BYTES,
} from "./models/attestation.js";
export type {
  Attestation,
  AttestationInput,
  AttestationVerifyContext,
  AttestationVerifyResult,
  AttestationVerifyWithKeysResult,
  EvidencePolicy,
  EvidenceRefusal,
  EvidenceRefusalParseResult,
} from "./models/attestation.js";

// INK Agent Authorization sign-in challenge (#198). The one artifact the flow
// profile adds on top of the grant: an RP signs a challenge to request sign-in,
// the user's agent verifies it against an active RP signing key before minting
// the grant that answers it, and the answering identity assertion adopts the
// grantId derived from the verified challenge.
export {
  AuthorizationChallengeSchema,
  buildAuthorizationChallenge,
  verifyAuthorizationChallenge,
  deriveChallengeGrantId,
  deriveRpOrigin,
  isChallengeRedirect,
  AuthorizationChallengeError,
  CHALLENGE_SCOPE_REGISTRY,
  MAX_CHALLENGE_LIFETIME_MS,
  MAX_CHALLENGE_BODY_BYTES,
} from "./models/authorization-challenge.js";
export type {
  AuthorizationChallenge,
  AuthorizationChallengeInput,
  AuthorizationChallengeReason,
  AuthorizationChallengeVerifyContext,
  AuthorizationChallengeVerifyResult,
} from "./models/authorization-challenge.js";
// Authorization chain, the post-1.0 delegation extension on top of the grant.
// A linear chain of 2 to 4 delegation links, each the grant field model plus a
// parent hash, each hop narrowing the last, so a service can verify a presenter
// holds authority tracing back through bounded re-delegations to an origin it
// roots. The verifier fails closed with the same typed reasons the grant uses,
// plus `chain` and `attenuation`.
export {
  AuthorizationChainSchema,
  buildDelegationLink,
  buildAuthorizationChain,
  verifyAuthorizationChain,
  deriveDelegationParentHash,
  AuthorizationChainError,
  INTERMEDIATE_LINK_MAX_LIFETIME_MS,
  FINAL_LINK_MAX_LIFETIME_MS,
  MAX_CHAIN_BODY_BYTES,
  DELEGATION_EXTEND_SCOPE,
} from "./models/authorization-chain.js";
export type {
  AuthorizationChain,
  DelegationLink,
  DelegationLinkInput,
  AuthorizationChainReason,
  ChainIssuerKey,
  AuthorizationChainVerifyContext,
  AuthorizationChainVerifyResult,
} from "./models/authorization-chain.js";

export type {
  BudgetCheckResult,
  HandshakeBudgetConfig,
} from "./ink/handshake-budget.js";
