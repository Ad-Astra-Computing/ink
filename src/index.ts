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
  signAuditEvent,
  verifyAuditEventSignature,
  signAuditResponse,
  verifyAuditResponseSignature,
  verifyAuditEventChain,
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
  decodePublicKeyMultibase,
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

// Optional containment / governance primitives
export { HandshakeBudgetTracker } from "./ink/handshake-budget.js";

// Type re-exports
export type { InkSignInput } from "./crypto/ink.js";
export type { CandidateKey } from "./models/key-entry.js";
export type { AgentCard } from "./models/agent-card.js";
export type {
  BudgetCheckResult,
  HandshakeBudgetConfig,
} from "./ink/handshake-budget.js";
