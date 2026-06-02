/**
 * did:web DID document.
 *
 * Minimal DID doc that resolves to the receiver's public key.
 * Served at `/.well-known/did.json` for the configured host. The
 * verificationMethod uses publicKeyMultibase per the
 * did-core 1.0 + did:key alignment that INK consumers already
 * implement.
 */

import type { ReceiverIdentity } from "./keys.js";

export interface DidDocConfig {
  did: string;
  host: string;
  identity: ReceiverIdentity;
}

export function buildDidDocument(cfg: DidDocConfig): unknown {
  const verificationMethodId = `${cfg.did}#signing-key`;
  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    id: cfg.did,
    verificationMethod: [
      {
        id: verificationMethodId,
        type: "Ed25519VerificationKey2020",
        controller: cfg.did,
        publicKeyMultibase: cfg.identity.publicKeyMultibase,
      },
    ],
    authentication: [verificationMethodId],
    assertionMethod: [verificationMethodId],
    service: [
      {
        id: `${cfg.did}#ink-inbox`,
        type: "InkAgentEndpoint",
        serviceEndpoint: `https://${cfg.host}/ink/v1/inbound`,
      },
      {
        id: `${cfg.did}#ink-agent-card`,
        type: "InkAgentCard",
        serviceEndpoint: `https://${cfg.host}/.well-known/ink/agent.json`,
      },
    ],
  };
}
