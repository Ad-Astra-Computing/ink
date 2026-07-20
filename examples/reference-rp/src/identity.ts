/**
 * Principals and key resolution.
 *
 * The relying party (RP) and the user's agent are both ordinary INK principals.
 * Under the INK Agent Authorization profile the RP MUST be a bare-host `did:web`
 * identifier, because the origin derived from it gates redirect acceptance
 * before any signature runs. The user's agent may be any principal the RP can
 * resolve to a signing key; this example makes it a bare-host `did:web` too, so
 * the same resolution path serves both.
 *
 * In production the user's agent resolves the RP's Agent Card over the network
 * at the derived origin's well-known path, under the private-hostname gate with
 * connect-time pinning and a transport refusal of redirects, and the RP resolves
 * the issuer's card the same way. This example resolves both in process: it hands
 * the agent the RP's candidate signing keys directly and gives the RP a resolver
 * over a small trusted directory. The wire artifacts and their verification are
 * identical either way; only the key transport is stubbed.
 */

import { generateKeypair, deriveRpOrigin, type CandidateKey } from "@adastracomputing/ink";

/** A principal plus the Ed25519 keypair whose public half its Agent Card publishes. */
export interface Identity {
  /** The principal string, a bare-host `did:web` identifier. */
  did: string;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/**
 * Build a bare-host `did:web` identifier for a host and optional port, then
 * confirm it is in profile by deriving its origin. An explicit port 443, an
 * all-digit final label, an uppercase host, or any other out-of-profile shape
 * yields a null origin and throws here rather than minting an unusable identity.
 */
function didWeb(host: string, port?: number): string {
  const did = port === undefined ? `did:web:${host}` : `did:web:${host}%3A${port}`;
  if (deriveRpOrigin(did) === null) {
    throw new Error(`host is not a bare-host did:web under the profile: ${did}`);
  }
  return did;
}

/** Mint a fresh identity for a bare-host `did:web` principal. */
export async function createIdentity(host: string, port?: number): Promise<Identity> {
  const { publicKey, privateKey } = await generateKeypair();
  return { did: didWeb(host, port), publicKey, privateKey };
}

/**
 * The active signing keys an identity's Agent Card publishes, in the shape the
 * challenge and grant verifiers consume. A single active Ed25519 key with an
 * open validity window is enough for the flow; a real card may carry several
 * under the key rotation spec, and the verifier tries each active in-window key.
 */
export function activeSigningKeys(identity: Identity): CandidateKey[] {
  return [
    {
      keyId: `${identity.did}#sign-0`,
      publicKey: identity.publicKey,
      status: "active",
      // An open lower bound: the key is usable at any verifier clock at or after
      // this instant. The verifier evaluates the window at its own `now`, never
      // at an RP-chosen `issuedAt`.
      validFrom: "2020-01-01T00:00:00Z",
    },
  ];
}

/**
 * The RP's view of the wider network: which principals it can resolve to a
 * signing key. The RP consults this to verify an identity assertion's issuer
 * signature. Resolution failure fails closed at the call site: an issuer the RP
 * cannot resolve to a usable key is rejected, never trusted unverified.
 */
export class Directory {
  private readonly keys = new Map<string, Uint8Array>();

  /** Publish an identity's active signing key so the RP can resolve its issuer. */
  publish(identity: Identity): void {
    this.keys.set(identity.did, identity.publicKey);
  }

  /** Resolve a principal to its signing key, or null when it is unknown. */
  resolve(principal: string): Uint8Array | null {
    return this.keys.get(principal) ?? null;
  }
}
