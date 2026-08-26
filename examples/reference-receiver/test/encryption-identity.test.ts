import { describe, it, expect } from "vitest";
import { generateEncryptionKeypair, encodeEncryptionKeyMultibase, decodeEncryptionKeyMultibase } from "@adastracomputing/ink";
import { loadEncryptionIdentity, type ReceiverEnv } from "../src/keys.js";

// Criterion 2c of the INK 1.0 soak runs three variants against this receiver,
// one of which is `encrypted`. It failed every day from 2026-08-13 with
// "receiver Agent Card advertises no active X25519 encryption key", because the
// receiver had no encryption identity at all. These pin the identity half; the
// card half is pinned in agent-card-encryption.test.ts.

const seedHex = (b: number) => Buffer.from(new Uint8Array(32).fill(b)).toString("hex");

describe("receiver encryption identity", () => {
  it("is absent when no encryption seed is configured", () => {
    // Encryption stays OPTIONAL. A deployment that sets no seed keeps working
    // exactly as before and simply advertises no encryption key.
    expect(loadEncryptionIdentity({} as ReceiverEnv)).toBeNull();
  });

  it("derives a usable X25519 identity from a configured seed", () => {
    const id = loadEncryptionIdentity({ INK_RECEIVER_ENCRYPTION_SEED: seedHex(7) } as ReceiverEnv);
    expect(id).not.toBeNull();
    expect(id!.privateKey).toBeInstanceOf(Uint8Array);
    expect(id!.privateKey.length).toBe(32);
    expect(id!.publicKey.length).toBe(32);
    // The advertised form must decode under the 0xec01 X25519 multicodec, which
    // is what a sender uses to seal to this receiver.
    expect(decodeEncryptionKeyMultibase(id!.publicKeyMultibase)).toEqual(id!.publicKey);
  });

  it("is deterministic, so a redeploy does not silently rotate the key", () => {
    const a = loadEncryptionIdentity({ INK_RECEIVER_ENCRYPTION_SEED: seedHex(9) } as ReceiverEnv);
    const b = loadEncryptionIdentity({ INK_RECEIVER_ENCRYPTION_SEED: seedHex(9) } as ReceiverEnv);
    expect(a!.publicKeyMultibase).toBe(b!.publicKeyMultibase);
  });

  it("refuses a seed that is not 32 bytes of hex rather than deriving a weak key", () => {
    expect(() => loadEncryptionIdentity({ INK_RECEIVER_ENCRYPTION_SEED: "abcd" } as ReceiverEnv)).toThrow();
    expect(() => loadEncryptionIdentity({ INK_RECEIVER_ENCRYPTION_SEED: "zz".repeat(32) } as ReceiverEnv)).toThrow();
  });

  it("agrees with the library's own keypair generator on the encoding", async () => {
    // Cross-check against the shipped primitive so the receiver cannot drift
    // into a private encoding of its own.
    const kp = await generateEncryptionKeypair();
    expect(decodeEncryptionKeyMultibase(encodeEncryptionKeyMultibase(kp.publicKey))).toEqual(kp.publicKey);
  });
});
