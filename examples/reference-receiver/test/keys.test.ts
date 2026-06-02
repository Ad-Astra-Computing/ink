import { describe, it, expect } from "vitest";
import { loadReceiverIdentity, deriveDidWeb, selfCheckIdentity } from "../src/keys.js";
import { generateKeypair, encodePublicKeyMultibase, base64urlEncode } from "@adastracomputing/ink";

async function freshIdentityVars(): Promise<{ INK_RECEIVER_SIGNING_SEED: string; INK_RECEIVER_PUBLIC_KEY_MULTIBASE: string }> {
  const kp = await generateKeypair();
  return {
    INK_RECEIVER_SIGNING_SEED: base64urlEncode(kp.privateKey),
    INK_RECEIVER_PUBLIC_KEY_MULTIBASE: encodePublicKeyMultibase(kp.publicKey),
  };
}

describe("loadReceiverIdentity", () => {
  it("loads a valid keypair from base64url seed + multibase public", async () => {
    const vars = await freshIdentityVars();
    const id = loadReceiverIdentity(vars);
    expect(id.privateKey.length).toBe(32);
    expect(id.publicKey.length).toBe(32);
    expect(id.publicKeyMultibase).toBe(vars.INK_RECEIVER_PUBLIC_KEY_MULTIBASE);
  });

  it("throws on missing seed", () => {
    expect(() => loadReceiverIdentity({ INK_RECEIVER_PUBLIC_KEY_MULTIBASE: "zfoo" })).toThrow(/missing_seed/);
  });

  it("throws on missing public key", async () => {
    const vars = await freshIdentityVars();
    const { INK_RECEIVER_SIGNING_SEED } = vars;
    expect(() => loadReceiverIdentity({ INK_RECEIVER_SIGNING_SEED })).toThrow(/missing_public_key/);
  });

  it("throws on malformed base64url seed", () => {
    expect(() => loadReceiverIdentity({
      INK_RECEIVER_SIGNING_SEED: "!!!not valid!!!",
      INK_RECEIVER_PUBLIC_KEY_MULTIBASE: "zfoo",
    })).toThrow(/invalid_seed/);
  });

  it("throws on wrong-length seed", () => {
    expect(() => loadReceiverIdentity({
      INK_RECEIVER_SIGNING_SEED: base64urlEncode(new Uint8Array(16)),
      INK_RECEIVER_PUBLIC_KEY_MULTIBASE: "zfoo",
    })).toThrow(/invalid_seed_length/);
  });

  it("throws on malformed multibase public key", async () => {
    const vars = await freshIdentityVars();
    expect(() => loadReceiverIdentity({
      INK_RECEIVER_SIGNING_SEED: vars.INK_RECEIVER_SIGNING_SEED,
      INK_RECEIVER_PUBLIC_KEY_MULTIBASE: "z!!notvalid",
    })).toThrow(/invalid_public_key/);
  });
});

describe("selfCheckIdentity", () => {
  it("passes for a matching seed + public", async () => {
    const vars = await freshIdentityVars();
    const id = loadReceiverIdentity(vars);
    await expect(selfCheckIdentity(id)).resolves.toBeUndefined();
  });

  it("rejects when seed and public key are unrelated", async () => {
    const a = await freshIdentityVars();
    const b = await freshIdentityVars();
    // Splice: seed from A, public from B. The canary signature will
    // verify against A's derived key, not B's published one.
    const id = loadReceiverIdentity({
      INK_RECEIVER_SIGNING_SEED: a.INK_RECEIVER_SIGNING_SEED,
      INK_RECEIVER_PUBLIC_KEY_MULTIBASE: b.INK_RECEIVER_PUBLIC_KEY_MULTIBASE,
    });
    await expect(selfCheckIdentity(id)).rejects.toThrow(/identity_mismatch/);
  });
});

describe("deriveDidWeb", () => {
  it("accepts a valid bare host", () => {
    expect(deriveDidWeb("ink-receiver.example.workers.dev")).toBe("did:web:ink-receiver.example.workers.dev");
  });

  it("lowercases the host", () => {
    expect(deriveDidWeb("EXAMPLE.com")).toBe("did:web:example.com");
  });

  it("rejects hosts with a port", () => {
    expect(() => deriveDidWeb("example.com:8443")).toThrow(/invalid_host/);
  });

  it("rejects hosts with a path", () => {
    expect(() => deriveDidWeb("example.com/foo")).toThrow(/invalid_host/);
  });

  it("rejects single-label hosts", () => {
    expect(() => deriveDidWeb("localhost")).toThrow(/invalid_host/);
  });

  it("rejects empty input", () => {
    expect(() => deriveDidWeb("")).toThrow(/invalid_host/);
  });
});
