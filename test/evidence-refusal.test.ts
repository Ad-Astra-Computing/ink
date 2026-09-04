import { describe, expect, it } from "vitest";
import { parseEvidenceRefusal } from "../src/models/attestation.js";

// The structured refusal of specs/ink-attestation.md: the receiver's HTTP 403
// body naming the claim types still missing. The sender parses it from an
// arbitrary receiver, so the shape tolerates unknown members but pins the code,
// the claim-type set grammar and the set bounds.

const refusal = {
  protocol: "ink/0.1",
  error: true,
  code: "policy:evidence_required",
  requiredClaimTypes: ["example.owner.verified_human"],
};

describe("parseEvidenceRefusal", () => {
  it("accepts a minimal refusal", () => {
    const r = parseEvidenceRefusal(refusal);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.refusal.requiredClaimTypes).toEqual(["example.owner.verified_human"]);
  });

  it("accepts a refusal with a message", () => {
    expect(parseEvidenceRefusal({ ...refusal, message: "evidence required" }).ok).toBe(true);
  });

  it("accepts and preserves an unknown member", () => {
    const r = parseEvidenceRefusal({ ...refusal, retryHint: "later" });
    expect(r.ok).toBe(true);
    if (r.ok) expect((r.refusal as Record<string, unknown>).retryHint).toBe("later");
  });

  it("accepts a 32-type set", () => {
    const types = Array.from({ length: 32 }, (_, i) => `example.claim.t${i}`);
    expect(parseEvidenceRefusal({ ...refusal, requiredClaimTypes: types }).ok).toBe(true);
  });

  it("rejects a wrong code", () => {
    expect(parseEvidenceRefusal({ ...refusal, code: "policy_violation" }).ok).toBe(false);
  });

  it("rejects error false", () => {
    expect(parseEvidenceRefusal({ ...refusal, error: false }).ok).toBe(false);
  });

  it("rejects a missing requiredClaimTypes", () => {
    const { requiredClaimTypes, ...rest } = refusal;
    void requiredClaimTypes;
    expect(parseEvidenceRefusal(rest).ok).toBe(false);
  });

  it("rejects an empty type set", () => {
    expect(parseEvidenceRefusal({ ...refusal, requiredClaimTypes: [] }).ok).toBe(false);
  });

  it("rejects a 33-type set", () => {
    const types = Array.from({ length: 33 }, (_, i) => `example.claim.t${i}`);
    expect(parseEvidenceRefusal({ ...refusal, requiredClaimTypes: types }).ok).toBe(false);
  });

  it("rejects duplicate types", () => {
    const t = "example.owner.verified_human";
    expect(parseEvidenceRefusal({ ...refusal, requiredClaimTypes: [t, t] }).ok).toBe(false);
  });

  it("rejects an out-of-grammar type", () => {
    expect(parseEvidenceRefusal({ ...refusal, requiredClaimTypes: ["NoDots"] }).ok).toBe(false);
  });

  it("rejects a non-string entry", () => {
    expect(parseEvidenceRefusal({ ...refusal, requiredClaimTypes: [1] }).ok).toBe(false);
  });

  it("rejects an over-length message", () => {
    expect(parseEvidenceRefusal({ ...refusal, message: "m".repeat(501) }).ok).toBe(false);
  });

  it("rejects a non-object without throwing", () => {
    expect(parseEvidenceRefusal("nope").ok).toBe(false);
    expect(parseEvidenceRefusal(null).ok).toBe(false);
    expect(parseEvidenceRefusal([refusal]).ok).toBe(false);
  });
});
