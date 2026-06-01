import { describe, it, expect } from "vitest";
import {
  evaluateInboundForeign,
  isForeignDid,
  normalizeHostSuffixes,
  type InkInboundPolicy,
} from "../src/inbound-policy.js";

function basePolicy(over: Partial<InkInboundPolicy> = {}): InkInboundPolicy {
  return {
    userId: "user-1",
    acceptForeignAgents: false,
    allowedMethods: [],
    allowedHosts: [],
    allowedDids: [],
    blockedDids: [],
    updatedAt: "2026-01-01T00:00:00Z",
    ...over,
  };
}

describe("isForeignDid", () => {
  it("recognizes did:web and did:key as foreign", () => {
    expect(isForeignDid("did:web:example.com")).toBe(true);
    expect(isForeignDid("did:key:z6Mk...")).toBe(true);
  });

  it("treats native methods as not-foreign", () => {
    expect(isForeignDid("did:tulpa:abc")).toBe(false);
    expect(isForeignDid("did:plc:abc")).toBe(false);
  });

  it("treats ANY non-native did:* method as foreign (default-deny)", () => {
    expect(isForeignDid("did:peer:abc")).toBe(true);
    expect(isForeignDid("did:ion:abc")).toBe(true);
  });

  it("non-did strings are not foreign DIDs", () => {
    expect(isForeignDid("https://example.com")).toBe(false);
    expect(isForeignDid("plain-string")).toBe(false);
  });
});

describe("evaluateInboundForeign", () => {
  it("permits native senders regardless of policy", () => {
    const policy = basePolicy({ acceptForeignAgents: false });
    expect(evaluateInboundForeign(policy, "did:tulpa:friend").allowed).toBe(true);
  });

  it("rejects every foreign sender when acceptForeignAgents is false", () => {
    const policy = basePolicy({ acceptForeignAgents: false });
    const d = evaluateInboundForeign(policy, "did:web:foo.com");
    expect(d.allowed).toBe(false);
    expect(d.reason).toBe("block_recipient_not_accepting_foreign");
  });

  it("blockedDids beats every other rule", () => {
    const policy = basePolicy({
      acceptForeignAgents: true,
      blockedDids: ["did:web:naughty.example"],
    });
    const d = evaluateInboundForeign(policy, "did:web:naughty.example");
    expect(d.allowed).toBe(false);
    expect(d.reason).toBe("block_did_in_user_block_list");
  });

  it("allowedDids when non-empty restricts to exact matches", () => {
    const policy = basePolicy({
      acceptForeignAgents: true,
      allowedDids: ["did:web:trusted.example"],
    });
    expect(evaluateInboundForeign(policy, "did:web:trusted.example").allowed).toBe(true);
    const d = evaluateInboundForeign(policy, "did:web:other.example");
    expect(d.allowed).toBe(false);
    expect(d.reason).toBe("block_did_not_in_user_allow_list");
  });

  it("allowedHosts uses trailing-label suffix matching", () => {
    const policy = basePolicy({
      acceptForeignAgents: true,
      allowedHosts: ["partner.example"],
    });
    expect(evaluateInboundForeign(policy, "did:web:partner.example").allowed).toBe(true);
    expect(evaluateInboundForeign(policy, "did:web:a.partner.example").allowed).toBe(true);
    // Prefix confusion: evilpartner.example must NOT match partner.example.
    const d = evaluateInboundForeign(policy, "did:web:evilpartner.example");
    expect(d.allowed).toBe(false);
    expect(d.reason).toBe("block_host_not_in_user_allow_list");
  });

  it("drops malformed method prefixes lacking trailing colon", () => {
    const policy = basePolicy({
      acceptForeignAgents: true,
      allowedMethods: ["did:key", "did:web:"], // first is malformed
    });
    expect(evaluateInboundForeign(policy, "did:web:trusted.example").allowed).toBe(true);
    const d = evaluateInboundForeign(policy, "did:keyevil:attacker");
    expect(d.allowed).toBe(false);
    expect(d.reason).toBe("block_method_not_in_user_allow_list");
  });
});

describe("normalizeHostSuffixes", () => {
  it("lowercases, strips trailing dots, dedupes", () => {
    expect(normalizeHostSuffixes(["GOOD.com", "good.com.", "GOOD.COM"])).toEqual(["good.com"]);
  });

  it("rejects ports, IP literals, wildcards, bare labels", () => {
    const bad = ["bad:8080", "10.0.0.5", "*.foo.com", "trailing.example.", "  ", "/path", "no-tld"];
    const out = normalizeHostSuffixes(bad);
    expect(out).toEqual(["trailing.example"]);
  });
});
