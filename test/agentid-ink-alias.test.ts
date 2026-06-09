import { describe, it, expect } from "vitest";
import {
  generateKeypair,
  deriveAgentId,
  extractPublicKeyFromAgentId,
  AGENT_ID_KEY_PREFIXES,
} from "../src/index.js";

/**
 * ink/0.4 agentId alias: `extractPublicKeyFromAgentId` accepts the `ink:` alias
 * as well as the canonical `tulpa:` prefix. Both carry the identical multibase
 * key, so the bootstrap verification key is byte-identical. Emission stays
 * `tulpa:` (accept both, emit one).
 */
describe("agentId ink: alias", () => {
  it("exposes both key prefixes, tulpa: first (canonical)", () => {
    expect(AGENT_ID_KEY_PREFIXES).toEqual(["tulpa:", "ink:"]);
  });

  it("freezes the exported prefix list so a consumer cannot widen validation", () => {
    expect(Object.isFrozen(AGENT_ID_KEY_PREFIXES)).toBe(true);
    expect(() => {
      // @ts-expect-error runtime mutation attempt on a frozen, readonly tuple
      AGENT_ID_KEY_PREFIXES.push("did:key:");
    }).toThrow();
  });

  it("deriveAgentId still emits the canonical tulpa: prefix", async () => {
    const kp = await generateKeypair();
    expect(deriveAgentId(kp.publicKey).startsWith("tulpa:")).toBe(true);
  });

  it("extracts a byte-identical key from the tulpa: and ink: spellings", async () => {
    const kp = await generateKeypair();
    const tulpaId = deriveAgentId(kp.publicKey);
    const inkId = `ink:${tulpaId.slice("tulpa:".length)}`;
    const fromTulpa = extractPublicKeyFromAgentId(tulpaId);
    const fromInk = extractPublicKeyFromAgentId(inkId);
    expect(fromInk).toEqual(fromTulpa);
    expect(fromInk).toEqual(kp.publicKey);
  });

  it("rejects other prefixes and malformed inputs", async () => {
    const kp = await generateKeypair();
    const tail = deriveAgentId(kp.publicKey).slice("tulpa:".length);
    // wrong/disallowed prefixes
    expect(() => extractPublicKeyFromAgentId(`did:key:${tail}`)).toThrow();
    expect(() => extractPublicKeyFromAgentId(`key:${tail}`)).toThrow();
    expect(() => extractPublicKeyFromAgentId(tail)).toThrow(); // no prefix
    // case-sensitive: only lowercase prefixes accepted
    expect(() => extractPublicKeyFromAgentId(`Ink:${tail}`)).toThrow();
    expect(() => extractPublicKeyFromAgentId(`TULPA:${tail}`)).toThrow();
    // no implicit trimming of surrounding whitespace
    expect(() => extractPublicKeyFromAgentId(` ink:${tail}`)).toThrow();
    // empty / over-long
    expect(() => extractPublicKeyFromAgentId("")).toThrow();
    expect(() => extractPublicKeyFromAgentId("ink:")).toThrow();
  });

  it("rejects a malformed multibase tail identically for both prefixes", () => {
    expect(() => extractPublicKeyFromAgentId("tulpa:znot-a-valid-key")).toThrow();
    expect(() => extractPublicKeyFromAgentId("ink:znot-a-valid-key")).toThrow();
  });
});
