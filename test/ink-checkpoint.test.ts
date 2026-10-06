import { describe, it, expect } from "vitest";
import { formatCheckpoint, isValidCheckpointOrigin, parseCheckpoint } from "../src/ink/checkpoint.js";

describe("INK Checkpoint", () => {
  describe("formatCheckpoint", () => {
    it("formats a tlog-checkpoint body", () => {
      const result = formatCheckpoint({
        origin: "example.network/agents/bob",
        treeSize: 42,
        rootHash: "abc123def456",
      });

      const lines = result.split("\n");
      expect(lines[0]).toBe("example.network/agents/bob");
      expect(lines[1]).toBe("42");
      expect(lines[2]).toBe("abc123def456");
      expect(lines[3]).toBe("");
    });

    it("includes empty trailing line", () => {
      const result = formatCheckpoint({
        origin: "test",
        treeSize: 1,
        rootHash: "hash",
      });
      expect(result.endsWith("\n")).toBe(true);
    });
  });

  describe("parseCheckpoint", () => {
    it("parses a valid checkpoint", () => {
      // Root hash must be 64 lowercase hex chars (SHA-256 output)
      const rootHash = "a3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4";
      const body = `example.network/agents/bob\n42\n${rootHash}\n`;
      const parsed = parseCheckpoint(body);
      expect(parsed).not.toBeNull();
      expect(parsed!.origin).toBe("example.network/agents/bob");
      expect(parsed!.treeSize).toBe(42);
      expect(parsed!.rootHash).toBe(rootHash);
    });

    it("returns null for invalid input", () => {
      const validHash = "a".repeat(64);
      expect(parseCheckpoint("")).toBeNull();
      expect(parseCheckpoint("only-one-line")).toBeNull();
      expect(parseCheckpoint(`origin\nnot-a-number\n${validHash}\n`)).toBeNull();
      // Short root hash rejected
      expect(parseCheckpoint("origin\n1\nabc123\n")).toBeNull();
      // Negative tree size rejected
      expect(parseCheckpoint(`origin\n-1\n${validHash}\n`)).toBeNull();
      // Tree size with junk rejected
      expect(parseCheckpoint(`origin\n100abc\n${validHash}\n`)).toBeNull();
      // Leading-zero tree size rejected, not normalized: "05" and "5" are
      // different byte strings.
      expect(parseCheckpoint(`origin\n05\n${validHash}\n`)).toBeNull();
      // An origin containing a lone (unpaired) UTF-16 surrogate rejects.
      // This has no valid UTF-8 encoding, so it is TS-only: a shared JSON
      // conformance vector cannot represent it portably across languages.
      expect(parseCheckpoint(`origin\uD800\n1\n${validHash}\n`)).toBeNull();
    });
  });

  describe("isValidCheckpointOrigin", () => {
    it("accepts an ordinary origin", () => {
      expect(isValidCheckpointOrigin("example.network/agents/bob")).toBe(true);
    });

    it("rejects a non-string", () => {
      expect(isValidCheckpointOrigin(42)).toBe(false);
      expect(isValidCheckpointOrigin(undefined)).toBe(false);
      expect(isValidCheckpointOrigin(null)).toBe(false);
    });

    it("rejects empty and oversized origins", () => {
      expect(isValidCheckpointOrigin("")).toBe(false);
      expect(isValidCheckpointOrigin("a".repeat(257))).toBe(false);
      expect(isValidCheckpointOrigin("a".repeat(256))).toBe(true);
    });

    it("rejects a lone surrogate", () => {
      expect(isValidCheckpointOrigin("log\uD800name")).toBe(false);
    });

    it("rejects '+' and control characters", () => {
      expect(isValidCheckpointOrigin("log+name")).toBe(false);
      expect(isValidCheckpointOrigin("log\u007Fname")).toBe(false);
      expect(isValidCheckpointOrigin("log\u009Fname")).toBe(false);
      expect(isValidCheckpointOrigin("log\u0000name")).toBe(false);
    });

    it("rejects Unicode whitespace beyond ASCII space", () => {
      expect(isValidCheckpointOrigin("log name")).toBe(false);
      expect(isValidCheckpointOrigin("log name")).toBe(false);
      expect(isValidCheckpointOrigin("log\u0085name")).toBe(false);
      expect(isValidCheckpointOrigin("log name")).toBe(false);
      expect(isValidCheckpointOrigin("log　name")).toBe(false);
    });
  });
});
