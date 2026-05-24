import { describe, it, expect } from "vitest";
import { formatCheckpoint, parseCheckpoint } from "../src/ink/checkpoint.js";

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
    });
  });
});
