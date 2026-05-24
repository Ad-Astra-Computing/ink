/**
 * Security regression tests for INK protocol library.
 * Tests for findings from security review round 5.
 */
import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import {
  encryptInkPayload,
  decryptInkPayload,
  buildAuthHeader,
  verifyInkSignature,
  type InkEncryptedEnvelope,
} from "../src/crypto/ink.js";
import { verifyInkAuth } from "../src/middleware/ink-auth.js";
import { signInkMessage } from "../src/crypto/ink.js";
import { generateKeypair, generateEncryptionKeypair, deriveAgentId } from "../src/crypto/keys.js";
import { fetchAgentCard } from "../src/discovery/agent-card.js";
import { parseCheckpoint } from "../src/ink/checkpoint.js";

// ── Helpers ──

async function makeKeypair() {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return { privateKey, publicKey };
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// ── ECIES envelope integrity ──

describe("ECIES envelope AAD binds outer fields", () => {
  it("mutating outer timestamp is rejected on decrypt", async () => {
    const kp = await makeKeypair();
    const agentId = deriveAgentId(kp.publicKey);
    const encKp = generateEncryptionKeypair();
    const recipientPubHex = toHex(encKp.publicKey);

    const plaintext = { hello: "world", from: agentId, to: "tulpa:zRecipient" };
    const ts = new Date().toISOString();
    const nonce = "testmessagenonce01";

    const { envelope } = await encryptInkPayload(
      plaintext,
      agentId,
      recipientPubHex,
      ts,
      nonce,
    );

    // Tamper with outer timestamp
    const tampered: InkEncryptedEnvelope = { ...envelope, timestamp: new Date(Date.now() + 60000).toISOString() };

    await expect(
      decryptInkPayload(tampered, toHex(encKp.privateKey), "tulpa:zRecipient"),
    ).rejects.toThrow();
  });

  it("mutating outer messageNonce is rejected on decrypt", async () => {
    const kp = await makeKeypair();
    const agentId = deriveAgentId(kp.publicKey);
    const encKp = generateEncryptionKeypair();
    const recipientPubHex = toHex(encKp.publicKey);

    const plaintext = { hello: "world", from: agentId, to: "tulpa:zRecipient" };
    const ts = new Date().toISOString();

    const { envelope } = await encryptInkPayload(
      plaintext,
      agentId,
      recipientPubHex,
      ts,
      "original-nonce",
    );

    // Tamper with outer messageNonce
    const tampered: InkEncryptedEnvelope = { ...envelope, messageNonce: "different-nonce" };

    await expect(
      decryptInkPayload(tampered, toHex(encKp.privateKey), "tulpa:zRecipient"),
    ).rejects.toThrow();
  });

  it("mutating outer from is rejected on decrypt", async () => {
    const kp = await makeKeypair();
    const agentId = deriveAgentId(kp.publicKey);
    const encKp = generateEncryptionKeypair();
    const recipientPubHex = toHex(encKp.publicKey);

    const plaintext = { hello: "world", from: agentId, to: "tulpa:zRecipient" };
    const ts = new Date().toISOString();

    const { envelope } = await encryptInkPayload(
      plaintext,
      agentId,
      recipientPubHex,
      ts,
      "nonce-abc",
    );

    // Tamper with outer from
    const tampered: InkEncryptedEnvelope = { ...envelope, from: "tulpa:zAttacker" };

    await expect(
      decryptInkPayload(tampered, toHex(encKp.privateKey), "tulpa:zRecipient"),
    ).rejects.toThrow();
  });

  it("valid envelope decrypts successfully", async () => {
    const kp = await makeKeypair();
    const agentId = deriveAgentId(kp.publicKey);
    const encKp = generateEncryptionKeypair();
    const recipientPubHex = toHex(encKp.publicKey);

    const plaintext = { hello: "world", from: agentId, to: "tulpa:zRecipient" };
    const ts = new Date().toISOString();

    const { envelope } = await encryptInkPayload(
      plaintext,
      agentId,
      recipientPubHex,
      ts,
      "nonce-123",
    );

    const decrypted = await decryptInkPayload(envelope, toHex(encKp.privateKey), "tulpa:zRecipient");
    expect(decrypted.hello).toBe("world");
  });
});

// ── X25519 low-order public key rejection ──

describe("X25519 low-order/zero shared secret rejection", () => {
  it("rejects ephemeral public key that produces all-zero shared secret", async () => {
    const encKp = generateEncryptionKeypair();

    // X25519 low-order point: all-zero ephemeral key (produces all-zero ECDH output)
    const allZeroEphKey = new Uint8Array(32); // 32 zero bytes

    const fakeEnvelope: InkEncryptedEnvelope = {
      protocol: "ink/0.1",
      type: "network.tulpa.encrypted",
      from: "tulpa:zAttacker",
      ephemeralKey: Buffer.from(allZeroEphKey).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
      nonce: Buffer.from(new Uint8Array(12)).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
      ciphertext: "dGVzdA", // "test" in base64url
      timestamp: new Date().toISOString(),
      messageNonce: "testnonce",
    };

    await expect(
      decryptInkPayload(fakeEnvelope, toHex(encKp.privateKey)),
    ).rejects.toThrow();
  });
});

// ── Auth header length cap ──

describe("Authorization header length caps", () => {
  it("rejects oversized signature token", async () => {
    const kp = await generateKeypair();
    const agentId = deriveAgentId(kp.publicKey);
    // Create a huge fake signature string
    const bigSig = "A".repeat(2000);
    const result = await verifyInkAuth({
      authHeader: `INK-Ed25519 ${bigSig}`,
      method: "POST",
      path: "/ink/v1/test",
      recipientAgentId: "tulpa:zRecipient",
      body: { from: agentId, timestamp: new Date().toISOString() },
    });
    expect(result.valid).toBe(false);
  });

  it("rejects oversized keyId token", async () => {
    const kp = await generateKeypair();
    const agentId = deriveAgentId(kp.publicKey);
    const now = new Date().toISOString();
    const sig = await signInkMessage(
      { method: "POST", path: "/ink/v1/test", recipientDid: "tulpa:zRecipient", body: { from: agentId, timestamp: now }, timestamp: now },
      kp.privateKey,
    );
    const bigKeyId = "A".repeat(2000);
    const result = await verifyInkAuth({
      authHeader: `INK-Ed25519 ${sig} keyId=${bigKeyId}`,
      method: "POST",
      path: "/ink/v1/test",
      recipientAgentId: "tulpa:zRecipient",
      body: { from: agentId, timestamp: now },
    });
    // Should fail verification (key not found in set), but should not blow up
    expect(result.valid).toBe(false);
  });
});

// ── fetchAgentCard baseUrl SSRF defense ──

describe("fetchAgentCard rejects unsafe baseUrl values", () => {
  it("rejects non-https schemes", async () => {
    expect(await fetchAgentCard("tulpa:zX", "http://example.com")).toBeNull();
    expect(await fetchAgentCard("tulpa:zX", "ftp://example.com")).toBeNull();
    expect(await fetchAgentCard("tulpa:zX", "file:///etc/passwd")).toBeNull();
    expect(await fetchAgentCard("tulpa:zX", "javascript:alert(1)")).toBeNull();
  });

  it("rejects baseUrls containing userinfo", async () => {
    expect(await fetchAgentCard("tulpa:zX", "https://user:pass@example.com")).toBeNull();
    expect(await fetchAgentCard("tulpa:zX", "https://attacker@trusted.example.com")).toBeNull();
  });

  it("rejects malformed baseUrls", async () => {
    expect(await fetchAgentCard("tulpa:zX", "not a url")).toBeNull();
    expect(await fetchAgentCard("tulpa:zX", "")).toBeNull();
  });

  it("rejects loopback / private / link-local hosts by default (SSRF defense)", async () => {
    expect(await fetchAgentCard("tulpa:zX", "https://localhost")).toBeNull();
    expect(await fetchAgentCard("tulpa:zX", "https://localhost.")).toBeNull();
    expect(await fetchAgentCard("tulpa:zX", "https://x.localhost")).toBeNull();
    expect(await fetchAgentCard("tulpa:zX", "https://127.0.0.1")).toBeNull();
    expect(await fetchAgentCard("tulpa:zX", "https://10.0.0.1")).toBeNull();
    expect(await fetchAgentCard("tulpa:zX", "https://192.168.1.1")).toBeNull();
    expect(await fetchAgentCard("tulpa:zX", "https://172.16.0.1")).toBeNull();
    expect(await fetchAgentCard("tulpa:zX", "https://169.254.169.254")).toBeNull(); // cloud metadata
    expect(await fetchAgentCard("tulpa:zX", "https://[::1]")).toBeNull();
    expect(await fetchAgentCard("tulpa:zX", "https://[fe80::1]")).toBeNull();
    expect(await fetchAgentCard("tulpa:zX", "https://[fd12:3456:789a::1]")).toBeNull();
    expect(await fetchAgentCard("tulpa:zX", "https://2130706433")).toBeNull(); // 127.0.0.1 as decimal
    // WHATWG URL canonicalizes [::ffff:127.0.0.1] to [::ffff:7f00:1]
    expect(await fetchAgentCard("tulpa:zX", "https://[::ffff:127.0.0.1]")).toBeNull();
    expect(await fetchAgentCard("tulpa:zX", "https://[::ffff:7f00:1]")).toBeNull(); // hex form of 127.0.0.1
    expect(await fetchAgentCard("tulpa:zX", "https://[::ffff:c0a8:1]")).toBeNull(); // 192.168.0.1 in hex
    expect(await fetchAgentCard("tulpa:zX", "https://[::ffff:a9fe:a9fe]")).toBeNull(); // 169.254.169.254 cloud metadata in hex
    // Documented and reserved IPv6 ranges are blocked
    expect(await fetchAgentCard("tulpa:zX", "https://[2001:db8::1]")).toBeNull(); // documentation
    expect(await fetchAgentCard("tulpa:zX", "https://[100::1]")).toBeNull();      // discard-only
    expect(await fetchAgentCard("tulpa:zX", "https://[ff00::1]")).toBeNull();     // multicast
    expect(await fetchAgentCard("tulpa:zX", "https://[fc00::1]")).toBeNull();     // ULA
    expect(await fetchAgentCard("tulpa:zX", "https://[64:ff9b::1]")).toBeNull();  // NAT64 well-known
    expect(await fetchAgentCard("tulpa:zX", "https://[64:ff9b:1::1]")).toBeNull(); // local IPv4/IPv6 translation
    // 6to4 tunneling private v4 via 2002::/16
    expect(await fetchAgentCard("tulpa:zX", "https://[2002:c0a8:0101::1]")).toBeNull(); // 192.168.1.1 over 6to4
    expect(await fetchAgentCard("tulpa:zX", "https://[2002:7f00:0001::1]")).toBeNull(); // 127.0.0.1 over 6to4
    expect(await fetchAgentCard("tulpa:zX", "https://[2002:a9fe:a9fe::1]")).toBeNull(); // 169.254.169.254 over 6to4
    // Additional 2001::/16 special-use blocks
    expect(await fetchAgentCard("tulpa:zX", "https://[2001::1]")).toBeNull();      // Teredo (2001::/32)
    expect(await fetchAgentCard("tulpa:zX", "https://[2001:2::1]")).toBeNull();    // BMWG benchmarking
    expect(await fetchAgentCard("tulpa:zX", "https://[2001:10::1]")).toBeNull();   // ORCHID deprecated
    expect(await fetchAgentCard("tulpa:zX", "https://[2001:1f::1]")).toBeNull();   // ORCHID range
    expect(await fetchAgentCard("tulpa:zX", "https://[2001:20::1]")).toBeNull();   // ORCHIDv2
    expect(await fetchAgentCard("tulpa:zX", "https://[2001:2f::1]")).toBeNull();   // ORCHIDv2 range
    expect(await fetchAgentCard("tulpa:zX", "https://[100:0:0:1::1]")).toBeNull(); // dummy IPv6 prefix RFC 7600
    expect(await fetchAgentCard("tulpa:zX", "https://[3fff::1]")).toBeNull();      // BMWG IPv6 benchmarking
    expect(await fetchAgentCard("tulpa:zX", "https://[3fff:ffff::1]")).toBeNull(); // BMWG range
    expect(await fetchAgentCard("tulpa:zX", "https://[5f00::1]")).toBeNull();      // SRv6 SIDs
    // Additional IANA special-use IPv4 blocks
    expect(await fetchAgentCard("tulpa:zX", "https://100.64.0.1")).toBeNull(); // CGNAT
    expect(await fetchAgentCard("tulpa:zX", "https://100.127.0.1")).toBeNull(); // CGNAT
    expect(await fetchAgentCard("tulpa:zX", "https://198.18.0.1")).toBeNull(); // benchmarking
    expect(await fetchAgentCard("tulpa:zX", "https://192.0.2.1")).toBeNull(); // TEST-NET-1
    expect(await fetchAgentCard("tulpa:zX", "https://198.51.100.1")).toBeNull(); // TEST-NET-2
    expect(await fetchAgentCard("tulpa:zX", "https://203.0.113.1")).toBeNull(); // TEST-NET-3
    expect(await fetchAgentCard("tulpa:zX", "https://224.0.0.1")).toBeNull(); // multicast
    expect(await fetchAgentCard("tulpa:zX", "https://239.255.255.250")).toBeNull(); // SSDP multicast
    expect(await fetchAgentCard("tulpa:zX", "https://240.0.0.1")).toBeNull(); // reserved
    expect(await fetchAgentCard("tulpa:zX", "https://255.255.255.255")).toBeNull(); // broadcast
    expect(await fetchAgentCard("tulpa:zX", "https://192.88.99.1")).toBeNull(); // deprecated 6to4
    // 24-bit special-use blocks that now use full-octet checks
    expect(await fetchAgentCard("tulpa:zX", "https://192.31.196.1")).toBeNull(); // AS112-v4
    expect(await fetchAgentCard("tulpa:zX", "https://192.52.193.1")).toBeNull(); // AMT
    expect(await fetchAgentCard("tulpa:zX", "https://192.175.48.1")).toBeNull(); // Direct Delegation AS112
    // Negative controls: addresses adjacent to special-use blocks must be allowed
    let called = false;
    const orig = globalThis.fetch;
    try {
      globalThis.fetch = (async () => { called = true; return new Response("{}", { status: 404 }); }) as typeof fetch;
      // 192.31.197.0 is one /24 over from AS112-v4 — should be allowed
      await fetchAgentCard("tulpa:zX", "https://192.31.197.1");
      expect(called).toBe(true);
      called = false;
      // 192.0.3.0 is just past TEST-NET-1
      await fetchAgentCard("tulpa:zX", "https://192.0.3.1");
      expect(called).toBe(true);
    } finally {
      globalThis.fetch = orig;
    }
  });

  it("accepts public IPv6 hosts (does not blanket-reject v6)", async () => {
    let called = false;
    const orig = globalThis.fetch;
    try {
      globalThis.fetch = (async () => { called = true; return new Response("{}", { status: 404 }); }) as typeof fetch;
      // Cloudflare's public IPv6 (2606:4700::6810:84e5) — must be allowed.
      await fetchAgentCard("tulpa:zX", "https://[2606:4700::6810:84e5]");
      expect(called).toBe(true);
      called = false;
      // Public Google DNS over v6
      await fetchAgentCard("tulpa:zX", "https://[2001:4860:4860::8888]");
      expect(called).toBe(true);
    } finally {
      globalThis.fetch = orig;
    }
  });

  it("private-host blocklist can be opted out for testing / intranet use", async () => {
    let called = false;
    const orig = globalThis.fetch;
    try {
      globalThis.fetch = (async () => { called = true; return new Response("{}", { status: 404 }); }) as typeof fetch;
      await fetchAgentCard("tulpa:zX", "https://127.0.0.1", { allowPrivateHosts: true });
      expect(called).toBe(true);
    } finally {
      globalThis.fetch = orig;
    }
  });

  it("rejects agentId values that would normalise to dot-segments", async () => {
    expect(await fetchAgentCard(".", "https://example.com")).toBeNull();
    expect(await fetchAgentCard("..", "https://example.com")).toBeNull();
    expect(await fetchAgentCard("foo/../bar", "https://example.com")).toBeNull();
    expect(await fetchAgentCard("foo\\..\\bar", "https://example.com")).toBeNull();
  });

  it("runtime-validates the card via Zod schema (rejects malformed shapes)", async () => {
    const orig = globalThis.fetch;
    try {
      // Card missing required fields — must be rejected by schema.
      globalThis.fetch = (async () => new Response(
        JSON.stringify({ protocol: "ink/0.1", agentId: "tulpa:zX" }),
        { status: 200 },
      )) as typeof fetch;
      expect(await fetchAgentCard("tulpa:zX", "https://example.com")).toBeNull();
    } finally {
      globalThis.fetch = orig;
    }
  });

  it("rejects cards whose thirdPartyAudit service endpoints target private hosts", async () => {
    const orig = globalThis.fetch;
    try {
      const evil = {
        protocol: "ink/0.1",
        agentId: "tulpa:zVictim2",
        handle: "victim2",
        displayName: "Victim2",
        endpoint: "https://example.com",
        publicKeyMultibase: "z6MkbootstrapKey1234567890123456789012345678",
        capabilities: {
          intentsAccepted: [],
          intentsSent: [],
          thirdPartyAudit: {
            services: [
              { endpoint: "http://169.254.169.254/", did: "did:web:x", publicKey: "z6" },
            ],
            submitPolicy: "all",
          },
        },
        availability: { timezone: "UTC" },
      };
      globalThis.fetch = (async () => new Response(JSON.stringify(evil), { status: 200 })) as typeof fetch;
      expect(await fetchAgentCard("tulpa:zVictim2", "https://example.com")).toBeNull();
    } finally {
      globalThis.fetch = orig;
    }
  });

  it("rejects cards whose endpoint targets a private host (SSRF for downstream callers)", async () => {
    const orig = globalThis.fetch;
    try {
      // A valid card shape but with an endpoint pointed at cloud metadata
      const evil = {
        protocol: "ink/0.1",
        agentId: "tulpa:zVictim",
        handle: "victim",
        displayName: "Victim",
        endpoint: "http://169.254.169.254/latest/meta-data/",
        publicKeyMultibase: "z6MkbootstrapKey1234567890123456789012345678",
        capabilities: { intentsAccepted: [], intentsSent: [] },
        availability: { timezone: "UTC" },
      };
      globalThis.fetch = (async () => new Response(JSON.stringify(evil), { status: 200 })) as typeof fetch;
      expect(await fetchAgentCard("tulpa:zVictim", "https://example.com")).toBeNull();
    } finally {
      globalThis.fetch = orig;
    }
  });

  it("accepts a fetch override for connect-time SSRF defense (DNS rebinding)", async () => {
    // Integrator-supplied fetch lets them plug in an undici dispatcher or
    // cf.resolveOverride that rejects private connect targets at TCP time.
    let called = false;
    const customFetch: typeof fetch = async () => {
      called = true;
      return new Response("{}", { status: 404 });
    };
    await fetchAgentCard("tulpa:zX", "https://example.com", { fetch: customFetch });
    expect(called).toBe(true);
  });

  it("refuses to follow redirects (SSRF defense)", async () => {
    let capturedInit: RequestInit | undefined;
    const orig = globalThis.fetch;
    try {
      globalThis.fetch = (async (_url: RequestInfo | URL, init?: RequestInit) => {
        capturedInit = init;
        return new Response("{}", { status: 200 });
      }) as typeof fetch;
      await fetchAgentCard("tulpa:zX", "https://example.com");
      expect(capturedInit?.redirect).toBe("manual");
    } finally {
      globalThis.fetch = orig;
    }
  });

  it("builds fetch URL from the parsed origin, not raw baseUrl (CRLF defense)", async () => {
    let capturedUrl = "";
    const orig = globalThis.fetch;
    try {
      globalThis.fetch = (async (url: RequestInfo | URL) => {
        capturedUrl = typeof url === "string" ? url : url.toString();
        return new Response("{}", { status: 404 });
      }) as typeof fetch;
      // Raw baseUrl contains URL-encoded CRLF in the path. The parsed URL
      // normalizes; the constructed fetch URL must not carry the original
      // raw bytes that could be interpreted as headers by a downstream proxy.
      await fetchAgentCard("tulpa:zX", "https://example.com/%0d%0aX-Injected:%20bad");
      // The actual fetch URL was built from `parsedBase.origin + normalized path`.
      // It must not contain literal CR/LF bytes (the WHATWG URL serializer
      // would percent-encode them in the pathname).
      expect(capturedUrl).not.toContain("\r");
      expect(capturedUrl).not.toContain("\n");
      // Must include the proper /ink/v1 path
      expect(capturedUrl).toContain("/ink/v1/");
      expect(capturedUrl).toContain("/agent.json");
    } finally {
      globalThis.fetch = orig;
    }
  });
});

// ── fetchAgentCard identity binding ──

describe("fetchAgentCard binds result to requested agentId", () => {
  it("returns null if card.agentId does not match requested agentId", async () => {
    const requestedId = "tulpa:zRequested";
    const differentId = "tulpa:zDifferent";

    // Mock fetch to return a card with a mismatched agentId
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (_url: RequestInfo | URL, _opts?: RequestInit) => {
      return new Response(JSON.stringify({
        protocol: "ink/0.1",
        agentId: differentId,  // Mismatch!
        handle: "test",
        displayName: "Test",
        endpoint: "https://example.com",
        publicKeyMultibase: "z11111111111111111111111111111111111111111111",
        capabilities: { intentsAccepted: [], intentsSent: [] },
        availability: { timezone: "UTC" },
      }), { status: 200, headers: { "Content-Type": "application/json" } });
    }) as typeof fetch;

    try {
      const card = await fetchAgentCard(requestedId, "https://example.com");
      expect(card).toBeNull();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("returns card when agentId matches", async () => {
    const requestedId = "tulpa:zRequested";

    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (_url: RequestInfo | URL, _opts?: RequestInit) => {
      return new Response(JSON.stringify({
        protocol: "ink/0.1",
        agentId: requestedId,  // Matches!
        handle: "test",
        displayName: "Test",
        endpoint: "https://example.com",
        publicKeyMultibase: "z11111111111111111111111111111111111111111111",
        capabilities: { intentsAccepted: [], intentsSent: [] },
        availability: { timezone: "UTC" },
      }), { status: 200, headers: { "Content-Type": "application/json" } });
    }) as typeof fetch;

    try {
      const card = await fetchAgentCard(requestedId, "https://example.com");
      expect(card).not.toBeNull();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

// ── parseCheckpoint strictness ──

describe("parseCheckpoint strict validation", () => {
  it("rejects tree size with trailing junk", () => {
    const result = parseCheckpoint("witness.tulpa.network\n100abc\nabc123\n");
    expect(result).toBeNull();
  });

  it("rejects root hash that is not 64-char hex", () => {
    const result = parseCheckpoint("witness.tulpa.network\n100\nNOTHEX!!\n");
    expect(result).toBeNull();
  });

  it("rejects negative tree size", () => {
    const result = parseCheckpoint("witness.tulpa.network\n-1\n" + "a".repeat(64) + "\n");
    expect(result).toBeNull();
  });

  it("accepts valid checkpoint", () => {
    const rootHash = "a".repeat(64);
    const result = parseCheckpoint(`witness.tulpa.network\n100\n${rootHash}\n`);
    expect(result).not.toBeNull();
    expect(result?.treeSize).toBe(100);
    expect(result?.rootHash).toBe(rootHash);
  });
});

// ── handshake-budget pairKey collision ──

describe("HandshakeBudgetTracker pairKey collision resistance", () => {
  it("correlationIds with colons cannot collide with other entries", async () => {
    const { HandshakeBudgetTracker } = await import("../src/ink/handshake-budget.js");
    const tracker = new HandshakeBudgetTracker();

    // If correlationId = "a:b" and fromDid = "c", pairKey = "a:b:c"
    // If correlationId = "a" and fromDid = "b:c", pairKey = "a:b:c" (collision!)
    const r1 = tracker.checkAndRecord({ correlationId: "a:b", fromDid: "c", messageType: "intent" });
    const r2 = tracker.checkAndRecord({ correlationId: "a", fromDid: "b:c", messageType: "intent" });

    // Both should be allowed (they are different correlations)
    expect(r1.allowed).toBe(true);
    expect(r2.allowed).toBe(true);

    // Verify they are treated as separate entries (no cross-contamination)
    // Both can still send further messages in their respective correlation
    const r3 = tracker.checkAndRecord({ correlationId: "a:b", fromDid: "c", messageType: "challenge" });
    const r4 = tracker.checkAndRecord({ correlationId: "a", fromDid: "b:c", messageType: "challenge" });
    expect(r3.allowed).toBe(true);
    expect(r4.allowed).toBe(true);
  });
});
