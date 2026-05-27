#!/usr/bin/env node
/**
 * CLI: verify an INK inclusion receipt against a witness's published
 * identity and current checkpoint. Self-contained ESM module so the
 * shebang resolves on any Node 22+ install without a TS toolchain.
 *
 * Usage:
 *
 *   # Receipt on stdin
 *   cat receipt.json | npx @adastracomputing/ink verify-inclusion \
 *     --witness https://witness.tulpa.network
 *
 *   # Receipt from file
 *   npx @adastracomputing/ink verify-inclusion \
 *     --file receipt.json \
 *     --witness https://witness.tulpa.network
 *
 *   # Also walk the inclusion proof
 *   npx @adastracomputing/ink verify-inclusion \
 *     --file receipt.json \
 *     --witness https://witness.tulpa.network \
 *     --event-hash 8a3c...
 *
 * Exit codes:
 *   0  receipt is valid
 *   1  receipt is invalid (a step failed)
 *   2  usage / network / parsing error
 */
import { readFileSync, statSync } from "node:fs";
import * as ed from "@noble/ed25519";
import canonicalize from "canonicalize";

// ── arg parsing ──

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--file" || a === "-f") out.file = argv[++i];
    else if (a === "--witness" || a === "-w") out.witness = argv[++i];
    else if (a === "--event-hash" || a === "-e") out.eventHash = argv[++i];
    else if (a === "--allow-http") out.allowHttp = true;
    else if (a === "--help" || a === "-h") out.help = true;
    else {
      console.error(`Unknown argument: ${a}`);
      process.exit(2);
    }
  }
  return out;
}

/**
 * Validate and normalize the --witness URL. Rejects unparseable URLs,
 * schemes other than https (or http with --allow-http), and URLs that
 * carry credentials. Returns scheme://host[:port] with no path.
 */
function validateWitnessUrl(raw, allowHttp) {
  let u;
  try { u = new URL(raw); }
  catch { throw new Error(`--witness is not a valid URL: ${raw}`); }
  if (u.username || u.password) throw new Error("--witness URL must not contain credentials");
  if (u.protocol === "https:") return `${u.protocol}//${u.host}`;
  if (u.protocol === "http:") {
    if (!allowHttp) throw new Error("--witness URL must use https:// (pass --allow-http for plain http)");
    return `${u.protocol}//${u.host}`;
  }
  throw new Error(`--witness URL scheme must be https:// or http://, got ${u.protocol}`);
}

function printHelp() {
  console.log(`verify-inclusion: verify an INK inclusion receipt.

Usage:
  verify-inclusion --witness <url> [--file <receipt.json>] [--event-hash <hex>]

Options:
  -w, --witness <url>      Witness base URL (e.g. https://witness.tulpa.network)
  -f, --file <path>        Receipt JSON file. Omit to read from stdin.
  -e, --event-hash <hex>   Optional. RFC 6962 leaf hash for the audit event:
                            SHA-256(0x00 || JCS(event-without-agentSignature)),
                            hex-encoded. When set, the inclusion proof is
                            re-walked from this leaf up to the claimed root.
  -h, --help               Show this help.

Exit codes:
  0  receipt valid
  1  receipt invalid
  2  usage or network error
`);
}

// ── encoding helpers (mirror src/crypto/ink.ts) ──

function base64urlDecode(s) {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "==".slice(0, (4 - (s.length % 4)) % 4);
  const bin = Buffer.from(padded, "base64");
  return new Uint8Array(bin.buffer, bin.byteOffset, bin.byteLength);
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    out[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return out;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ── multibase Ed25519 key decode (z-prefix, base58btc, 0xed 0x01 multicodec) ──

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function decodePublicKeyMultibase(mb) {
  if (typeof mb !== "string" || mb.length === 0 || mb[0] !== "z") {
    throw new Error("publicKeyMultibase must start with 'z' (base58btc)");
  }
  const body = mb.slice(1);
  let num = 0n;
  for (const ch of body) {
    const idx = BASE58.indexOf(ch);
    if (idx < 0) throw new Error(`invalid base58btc char: ${ch}`);
    num = num * 58n + BigInt(idx);
  }
  const bytes = [];
  while (num > 0n) {
    bytes.unshift(Number(num & 0xffn));
    num >>= 8n;
  }
  for (const ch of body) {
    if (ch !== "1") break;
    bytes.unshift(0);
  }
  if (bytes.length < 2 || bytes[0] !== 0xed || bytes[1] !== 0x01) {
    throw new Error("multibase key missing Ed25519 multicodec prefix (0xed 0x01)");
  }
  return new Uint8Array(bytes.slice(2));
}

// ── Merkle inclusion-proof walker (RFC 6962-derived) ──

async function hashPair(left, right) {
  const l = hexToBytes(left);
  const r = hexToBytes(right);
  const buf = new Uint8Array(1 + l.length + r.length);
  buf[0] = 0x01;
  buf.set(l, 1);
  buf.set(r, 1 + l.length);
  const out = new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
  return bytesToHex(out);
}

function largestPowerOf2LessThan(n) {
  if (n <= 1) return 0;
  let p = 1;
  while (p * 2 < n) p *= 2;
  return p;
}

async function recomputeRoot(currentHash, proof, proofIdx, leafIndex, start, size) {
  if (size === 1) {
    if (proofIdx !== proof.length) throw new Error("inclusion proof has unused entries");
    return currentHash;
  }
  if (proofIdx >= proof.length) {
    throw new Error("inclusion proof too short for declared treeSize");
  }
  const split = largestPowerOf2LessThan(size);
  if (leafIndex - start < split) {
    const leftResult = await recomputeRoot(currentHash, proof, proofIdx + 1, leafIndex, start, split);
    return hashPair(leftResult, proof[proofIdx]);
  }
  const rightResult = await recomputeRoot(currentHash, proof, proofIdx + 1, leafIndex, start + split, size - split);
  return hashPair(proof[proofIdx], rightResult);
}

// ── core verifier ──

const MAX_PROOF_LENGTH = 64;
const MAX_RECEIPT_BYTES = 64 * 1024;

function checkCheckpointShape(cp) {
  if (cp === null || typeof cp !== "object") return "laterCheckpoint must be an object";
  if (!Number.isInteger(cp.treeSize) || cp.treeSize < 0) return "laterCheckpoint.treeSize must be a non-negative integer";
  if (typeof cp.rootHash !== "string" || !/^[0-9a-f]{64}$/.test(cp.rootHash)) {
    return "laterCheckpoint.rootHash must be 64 lowercase hex chars";
  }
  return null;
}

function checkReceiptShape(r) {
  if (r === null || typeof r !== "object") return "receipt is not an object";
  if (typeof r.eventId !== "string" || r.eventId.length === 0) return "eventId missing";
  if (!Number.isInteger(r.leafIndex) || r.leafIndex < 0) return "leafIndex must be non-negative integer";
  if (!Number.isInteger(r.treeSize) || r.treeSize < 1) return "treeSize must be positive integer";
  if (r.leafIndex >= r.treeSize) return "leafIndex must be < treeSize";
  if (typeof r.rootHash !== "string" || !/^[0-9a-f]{64}$/.test(r.rootHash)) return "rootHash must be 64 lowercase hex chars";
  if (!Array.isArray(r.inclusionProof)) return "inclusionProof must be an array";
  if (r.inclusionProof.length > MAX_PROOF_LENGTH) return `inclusionProof exceeds max length of ${MAX_PROOF_LENGTH} entries`;
  for (const p of r.inclusionProof) {
    if (typeof p !== "string" || !/^[0-9a-f]{64}$/.test(p)) return "every inclusionProof entry must be 64 lowercase hex chars";
  }
  if (typeof r.timestamp !== "string" || r.timestamp.length === 0) return "timestamp missing";
  if (typeof r.serviceSignature !== "string" || r.serviceSignature.length === 0) return "serviceSignature missing";
  return null;
}

async function verifyReceipt(receipt, witnessPublicKey, eventHash, laterCheckpoint) {
  const steps = [];
  const structuralProblem = checkReceiptShape(receipt);
  if (structuralProblem) {
    steps.push({ name: "structure", pass: false, detail: structuralProblem });
    return { valid: false, steps };
  }
  steps.push({ name: "structure", pass: true });

  const signedPayload = {
    eventId: receipt.eventId,
    leafIndex: receipt.leafIndex,
    treeSize: receipt.treeSize,
    rootHash: receipt.rootHash,
    timestamp: receipt.timestamp,
  };
  const sigBase = `ink/audit-inclusion/v1\n${canonicalize(signedPayload)}`;
  let sigValid = false;
  try {
    const sig = base64urlDecode(receipt.serviceSignature);
    sigValid = await ed.verifyAsync(sig, new TextEncoder().encode(sigBase), witnessPublicKey);
  } catch (e) {
    steps.push({ name: "signature", pass: false, detail: e instanceof Error ? e.message : "signature decode failed" });
    return { valid: false, steps };
  }
  if (!sigValid) {
    steps.push({ name: "signature", pass: false, detail: "Ed25519 verification failed" });
    return { valid: false, steps };
  }
  steps.push({ name: "signature", pass: true });

  if (eventHash !== undefined) {
    if (!/^[0-9a-f]{64}$/.test(eventHash)) {
      steps.push({ name: "proof", pass: false, detail: "eventHash must be 64 lowercase hex chars" });
      return { valid: false, steps };
    }
    let computed;
    try {
      computed = await recomputeRoot(eventHash, receipt.inclusionProof, 0, receipt.leafIndex, 0, receipt.treeSize);
    } catch (e) {
      steps.push({ name: "proof", pass: false, detail: e instanceof Error ? e.message : "proof walk failed" });
      return { valid: false, steps };
    }
    if (computed !== receipt.rootHash) {
      steps.push({ name: "proof", pass: false, detail: "leaf-to-root walk did not reach claimed rootHash" });
      return { valid: false, steps };
    }
    steps.push({ name: "proof", pass: true });
  }

  if (laterCheckpoint !== undefined) {
    const cpShape = checkCheckpointShape(laterCheckpoint);
    if (cpShape) {
      steps.push({ name: "checkpoint", pass: false, detail: cpShape });
      return { valid: false, steps };
    }
    if (laterCheckpoint.treeSize < receipt.treeSize) {
      steps.push({
        name: "checkpoint",
        pass: false,
        detail: `checkpoint treeSize ${laterCheckpoint.treeSize} < receipt treeSize ${receipt.treeSize} (witness rewound the tree)`,
      });
      return { valid: false, steps };
    }
    if (laterCheckpoint.treeSize === receipt.treeSize && laterCheckpoint.rootHash !== receipt.rootHash) {
      steps.push({
        name: "checkpoint",
        pass: false,
        detail: "checkpoint rootHash differs from receipt rootHash at same treeSize (fork)",
      });
      return { valid: false, steps };
    }
    steps.push({ name: "checkpoint", pass: true });
  }

  return { valid: true, steps };
}

// ── witness HTTP helpers ──

/** Hard caps to prevent a malicious or compromised --witness URL
 *  from forcing unbounded memory growth via a streamed response. */
const MAX_RESPONSE_BYTES = 64 * 1024;
const FETCH_TIMEOUT_MS = 10_000;

/**
 * Fetch with byte cap and abort timeout. Aborts the response stream
 * mid-read if it exceeds the cap so we never allocate beyond it.
 * Returns the decoded UTF-8 text.
 */
async function fetchBounded(url) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(new Error("fetch timed out")), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: ctrl.signal });
    if (!res.ok) throw new Error(`fetch failed (${res.status}): ${url}`);
    if (!res.body) return "";
    const reader = res.body.getReader();
    const chunks = [];
    let total = 0;
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        if (value) {
          total += value.byteLength;
          if (total > MAX_RESPONSE_BYTES) {
            try { await reader.cancel(); } catch { /* ignore */ }
            throw new Error(`response exceeds ${MAX_RESPONSE_BYTES} bytes`);
          }
          chunks.push(value);
        }
      }
    } finally {
      try { reader.releaseLock(); } catch { /* ignore */ }
    }
    const merged = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) { merged.set(c, off); off += c.byteLength; }
    return new TextDecoder().decode(merged);
  } finally {
    clearTimeout(timer);
  }
}

async function fetchWitnessPublicKey(witnessUrl) {
  const url = `${witnessUrl.replace(/\/$/, "")}/.well-known/did.json`;
  const body = await fetchBounded(url);
  let doc;
  try { doc = JSON.parse(body); }
  catch { throw new Error(`DID document is not valid JSON: ${url}`); }
  const vm = doc?.verificationMethod?.[0]?.publicKeyMultibase;
  if (typeof vm !== "string") throw new Error("DID document missing verificationMethod[0].publicKeyMultibase");
  return decodePublicKeyMultibase(vm);
}

/**
 * Parse a C2SP tlog-checkpoint response. The body has three header
 * lines (origin, treeSize, rootHash), each terminated by \n, then a
 * blank line, then a signature line. We don't verify the signature
 * here (it'd require pre-fetching the witness key, which the caller
 * already does for the receipt). Just extract the header fields with
 * strict regexes so a malformed checkpoint can't fake-pass.
 */
function parseCheckpointBody(body) {
  const sepIdx = body.indexOf("\n\n");
  if (sepIdx < 0) return null;
  const header = body.slice(0, sepIdx);
  const lines = header.split("\n");
  if (lines.length !== 3) return null;
  if (!lines[0]) return null;
  if (!/^\d+$/.test(lines[1])) return null;
  const treeSize = parseInt(lines[1], 10);
  if (!Number.isInteger(treeSize) || treeSize < 0 || treeSize > Number.MAX_SAFE_INTEGER) return null;
  if (!/^[0-9a-f]{64}$/.test(lines[2])) return null;
  return { treeSize, rootHash: lines[2] };
}

async function fetchCurrentCheckpoint(witnessUrl) {
  const url = `${witnessUrl.replace(/\/$/, "")}/ink/v1/checkpoint`;
  let body;
  try {
    body = await fetchBounded(url);
  } catch {
    // Checkpoint cross-check is optional; downgrade fetch failures to
    // 'not available' rather than crashing the verifier.
    return null;
  }
  return parseCheckpointBody(body);
}

async function readStdin() {
  return new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      data += chunk;
      if (data.length > MAX_RECEIPT_BYTES) {
        reject(new Error(`receipt input exceeds ${MAX_RECEIPT_BYTES} bytes`));
        process.stdin.destroy();
      }
    });
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", reject);
  });
}

// ── main ──

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    process.exit(0);
  }
  if (!args.witness) {
    console.error("Error: --witness <url> is required.");
    printHelp();
    process.exit(2);
  }

  let witnessBase;
  try {
    witnessBase = validateWitnessUrl(args.witness, args.allowHttp);
  } catch (e) {
    console.error(`Error: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(2);
  }

  let raw;
  try {
    if (args.file) {
      // Stat first so a multi-GB file is rejected before allocation.
      const st = statSync(args.file);
      if (st.size > MAX_RECEIPT_BYTES) {
        throw new Error(`receipt file exceeds ${MAX_RECEIPT_BYTES} bytes (${st.size} on disk)`);
      }
      raw = readFileSync(args.file, "utf8");
    } else {
      raw = await readStdin();
    }
    if (raw.length > MAX_RECEIPT_BYTES) {
      throw new Error(`receipt exceeds ${MAX_RECEIPT_BYTES} bytes after decode`);
    }
  } catch (e) {
    console.error(`Error reading receipt: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(2);
  }

  let receipt;
  try {
    receipt = JSON.parse(raw);
  } catch (e) {
    console.error(`Error parsing receipt JSON: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(2);
  }

  let witnessPublicKey;
  try {
    witnessPublicKey = await fetchWitnessPublicKey(witnessBase);
  } catch (e) {
    console.error(`Error fetching witness identity: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(2);
  }

  const laterCheckpoint = await fetchCurrentCheckpoint(witnessBase);

  const result = await verifyReceipt(receipt, witnessPublicKey, args.eventHash, laterCheckpoint ?? undefined);

  console.log(`Receipt: eventId=${receipt?.eventId} leafIndex=${receipt?.leafIndex} treeSize=${receipt?.treeSize}`);
  console.log(`Witness: ${witnessBase}`);
  if (laterCheckpoint) {
    console.log(`Current checkpoint: treeSize=${laterCheckpoint.treeSize} rootHash=${laterCheckpoint.rootHash}`);
  } else {
    console.log("Current checkpoint: not available (skipping checkpoint cross-check)");
  }
  console.log("");
  for (const step of result.steps) {
    const mark = step.pass ? "PASS" : "FAIL";
    console.log(`  [${mark}] ${step.name}${step.detail ? ": " + step.detail : ""}`);
  }
  console.log("");
  if (result.valid) {
    console.log("RECEIPT VALID");
    process.exit(0);
  } else {
    console.log("RECEIPT INVALID");
    process.exit(1);
  }
}

main().catch((e) => {
  console.error(`Unexpected error: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(2);
});
