#!/usr/bin/env node
/**
 * CLI: verify an INK inclusion receipt against a witness's published
 * identity and current checkpoint. Self-contained ESM module so the
 * shebang resolves on any supported Node install without a TS toolchain.
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
// The receipt is a signed artifact, so it goes through the same text-level gate
// as every other signed body rather than a bare JSON.parse. dist/ ships in the
// same package as this file, so the import resolves wherever the CLI runs.
import { parseSignedBodyBytes } from "../dist/index.js";

// ── arg parsing ──

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--file" || a === "-f") out.file = argv[++i];
    else if (a === "--witness" || a === "-w") out.witness = argv[++i];
    else if (a === "--origin") out.origin = argv[++i];
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
      --origin <name>      Optional. Expected checkpoint origin (log identity)
                            to bind the signed checkpoint to. Enables the
                            checkpoint cross-check: the current checkpoint's
                            signature is verified against the witness key, and
                            when it is newer than the receipt and the witness
                            serves an RFC 6962 consistency proof, that proof is
                            verified so a forked history is caught. If the witness
                            serves no proof the consistency step is reported as
                            skipped, not passed. When --origin is omitted the
                            cross-check is skipped rather than trusting an
                            unverified checkpoint body.
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

const EMPTY_TREE_ROOT = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/**
 * Verify an RFC 6962 Section 2.1.2 consistency proof (the first-sized tree is a
 * prefix of the second). Mirrors verifyConsistencyProof() in
 * src/audit/inclusion-receipt.ts — keep them in sync.
 */
async function verifyConsistencyProofCli(first, firstRoot, second, secondRoot, proof) {
  const isHash = (s) => typeof s === "string" && /^[0-9a-f]{64}$/.test(s);
  if (!Number.isSafeInteger(first) || !Number.isSafeInteger(second)) return false;
  if (first < 0 || second < 0) return false;
  if (!isHash(firstRoot) || !isHash(secondRoot)) return false;
  if (!Array.isArray(proof) || !proof.every(isHash) || proof.length > 64) return false;
  if (first > second) return false;
  if (first === second) return proof.length === 0 && firstRoot === secondRoot;
  if (first === 0) return proof.length === 0 && firstRoot === EMPTY_TREE_ROOT;

  let node = first - 1;
  let last = second - 1;
  while (node % 2 === 1) { node = Math.floor(node / 2); last = Math.floor(last / 2); }
  let i = 0;
  const take = () => (i < proof.length ? proof[i++] : null);
  let oldHash;
  if (node > 0) { const h = take(); if (h === null) return false; oldHash = h; } else { oldHash = firstRoot; }
  let newHash = oldHash;
  while (node > 0) {
    if (node % 2 === 1) {
      const h = take(); if (h === null) return false;
      oldHash = await hashPair(h, oldHash);
      newHash = await hashPair(h, newHash);
    } else if (node < last) {
      const h = take(); if (h === null) return false;
      newHash = await hashPair(newHash, h);
    }
    node = Math.floor(node / 2); last = Math.floor(last / 2);
  }
  while (last > 0) { const h = take(); if (h === null) return false; newHash = await hashPair(newHash, h); last = Math.floor(last / 2); }
  if (i !== proof.length) return false;
  return oldHash === firstRoot && newHash === secondRoot;
}

// ── core verifier ──

const MAX_PROOF_LENGTH = 64;
// Matches Go's MaxInclusionReceiptBytes. The two have to agree, or the CLI
// refuses a receipt the library verifiers accept: a signed core at the
// canonicalize ceiling can legitimately reach several MiB on the wire once
// escaped, since the signature verifies against the re-canonicalized core
// rather than the raw bytes.
const MAX_RECEIPT_BYTES = 8 * 1024 * 1024;

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
    // RFC 8032 strict verification, matching the library (reject small-order keys).
    sigValid = await ed.verifyAsync(sig, new TextEncoder().encode(sigBase), witnessPublicKey, { zip215: false });
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
 * Verify a signed C2SP tlog-checkpoint and return { treeSize, rootHash,
 * origin }, or null if the signature, origin, or format is invalid. The
 * Ed25519 signature covers the body bytes `<origin>\n<treeSize>\n<rootHash>`
 * (no trailing newline). The anti-rollback cross-check below only means
 * anything against a checkpoint whose signature we have verified against the
 * witness key, so this MUST verify, not just parse.
 *
 * Mirrors verifyCheckpoint() in src/ink/checkpoint.ts — keep them in sync.
 */
async function verifyCheckpointBody(signed, witnessPublicKey, expectedOrigin) {
  if (typeof signed !== "string" || signed.length === 0 || signed.length > 4096) return null;
  const SEP = "\n\n-- ";
  const idx = signed.indexOf(SEP);
  if (idx < 0) return null;
  const body = signed.slice(0, idx);
  const lines = body.split("\n");
  if (lines.length !== 3) return null;
  const [origin, sizeLine, rootHash] = lines;
  if (!origin || origin.length > 256) return null;
  if (!/^\d+$/.test(sizeLine)) return null;
  const treeSize = parseInt(sizeLine, 10);
  if (!Number.isInteger(treeSize) || treeSize < 0 || treeSize > Number.MAX_SAFE_INTEGER) return null;
  if (!/^[0-9a-f]{64}$/.test(rootHash)) return null;
  // The expected origin must be supplied by the caller (a trusted value), not
  // taken from the checkpoint body, so a witness key that signs several origins
  // cannot substitute a checkpoint for a different log than the receipt's.
  if (typeof expectedOrigin !== "string" || expectedOrigin.length === 0) return null;
  if (origin !== expectedOrigin) return null;
  const sigLines = signed.slice(idx + 2).split("\n").filter((l) => l.length > 0);
  if (sigLines.length === 0 || sigLines.length > 8) return null;
  const bodyBytes = new TextEncoder().encode(body);
  for (const line of sigLines) {
    if (!line.startsWith("-- ")) return null;
    const rest = line.slice(3);
    const sp = rest.indexOf(" ");
    if (sp < 0) return null;
    if (rest.slice(0, sp) !== expectedOrigin) continue;
    try {
      const sig = base64urlDecode(rest.slice(sp + 1));
      if (sig.length !== 64) return null;
      const ok = await ed.verifyAsync(sig, bodyBytes, witnessPublicKey, { zip215: false });
      return ok ? { treeSize, rootHash, origin } : null;
    } catch {
      return null;
    }
  }
  return null;
}

async function fetchCurrentCheckpoint(witnessUrl, witnessPublicKey, expectedOrigin) {
  // No trusted origin, no cross-check: refuse to trust the checkpoint body's
  // self-asserted origin. Pass --origin <witness-origin> to enable it.
  if (typeof expectedOrigin !== "string" || expectedOrigin.length === 0) return null;
  const url = `${witnessUrl.replace(/\/$/, "")}/ink/v1/checkpoint`;
  let body;
  try {
    body = await fetchBounded(url);
  } catch {
    // Checkpoint cross-check is optional; downgrade fetch failures to
    // 'not available' rather than crashing the verifier.
    return null;
  }
  return verifyCheckpointBody(body, witnessPublicKey, expectedOrigin);
}

async function fetchConsistencyProof(witnessUrl, first, second) {
  const url = `${witnessUrl.replace(/\/$/, "")}/ink/v1/consistency?first=${first}&second=${second}`;
  let body;
  try {
    body = await fetchBounded(url);
  } catch {
    // A witness that does not serve consistency proofs downgrades the check to
    // 'not available' rather than failing the receipt.
    return null;
  }
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch {
    return null;
  }
  if (!parsed || !Array.isArray(parsed.proof)) return null;
  return parsed.proof;
}

/**
 * Read the receipt from stdin as BYTES, not text. The signature covers the raw
 * bytes, so decoding here with Node's non-fatal decoder would substitute U+FFFD
 * for an invalid sequence and hand the verifier something the sender never
 * signed. The fatal decode belongs to `parseSignedBodyBytes`.
 */
async function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    process.stdin.on("data", (chunk) => {
      total += chunk.length;
      if (total > MAX_RECEIPT_BYTES) {
        reject(new Error(`receipt input exceeds ${MAX_RECEIPT_BYTES} bytes`));
        process.stdin.destroy();
        return;
      }
      chunks.push(chunk);
    });
    process.stdin.on("end", () => resolve(new Uint8Array(Buffer.concat(chunks))));
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
      raw = new Uint8Array(readFileSync(args.file));
    } else {
      raw = await readStdin();
    }
    if (raw.length > MAX_RECEIPT_BYTES) {
      throw new Error(`receipt exceeds ${MAX_RECEIPT_BYTES} bytes`);
    }
  } catch (e) {
    console.error(`Error reading receipt: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(2);
  }

  let receipt;
  try {
    receipt = parseSignedBodyBytes(raw);
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

  // The checkpoint cross-check only carries weight against a checkpoint whose
  // Ed25519 signature we have verified against the witness key. An unverified
  // checkpoint (bad/absent signature, or origin mismatch) is dropped so the
  // cross-check is skipped rather than trusting attacker-controlled values.
  const laterCheckpoint = await fetchCurrentCheckpoint(witnessBase, witnessPublicKey, args.origin);

  const result = await verifyReceipt(receipt, witnessPublicKey, args.eventHash, laterCheckpoint ?? undefined);

  // Append-only proof: when the signature-verified checkpoint is strictly newer
  // than the receipt's tree, fetch and verify an RFC 6962 consistency proof, so
  // a witness that forked its history between the two snapshots is caught. The
  // checkpoint size comparison alone cannot detect a same-prefix fork.
  if (laterCheckpoint && Number.isInteger(receipt?.treeSize) && laterCheckpoint.treeSize > receipt.treeSize) {
    const proof = await fetchConsistencyProof(witnessBase, receipt.treeSize, laterCheckpoint.treeSize);
    if (proof === null) {
      // Honest downgrade: the witness did not serve a usable consistency proof.
      // Mark it skipped (NOT passed) so a witness that forked cannot look clean
      // by withholding the endpoint; the checkpoint signature, rewind, and
      // same-size fork checks still ran.
      result.steps.push({
        name: "consistency",
        skip: true,
        detail: "not checked (witness did not serve a consistency proof); append-only growth was not verified",
      });
    } else {
      const consistent = await verifyConsistencyProofCli(
        receipt.treeSize, receipt.rootHash, laterCheckpoint.treeSize, laterCheckpoint.rootHash, proof,
      );
      if (consistent) {
        result.steps.push({
          name: "consistency",
          pass: true,
          detail: `receipt tree (size ${receipt.treeSize}) is an append-only prefix of the checkpoint (size ${laterCheckpoint.treeSize})`,
        });
      } else {
        result.steps.push({
          name: "consistency",
          pass: false,
          detail: `receipt tree (size ${receipt.treeSize}) is NOT an append-only prefix of the checkpoint (size ${laterCheckpoint.treeSize}); the witness forked its history`,
        });
        result.valid = false;
      }
    }
  }

  console.log(`Receipt: eventId=${receipt?.eventId} leafIndex=${receipt?.leafIndex} treeSize=${receipt?.treeSize}`);
  console.log(`Witness: ${witnessBase}`);
  if (laterCheckpoint) {
    console.log(`Current checkpoint (signature verified): treeSize=${laterCheckpoint.treeSize} rootHash=${laterCheckpoint.rootHash}`);
  } else if (!args.origin) {
    console.log("Current checkpoint: cross-check skipped (pass --origin <witness-origin> to enable the anti-rollback check)");
  } else {
    console.log("Current checkpoint: not available or signature unverified (skipping checkpoint cross-check)");
  }
  console.log("");
  for (const step of result.steps) {
    const mark = step.skip ? "SKIP" : step.pass ? "PASS" : "FAIL";
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
