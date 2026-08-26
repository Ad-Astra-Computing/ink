// Sender-to-receiver e2e against a LIVE INK receiver, using the tarball that
// was actually published to npm rather than the local build. The hermetic
// version of this lives in the Docker interop lab and runs on every PR; this
// one answers a different question, which only has an answer once a release
// exists: does the artifact adopters install sign envelopes a real receiver
// accepts?
//
//   node scripts/e2e-published.mjs [version]
//
// The version defaults to the local package.json version, so a post-publish
// step needs no argument. Environment overrides:
//   INK_E2E_ENDPOINT   inbound endpoint (default the public echo receiver)
//   INK_E2E_DID        receiver DID, must match the endpoint's card
//   INK_E2E_TIMEOUT_MS per-request timeout (default 15000)
//
// Exits 0 only when a well-formed envelope is ACCEPTED and a tampered one is
// REJECTED. The negative control is not optional: a 200 alone proves the
// endpoint is reachable, not that it verifies anything.
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const version =
  process.argv[2] ?? JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;
const ENDPOINT = process.env.INK_E2E_ENDPOINT ?? "https://ink-echo.tulpa.network/ink/v1/inbound";
const RECEIVER_DID = process.env.INK_E2E_DID ?? "did:web:ink-echo.tulpa.network";
const TIMEOUT_MS = Number(process.env.INK_E2E_TIMEOUT_MS ?? 15000);
const PATH_COMPONENT = new URL(ENDPOINT).pathname;

function fail(msg) {
  console.error(`[FAIL] ${msg}`);
  process.exit(1);
}

async function post(body, authorization, timestamp) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(ENDPOINT, {
      method: "POST",
      signal: controller.signal,
      headers: {
        "content-type": "application/json",
        authorization,
        "ink-timestamp": timestamp,
      },
      body: JSON.stringify(body),
    });
    return { status: res.status, text: await res.text() };
  } finally {
    clearTimeout(timer);
  }
}

// Install into a throwaway directory so the local build cannot satisfy the
// import. This is the whole point: the code under test is the registry's copy.
const dir = mkdtempSync(join(tmpdir(), "ink-e2e-"));
try {
  console.log(`installing @adastracomputing/ink@${version} from the registry`);
  try {
    execFileSync("npm", ["init", "-y"], { cwd: dir, stdio: "ignore" });
    execFileSync("npm", ["install", `@adastracomputing/ink@${version}`], {
      cwd: dir,
      stdio: "ignore",
    });
  } catch {
    // The common cause is running before the publish lands, or a typo'd
    // version. Say that rather than dumping an npm stack trace.
    fail(`could not install @adastracomputing/ink@${version} from the registry`);
  }

  const require = createRequire(join(dir, "index.js"));
  const installed = require("@adastracomputing/ink/package.json");
  if (installed.version !== version) {
    fail(`installed ${installed.version}, expected ${version}`);
  }
  const ink = require("@adastracomputing/ink");
  console.log(`installed ${installed.name}@${installed.version} (${Object.keys(ink).length} exports)`);

  const kp = await ink.generateKeypair();
  // did:key, not the ink: key-derived spelling: the public echo receiver
  // resolves did:key and did:web senders only.
  const senderId = `did:key:${ink.encodePublicKeyMultibase(kp.publicKey)}`;
  const now = new Date().toISOString();
  const body = {
    protocol: "ink/0.1",
    id: crypto.randomUUID(),
    correlationId: crypto.randomUUID(),
    createdAt: now,
    from: senderId,
    to: RECEIVER_DID,
    intent: "ping",
    payload: { note: `published-artifact e2e for ${version}` },
    timestamp: now,
    nonce: crypto.randomUUID(),
  };

  // §3.6 signs the body WITHOUT its signature member; §3.3 then canonicalizes
  // the body exactly as delivered, signature member included. That ordering is
  // the one the signature-base category pins in both directions, so getting it
  // wrong here fails against a conformant receiver.
  const bodySignature = await ink.signMessage(body, kp.privateKey);
  const wireBody = { ...body, signature: bodySignature };
  const transportSignature = await ink.signInkMessage(
    { method: "POST", path: PATH_COMPONENT, recipientDid: RECEIVER_DID, body: wireBody, timestamp: now },
    kp.privateKey,
  );
  const authorization = `INK-Ed25519 ${transportSignature}`;

  const accepted = await post(wireBody, authorization, now);
  console.log(`accept case: HTTP ${accepted.status} ${accepted.text.slice(0, 200)}`);
  if (accepted.status !== 200) fail(`receiver rejected a well-formed envelope (${accepted.status})`);

  let parsed = null;
  try {
    parsed = JSON.parse(accepted.text);
  } catch {
    fail("accept response was not JSON");
  }
  if (parsed.ok !== true) fail(`receiver did not acknowledge: ${accepted.text.slice(0, 200)}`);
  // Bind the acknowledgement to THIS message. Without these, any cached or
  // unrelated 200 would pass.
  if (parsed.receiverDid !== RECEIVER_DID) fail(`receiverDid ${parsed.receiverDid}`);
  if (parsed.inReplyTo !== body.id) fail(`inReplyTo ${parsed.inReplyTo} != ${body.id}`);
  if (parsed.correlationId !== body.correlationId) fail(`correlationId ${parsed.correlationId}`);
  if (parsed.receivedIntent !== body.intent) fail(`receivedIntent ${parsed.receivedIntent}`);
  console.log("[OK] well-formed envelope accepted and echoed back, bound to this message");

  // Negative control: same transport signature, payload mutated after signing.
  const tampered = { ...wireBody, payload: { note: "tampered after signing" } };
  const rejected = await post(tampered, authorization, now);
  console.log(`tamper case: HTTP ${rejected.status} ${rejected.text.slice(0, 160)}`);
  if (rejected.status === 200) {
    fail("receiver ACCEPTED a tampered body, so the accept case proves nothing");
  }
  console.log("[OK] tampered envelope rejected");

  console.log(`\ne2e-published: @adastracomputing/ink@${version} interoperates with ${RECEIVER_DID}`);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
