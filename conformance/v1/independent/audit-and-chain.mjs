// The remaining fixed signing domains and the RFC 6962 leaf hash, written from
// their normative sections rather than from `src/`. See README.md here.
import { createHash } from "node:crypto";
import { jcs } from "./jcs.mjs";

// Protocol §3.6 "Other signing domains": the audit and witness sub-protocols
// use fixed prefixes over JCS of their payloads, each excluding the signature
// member it is about to produce.
const AUDIT_EVENT = "ink/audit-event\n";
const AUDIT_RESPONSE = "ink/audit-response\n";
const AUDIT_QUERY_RESPONSE = "ink/audit-query-response/v1\n";
// ink-authorization-chain.md: the parent hash uses the same domain-then-newline
// pattern as the body-signature scheme.
const DELEGATION_LINK = "ink/delegation-link\n";

function without(object, member) {
  if (object === null || typeof object !== "object" || Array.isArray(object)) {
    throw new Error("expected a JSON object");
  }
  const out = {};
  for (const key of Object.keys(object)) {
    if (key !== member) out[key] = object[key];
  }
  return out;
}

export function auditEventSignatureBase(event) {
  return `${AUDIT_EVENT}${jcs(without(event, "agentSignature"))}`;
}

// Protocol §3.6: a bilateral audit slice signs over JCS of the events array.
export function auditResponseSignatureBase(events) {
  return `${AUDIT_RESPONSE}${jcs(events)}`;
}

export function auditQueryResponseSignatureBase(response) {
  return `${AUDIT_QUERY_RESPONSE}${jcs(without(response, "serviceSignature"))}`;
}

// ink-merkle-leaf.md: SHA-256(0x00 || JCS(event without agentSignature)),
// returned as 64 lowercase hex characters. The 0x00 prefix is RFC 6962's leaf
// domain separator, which is what stops a leaf being reinterpreted as an
// interior node.
export function merkleLeafHash(event) {
  const canonical = jcs(without(event, "agentSignature"));
  const hash = createHash("sha256");
  hash.update(Uint8Array.from([0x00]));
  hash.update(Buffer.from(canonical, "utf8"));
  return hash.digest("hex");
}

// ink-authorization-chain.md: the parent hash is base64url without padding of
// SHA-256 over the domain, a newline, and the JCS of the FULL parent link
// INCLUDING its signature. Including the signature is the point: the child
// commits to the parent as it was actually signed and presented, not to an
// unsigned skeleton of it.
export function delegationLinkParentHash(parentLink) {
  const digest = createHash("sha256")
    .update(Buffer.from(`${DELEGATION_LINK}${jcs(parentLink)}`, "utf8"))
    .digest();
  return digest.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
