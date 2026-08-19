// The §3.3 transport signature base, written from the normative text in
// specs/ink-protocol.md rather than from `src/`.
import { jcs } from "./jcs.mjs";

// §3.3: the first line is the fixed literal `ink/0.1` for EVERY message,
// including ink/0.2 traffic. The transport base does not track the message
// `protocol` value; only the §3.6 body signature domain does.
const DOMAIN = "ink/0.1";

export function transportSignatureBase({ method, path, recipientDid, body, timestamp }) {
  // §3.3: the four scalar fields MUST NOT contain a CR or LF, because the base
  // is newline-delimited and an embedded newline lets two distinct inputs
  // collide on one signed string.
  for (const [name, value] of [
    ["METHOD", method],
    ["PATH", path],
    ["recipientDid", recipientDid],
    ["timestamp", timestamp],
  ]) {
    if (typeof value !== "string") throw new Error(`§3.3: ${name} is not a string`);
    if (/[\r\n]/.test(value)) throw new Error(`§3.3: ${name} contains CR or LF`);
  }

  // §3.3: METHOD is the uppercase HTTP method. Normalizing a lowercase one here
  // would hide exactly the kind of leniency this corpus exists to expose, so
  // this refuses instead.
  if (method !== method.toUpperCase()) {
    throw new Error(`§3.3: METHOD ${JSON.stringify(method)} is not uppercase`);
  }

  // §3.3 item 5: no field is stripped from the body before canonicalization.
  // The base commits to the body exactly as delivered, `signature` member
  // included. This is where it differs from the §3.6 body signature.
  return [DOMAIN, method, path, recipientDid, jcs(body), timestamp].join("\n");
}
