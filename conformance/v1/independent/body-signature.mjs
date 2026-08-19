// The §3.6 body signature base, written from specs/ink-protocol.md rather than
// from `src/`. Distinct from the §3.3 transport base in two ways that are easy
// to conflate: the domain is version-keyed, and the `signature` member IS
// removed before canonicalizing (§3.3 removes nothing).
import { jcs } from "./jcs.mjs";

// §3.6: only the exact string "ink/0.2" switches domains, so no other value can
// smuggle one in. The legacy domain is retained permanently so every signature
// ever produced still verifies.
const INK_SIGN = "ink/sign\n";
const LEGACY_SIGN = "tulpa/sign\n";

export function bodySignatureDomain(object) {
  return object?.protocol === "ink/0.2" ? INK_SIGN : LEGACY_SIGN;
}

export function bodySignatureBase(object) {
  if (object === null || typeof object !== "object" || Array.isArray(object)) {
    throw new Error("§3.6: expected a JSON object");
  }
  const withoutSignature = {};
  for (const key of Object.keys(object)) {
    if (key !== "signature") withoutSignature[key] = object[key];
  }
  // The domain is chosen from the object's own `protocol`, which is inside the
  // signed bytes, so a relabelled object verifies under the wrong domain and
  // fails. A verifier picks exactly one domain and MUST NOT try the other.
  return `${bodySignatureDomain(object)}${jcs(withoutSignature)}`;
}
