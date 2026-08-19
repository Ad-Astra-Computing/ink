// The Agent Card and rotation-link signature bases, written from
// specs/ink-agent-card-signature.md §3.2 and §5 rather than from `src/`.
import { jcs } from "./jcs.mjs";

// §3.2: not version-keyed. Card format evolution is governed by the card's own
// `protocol` field, which is inside the signed bytes.
const CARD_DOMAIN = "ink/agent-card";
const ROTATION_DOMAIN = "ink/card-rotation";

// Remove exactly one member and nothing else. Written as an explicit copy so a
// reader can see that no other field is dropped, reordered or defaulted; JCS
// sorts the keys, so the order this produces does not matter.
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

// §3.2: the full card with `cardSignature` removed and NOTHING else stripped.
// Only cardSignature goes, because it cannot commit to itself.
export function cardSignatureBase(card) {
  return `${CARD_DOMAIN}\n${jcs(without(card, "cardSignature"))}`;
}

// §5: the full link with `signature` removed and nothing else stripped. The
// spec is explicit that rebuilding from a named-field subset such as
// {keySetVersion, signing, prevKeyId} is forbidden for signer and verifier
// alike, because it would leave every other member outside the signature.
export function rotationLinkSignatureBase(link) {
  return `${ROTATION_DOMAIN}\n${jcs(without(link, "signature"))}`;
}
