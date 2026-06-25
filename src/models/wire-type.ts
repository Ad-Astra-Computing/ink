import { z } from "zod";

// INK message `type` fields historically carry the `network.tulpa.*` prefix (an
// artifact of INK's origin; Ad Astra Computing stewards the protocol). The
// vendor-neutral `network.ink.*` prefix is introduced as a backward-compatible,
// receiver-first transition, mirroring how `ink/0.2` negotiated the
// body-signature domain: receivers ACCEPT both spellings, senders keep EMITTING
// `network.tulpa.*` by default until an explicit capability negotiates otherwise.
//
// The dual-accept is purely a receiver-side leniency and is INDEPENDENT of the
// signed `protocol` field (which only selects the body-signature domain). A
// validated message retains its actual `type` string, so every signature, hash,
// receipt, and AEAD check binds the spelling that was on the wire, never a
// normalized one. See specs/ink-compatibility-policy.md §1.3.
export function dualWireType<S extends string>(suffix: S) {
  return z.union([
    z.literal(`network.tulpa.${suffix}` as const),
    z.literal(`network.ink.${suffix}` as const),
  ]);
}

// The legacy and vendor-neutral spellings of a single type suffix, for runtime
// membership checks outside a Zod schema (e.g. the encrypted-envelope guard and
// the receipt loop-prevention set).
export function wireTypeAliases<S extends string>(suffix: S): readonly [`network.tulpa.${S}`, `network.ink.${S}`] {
  return [`network.tulpa.${suffix}`, `network.ink.${suffix}`] as const;
}
