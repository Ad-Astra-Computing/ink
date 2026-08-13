import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

// The conformance profile freeze. Each manifest category carries a `profile`
// that pins which conformance profile requires it. The `base` set is the floor
// every conforming INK implementation MUST satisfy; the rest are capability
// gated. These frozen sets are the machine-readable half of
// specs/ink-conformance-profile.md: moving a category between profiles, or
// adding one without classifying it, must be a deliberate edit here (and in the
// Go tripwire), not a silent drift. See go/ink/conformance_manifest_test.go for
// the matching freeze on the second implementation.
const v1Dir = fileURLToPath(new URL("../conformance/v1/", import.meta.url).href);
const repoRoot = fileURLToPath(new URL("../", import.meta.url).href);

interface ManifestCategory {
  id: string;
  profile: string;
  spec: string;
}
interface Manifest {
  categories: ManifestCategory[];
}

const manifest = JSON.parse(readFileSync(v1Dir + "manifest.json", "utf8")) as Manifest;

const FROZEN_PROFILES = {
  audit: ["audit-query-response", "inclusion-receipt", "merkle-leaf"],
  authorization: ["agent-authorization", "authorization-grant"],
  base: [
    "agent-card",
    "agent-card-fetch",
    "agent-card-signature",
    "authorization-header",
    "connection-payload",
    "first-contact-transcript",
    "jcs-number",
    "jcs-string-safety",
    "key-rotation",
    "principal-normalization",
    "private-hostname",
    "replay-freshness",
    "signature-base",
    "signed-body-utf8",
    "timestamp-validity",
  ],
  containment: ["handshake-message"],
  delegation: ["authorization-chain"],
  discovery: ["discovery-query-envelope"],
  encryption: ["payload-encryption"],
  // Staged: anchored and agreed now, required on a scheduled date. A staged
  // category is NOT a conformance obligation, and it is NOT in `base`, so the
  // frozen base set above is untouched by its presence. The flip moves its id
  // from this list to `base` in both tripwires and retags the manifest entry.
  staged: ["agent-card-signature-phase-c"],
  witness: ["merkle-checkpoint", "merkle-consistency", "merkle-inclusion"],
} satisfies Record<string, string[]>;

const KNOWN_PROFILES = Object.keys(FROZEN_PROFILES) as (keyof typeof FROZEN_PROFILES)[];

function categoriesByProfile(profile: string): string[] {
  return manifest.categories
    .filter((c) => c.profile === profile)
    .map((c) => c.id)
    .sort();
}

describe("conformance profile freeze", () => {
  it("tags every manifest category with a known profile", () => {
    for (const cat of manifest.categories) {
      expect(KNOWN_PROFILES, cat.id).toContain(cat.profile);
    }
  });

  it("classifies every category into exactly one frozen profile", () => {
    const frozenTotal = Object.values(FROZEN_PROFILES).reduce((n, ids) => n + ids.length, 0);
    expect(frozenTotal).toBe(manifest.categories.length);
  });

  for (const profile of KNOWN_PROFILES) {
    it(`freezes the ${profile} profile category set`, () => {
      expect(categoriesByProfile(profile)).toEqual(FROZEN_PROFILES[profile]);
    });
  }

  it("documents the freeze in specs/ink-conformance-profile.md", () => {
    const spec = readFileSync(repoRoot + "specs/ink-conformance-profile.md", "utf8");
    // The normative doc must name every profile and list every base category,
    // so the prose cannot drift from the machine-readable manifest.
    for (const profile of KNOWN_PROFILES) {
      expect(spec, profile).toContain(profile);
    }
    for (const id of FROZEN_PROFILES.base) {
      expect(spec, id).toContain(id);
    }
  });
});
