# Governance

INK is stewarded by Ad Astra Computing. This document says who decides what, how a change to the protocol becomes official, what a 1.0 commitment means and how the project survives the loss of a maintainer, the GitHub organization or the npm scope. It is deliberately concrete. If a rule here conflicts with a passing convention in a pull request thread, the rule here wins.

The spec and the library in this repository are treated as one artifact. Governance covers both.

## Roles

**Contributors** are anyone who opens an issue, a discussion or a pull request. Contributing does not require a role grant. It requires a signed-off commit (see [`CONTRIBUTING.md`](CONTRIBUTING.md)) and acceptance of the [Code of Conduct](CODE_OF_CONDUCT.md).

**Maintainers** hold commit and review authority. A maintainer can approve and merge a pull request, cut a release tag and move an npm dist-tag. Maintainers are listed by name and by signing-key fingerprint in the [Signers](#signers) section below.

**The lead maintainer** holds final authority on protocol and release decisions and breaks ties. Today that is Jason Odoom (`jason@adastracomputing.com`), signing key `D75B 8BCB 3A0C 402B 7B3D  1A5F A465 7367 1D50 E3D8`. Final authority is a role, not a person for all time. The succession rules below describe how it moves.

There is intentionally no larger committee. INK is small and the review load is real, so the model is a working maintainer with a documented second, not a foundation board.

## Deciding a spec or protocol change

A protocol change is any change to the on-wire format, the signing base, the trust model, the key-rotation authority rule, the conformance corpus or anything else the [compatibility policy](specs/ink-compatibility-policy.md) governs. Bug fixes and test improvements that do not touch wire behavior are not protocol changes and follow the ordinary pull-request path in `CONTRIBUTING.md`.

Protocol changes move through four steps.

1. **Propose.** Open a discussion first, as `CONTRIBUTING.md` requires. State the problem, the wire impact and which compatibility tier the change lands in (backward-compatible minor or a break). A change with no discussion and a surprise wire delta will be sent back to this step.

2. **Specify.** The spec is edited first, in the same pull request or an earlier one it references. Spec and implementation stay in sync by rule. A pull request that changes wire behavior without a matching `specs/` edit is not mergeable regardless of how good the code is.

3. **Review against the policy.** Every wire change MUST be evaluated against [`specs/ink-compatibility-policy.md`](specs/ink-compatibility-policy.md) before it merges. That is the normative contract, not a courtesy. Review confirms the change is placed in the right version tier, that receivers can still accept prior minors through the stated transition window and that the conformance corpus is updated so the TypeScript reference and the independent Go verifier still reach the same accept-or-reject decision on every vector. All CI gates must be green, including `go-conformance` and the manifest-integrity cross-check.

4. **Accept.** A maintainer approves and merges. A change that breaks wire compatibility, alters the compatibility policy itself or touches the frozen base profile needs the lead maintainer's explicit sign-off in addition to a passing review. Silence is not consent for those. For everything else a single maintainer approval on a green pull request is enough, and the lead maintainer can be that approver.

When maintainers disagree and cannot resolve it in the pull request, the lead maintainer decides and records the reasoning in the thread. Decisions are made in the open on the issue, the discussion or the pull request. There is no private acceptance channel for protocol changes. Security reports are the one exception and follow [`SECURITY.md`](SECURITY.md).

## Versioning authority and what "1.0" means

Version tiers and transition rules are set by the [compatibility policy](specs/ink-compatibility-policy.md) and summarized in [`docs/maturity.md`](docs/maturity.md). Authority to cut a version and to move a dist-tag rests with the maintainers, and the promotion of a release to the `latest` tag or to a 1.0 line rests with the lead maintainer.

Publishing is already mechanical and traceable. Releases are cut from signed tags through the [`publish`](.github/workflows/publish.yml) workflow, which builds under the pinned Nix toolchain, publishes to npm with sigstore OIDC provenance and creates the GitHub Release from the in-repo changelog. Pre-1.0 tarballs go to the `next` dist-tag. `latest` only advances when a maintainer promotes a specific version by hand.

A promotion moves the `latest` dist-tag onto the exact version that soaked, and it is owner-attended: after a release pull request lands the dist-tag pin naming the destination, the lead maintainer verifies the pin (`npm run check:release-pin`), confirms the release gate, and runs `npm dist-tag add` locally with their own second factor. npm's trusted publishing cannot authenticate a dist-tag move (npm/cli#8547) and the automation tokens that could are being phased out, so no stored npm credential exists anywhere in the pipeline, and none is minted for a promote. As a fallback for when no maintainer can run the attended move, a `latest-v<version>` tag re-cuts the soaked version as a patch and publishes it to `latest` through the same build, test and packaging gauntlet under the OIDC provenance identity; the re-cut ships a version string that did not itself soak, which is why it is the exception rather than the promotion path. Ordinary `v<version>` tags keep publishing to `next` unchanged. Both tag patterns are signed, and the `latest-v*` path additionally runs under the `npm-release` environment, so any environment protection rule applies to that path.

A release pull request that cuts a version or moves a dist-tag also updates [`governance/releases/npm-dist-tags.json`](governance/releases/npm-dist-tags.json). That file is the offline source of truth for every dist-tag quoted in prose, and `npm run check:facts` fails once the registry moves past it, so a release cannot leave the documents describing the previous line.

That update is enforced, not remembered. Every path that can move a dist-tag runs `npm run check:release-pin` first, and it refuses to publish or promote while the pin names a version other than the one about to be moved. The check runs after the full build and test gauntlet and before anything reaches the registry, so a forgotten pin bump costs a re-cut rather than a released version and a red `main`. The pin stays committed and offline: it is what lets `check:facts` settle a dist-tag claim on a runner with no network access, so nothing may rewrite it from the live registry.

Committing to "1.0" is a governance act, not an automatic outcome of green CI. It means:

- The mandatory base profile is frozen. After 1.0, the base wire contract does not take a breaking change without a major version. The frozen 1.0 base is exactly the set recorded in [`governance/releases/1.0-readiness-evidence.md`](governance/releases/1.0-readiness-evidence.md), pinned to a named conformance corpus id and a SHA-256 manifest-integrity anchor. A verifier cannot drift from that corpus without the anchor changing.
- The soak-dependent evidence in that readiness record has been written and reviewed. The exit criteria are normative and are stated once, in [§2 of the readiness record](governance/releases/1.0-readiness-evidence.md#2-soak-exit-criteria). This document does not restate them, so there is one place to read and one place to amend. Meeting the bar is necessary. It is not automatically sufficient. The lead maintainer still gates the promotion.
- The dual-implementation agreement holds. A 1.0 wire claim is only credible while the TypeScript reference and the Go verifier agree on the whole base corpus. Losing that agreement is a release blocker.

Nothing in the readiness record or in this document authorizes a 1.0 promotion on its own. It is a deliberate manual step behind an explicit human gate, and that gate is the lead maintainer.

## Continuity and succession

The point of this section is that INK does not depend on one person staying reachable. If the current lead maintainer disappears tomorrow, another maintainer can review a change, cut a signed release and recover the project's identity from what is written here and committed to the repository.

### Signers

The project publishes its maintainer set and their signing keys so an adopter can verify that a tag or a commit came from a real maintainer and not an impersonator.

| Role | Name | GPG key fingerprint |
|------|------|---------------------|
| Lead maintainer | Jason Odoom | `D75B 8BCB 3A0C 402B 7B3D  1A5F A465 7367 1D50 E3D8` |

The second-signer seat is currently open. Until it is filled with an independently held key the project's bus factor is one and a 1.0 release is blocked.

The key is Ed25519, and the maintainer holds their own private key. Release tags and commits are GPG-signed. An adopter verifies a release by checking the tag signature against the fingerprint in this table.

### Adding a maintainer

A second maintainer is not a formality to defer. Until this table has two working signers with two independently held keys, the project's bus factor is one and that is a release blocker for 1.0.

To add a maintainer:

1. The lead maintainer nominates the candidate in a discussion or, for a sensitive nomination, privately to the existing maintainers. The bar is a track record of merged, spec-aware contributions and demonstrated judgment on the compatibility policy.
2. The candidate generates a signing key on hardware they control and publishes the public key. They do not share private key material with anyone.
3. The lead maintainer adds the candidate's name, role and fingerprint to the [Signers](#signers) table in a signed commit, grants GitHub write access and adds them to the npm scope with publish rights.
4. The candidate proves the setup end to end by signing off and merging one real change, then verifying they can produce a signed tag that the `publish` workflow accepts.

Removing a maintainer reverses those steps: strike the row, revoke GitHub and npm access and, if the departure is not amicable, rotate any shared credentials the departing maintainer could have held.

### Key rotation and backup

Signing keys are rotated on a fixed schedule and immediately on any suspected compromise.

- **Scheduled rotation.** Each maintainer rotates their signing key on a schedule of every 2 years. The new fingerprint is committed to the [Signers](#signers) table in a commit signed by the outgoing key before that key is retired, so the chain of trust is continuous and an adopter can follow one signature to the next.
- **Compromise.** On suspected private-key compromise, the maintainer rotates immediately, publishes the new fingerprint and announces the retired fingerprint as no longer trusted in the changelog and on the docs site. Tags signed by a key before its published compromise date remain verifiable against that key. Tags dated after are not trusted.
- **Backup.** Each maintainer keeps an offline encrypted backup of their signing key so a lost laptop is not a lost identity. The lead maintainer's key additionally has a recovery custody arrangement recorded in a signed private continuity record held by the lead maintainer, stored offline and separately from the working key, so the project's primary identity survives the loss of one person's hardware. Custody is for recovery only. The custodian does not sign on the lead maintainer's behalf.

The second signer is the concrete backstop. Once that seat is filled, two maintainers hold two independent keys and both can publish, so a release can still ship if either one is unavailable.

### Disaster recovery

Two assets are single points of failure that live outside the git history: the GitHub organization and the npm scope. The repository content itself is not a single point of failure because every maintainer holds a full clone and the tags are signed, so the canonical history can be re-hosted anywhere and re-verified.

**Loss of the `Ad-Astra-Computing` GitHub organization** (account lockout, takeover, platform action):

1. Re-host the repository from a maintainer's local clone to Codeberg; a later move to a different host can go through the ordinary pull-request path. The signed tags travel with the history, so adopters can verify the re-hosted releases against the same fingerprints in the [Signers](#signers) table.
2. Update `repository`, `homepage` and `bugs` URLs in `package.json` and the links in the README, then cut a patch release from the new location.
3. Announce the move on the docs site and in the changelog and, if the original organization is recoverable, leave a pointer commit there to the new home.
4. The npm scope is unaffected by a GitHub loss, so published versions remain installable throughout.

**Loss of the `@adastracomputing` npm scope** (account lockout, scope dispute, registry action):

1. The already-published tarballs stay installable at their existing versions unless the registry itself removes them, so adopters are not immediately broken.
2. Republish future releases under a scope the maintainers control, announced at recovery time by a signed commit and a signed tag so the new supply chain is verifiable against the [Signers](#signers) table. The git tags remain the source of truth for what each release contains. The package name change is a breaking packaging event, so it ships with a changelog entry, a README note and a major or clearly-flagged version so no adopter silently swaps supply chains.
3. The git tags remain the source of truth for what each release contains. An adopter who does not trust the new scope can build the tarball from a signed tag with `nix build` and get a byte-reproducible result.
4. Announce on the docs site and in the changelog and, where possible, leave a final deprecation release under the old scope pointing at the new one.

In both cases the recovery path depends only on a maintainer's local clone, the signed tags and this document. Keep all three current.

## Amending this document

Changes to governance follow the ordinary pull-request path and need the lead maintainer's approval. A change that alters final authority, the succession rules or the [Signers](#signers) table must be a signed commit and should be announced in the changelog so the record of who could sign what and when stays auditable.
