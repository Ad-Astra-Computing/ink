# 0001. Key-derived principals are the identity root

**Status:** Ratified by the project owner on 2026-08-18.
**Applies to:** every INK specification, implementation and published document.
**Normative home of the model:** [`specs/ink-identity-model.md`](../../specs/ink-identity-model.md).

This is a decision record. It states what was decided, why, what the decision
costs and what it forecloses. It defines no wire format and no requirement of
its own: where a rule is normative, the identity model or the spec it cites owns
it, and this document points at that owner rather than restating it.

## The ruling

Key-derived principals are INK's identity root.

A key-derived principal is `tulpa:<multibase>` or `ink:<multibase>`, whose
multibase tail decodes to the 32-byte Ed25519 public key that is the identity's
genesis root. It is self-certifying: it identifies exactly the party holding the
private half of that key and carries no other claim. There is no directory, no
registry and no issuer behind it. Creating one requires nobody's permission and
no third party can revoke one.

The AT Protocol is one optional owner-linkage pipeline among several. It is
never the root of trust, never what makes a signature valid and never a
requirement of participation. A deployment that links owners through AT
Protocol, through some other identity system or not at all, is equally
conforming. `did:web` is a supported alternative principal family whose DID
document roots the key.

No INK document may describe a human DID, an owner record or any external
directory as the root of trust, and no verifier may authorize on a card's owner
fields. Owner status is an advisory input a service computes under its own
policy, out of band of INK.

## Why

INK is meant to be to agent messaging what email was to person messaging. That
goal sets the identity requirement, and the requirement is permissionlessness.

An identity layer that requires membership in one network is not permissionless.
If the root of trust were an AT Protocol DID, then INK's availability would
depend on that network's PDS and directory infrastructure being reachable, its
governance would be downstream of that ecosystem's governance and its policy
surface would include every account action that ecosystem can take. Whoever can
refuse to issue an identifier, or withdraw one, would hold a veto over who can
speak INK. That is a different protocol from the one being built.

Key-derived principals move that decision to the holder of a keypair. Anyone can
mint one offline. Nobody can take one away. The identifier carries its own
verification key, so a cold verifier meeting a principal for the first time can
check a signature without asking a third party anything, which is also what
makes first contact work without pre-established trust
(`specs/ink-identity-model.md` §6.1).

## What it costs

Two costs, stated as costs.

**A key-derived identity is exactly as unrecoverable as its key material.**
There is no authority to appeal to for a reissue, because there is no authority.
Loss of every chain-capable key is identity loss, and it is observable to
counterparties only as silence. The in-band mitigation is a pre-declared offline
recovery key, which has to exist before the loss. This is why recovery in the
Tulpa deployment preserves the `agentId` and rotates keys underneath it rather
than minting a new identity: under this model a new identifier is a new agent to
every counterparty, and no continuity claim spans the two
(`specs/ink-key-rotation-spec.md` §4.1,
`specs/ink-agent-card-signature.md` §9).

**The identity layer offers no answer to "who is this human".** It is not
deferred and it is not planned. INK identifies agents. Accountability for the
person or organization behind an agent belongs to policy layers built on top,
informed by the advisory owner signal a deployment computes for itself. An
adopter who needs a verified human obtains that from the identity system that
issued the owner DID, under that system's rules, and INK will not tell them
whether it worked.

## The long-term constraint

A key-derived `agentId` embeds a permanent Ed25519 key. The identifier cannot be
re-rooted on a post-quantum signature scheme without becoming a different
identifier, so the genesis root of every key-derived identity stays classical for
that identity's life. Rotation moves the live signing key and does not move the
root.

A `did:web` principal does not have this constraint: its root is a document, and
a document can name a new key of a new kind. So the post-quantum ceiling differs
by principal family, and the family this ruling makes primary is the one with
the lower ceiling. That trade was made knowingly. Confidentiality is the nearer
post-quantum problem and hybrid key agreement is addressable without touching an
identifier; signature-root migration is the harder one, and this ruling does not
pretend otherwise.

## History

Briefly, because the record was until now only inferable from code.

- The implementation has been key-derived since the genesis commit (2026-03-10,
  `tulpa:<multibase-encoded-public-key>` derived directly from the Ed25519
  public key).
- AT Protocol support arrived two days later (2026-03-12) and was additive from
  the start. It never sat under signature verification.
- The prose diverged. Design documents asserted a human-rooted model in which
  the owner DID was the root of trust and every agent action traced to an
  owner-published record. Nothing ever implemented that. It was a description of
  a system that did not exist, and it survived because no gate compares prose to
  a model.
- Owner verification shipped on 2026-06-08 as an advisory, default-off signal,
  which is the posture that matches the model rather than the prose.
- `specs/ink-identity-model.md` formalized the position on 2026-08-17, stating
  that a key-derived principal is self-certifying and that INK defines no proof
  binding an owner to an agent.
- The project owner ratified the position on 2026-08-18. This record is that
  ratification.

## Consequences for documents

Any document asserting an owner-rooted identity model is superseded by this one,
whatever its own status line says. That includes design-principle statements
naming a human DID as the root of trust, diagram legends labelling an external
identity system as the identity layer and verification procedures whose steps
require an owner record to be fetched before a signature counts.

A page describing a record format that no INK specification defines and no
implementation reads is not protocol surface and should not be published beside
one. Correcting such a page means removing the claim, not restating it against a
mechanism that was never built.
