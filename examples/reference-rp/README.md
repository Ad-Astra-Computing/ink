# INK Reference Relying Party

A runnable relying-party (RP) half of the Sign in with INK flow, built solely on
the public surface of `@adastracomputing/ink`. It signs an authorization
challenge, tracks the sign-in context, consumes the answering identity assertion
at a completion endpoint, and upholds every acceptance rule the profile pins. A
simulated user agent mints the assertion so the whole flow runs end to end in one
process.

It is the RP counterpart to the [reference sender](../reference-sender/) and
[reference receiver](../reference-receiver/): the same goal, prove the OSS package
by itself is enough to build a conformant side of the protocol. No internal
modules, no private fork of the schema. Every module is code an adopter can lift.

The flow it implements is [`specs/ink-agent-authorization.md`](../../specs/ink-agent-authorization.md),
which composes the grant primitive in [`specs/ink-authorization-grant.md`](../../specs/ink-authorization-grant.md).

## Quick start

No build step. The demo and tests run the TypeScript source directly under
Node's native type stripping. `@adastracomputing/ink` requires Node 24+.

```sh
cd examples/reference-rp
npm install

# Walk the whole flow: challenge, mint, sign-in, then two fail-closed paths.
npm run demo
```

A successful run signs the user in, then shows a replayed grant and a forged
grant id both refused:

```
3. RP completion endpoint consumes the assertion
  signed in as     did:web:agent.example
  scope            identity.assert, profile.read

4. Replay of the accepted grant
  refused          grant:replay

5. Grant id not derived from the challenge
  refused          grant_id_not_derived
```

## The flow

Three principals take part: the RP that wants to sign a user in, the user's agent
that answers, and the user whose consent gates the agent. The RP and the agent
are both ordinary INK principals with published Agent Cards. No shared platform
or identity provider sits between them.

1. The RP signs an `authorization_challenge` for its bare-host `did:web`
   principal, requesting `identity.assert` (plus any other registry tokens) and
   naming a `redirectUri` on its own origin. It opens a sign-in context for the
   session that initiated the challenge.
2. The user's agent verifies the challenge against an active RP signing key,
   obtains consent, and mints an identity assertion. The assertion's issuer and
   subject are the agent, its audience is the RP, and its `grantId` is derived
   from the verified challenge rather than the raw nonce.
3. The RP's completion endpoint receives the assertion, verifies it with the
   ordinary grant verifier bound to the RP audience, runs the profile acceptance
   checklist, and treats the subject as the signed-in identity.

## What it does

| Step | Module | What happens |
|------|--------|--------------|
| Identity | `src/identity.ts` | Mint bare-host `did:web` principals for the RP and the agent, expose the RP's active signing keys, and resolve an issuer to its key. |
| Scope | `src/scope.ts` | The profile's closed scope registry, split into the identity-assertion tokens an assertion may carry and the delegated-capability token it may not. |
| Challenge | `src/challenge.ts` | Mint a 128-bit nonce, build a completion URL on the RP origin, and sign the challenge with `buildAuthorizationChallenge`. |
| Context | `src/sign-in-context.ts` | Hold the outstanding challenge per session, pin its derived grant id, expire it at the challenge expiry, and record accepted `(issuer, grantId)` pairs. |
| Completion | `src/completion.ts` | Consume the assertion, verify it with `verifyAuthorizationGrant`, run the acceptance checklist, and return the signed-in subject. |
| User agent | `src/user-agent.ts` | The simulated counterparty: verify the challenge, gate on consent, mint the assertion with the derived id, enforce mint-once. |

## Security properties the RP upholds

The base grant verifier from the package makes the decisions two implementations
must agree on over the grant bytes: signature, audience, window, replay. It does
not know this profile's shape, so the completion endpoint layers the profile's
own rules on top. Every check fails closed with a typed reason and no sign-in.

- **Consume the grant, forward nothing.** The endpoint the `redirectUri` names
  consumes the assertion. It is not a redirect and it does not forward the grant
  bytes cross-origin. The literal-prefix rule already narrows delivery to the
  RP's own origin, and consumption closes what remains, so a stolen challenge
  cannot deliver the sign-in anywhere but the RP's own consuming endpoint. The
  example enforces this by checking the delivery URL against the challenge
  redirect and by making the completion function terminal.
- **Bind acceptance to the derived id.** The assertion's `grantId` must equal the
  id the RP derives from the challenge whose context received the completion. A
  grant minted for any other challenge carries a different id and is refused, so
  an assertion minted for one sign-in cannot complete another.
- **Bind to the audience.** The signed `audience` must equal the RP's own
  identity, the confused-deputy defense, so a grant minted for another service is
  not presentable here.
- **Expire the context at the challenge expiry.** The sign-in context is dropped
  at the challenge's `expiresAt`, so a late completion finds no context that owns
  its nonce, whatever the grant's own window says. This is the presentation
  control for a browser redirect, where no authenticated presenter exists and the
  grant verifier's presentation binding never fires.
- **Reject a replay.** An accepted `(issuer, grantId)` pair is recorded atomically
  with acceptance, so a second presentation of the same pair is refused even if
  the issuer lost its own mint-once record. The two layers do not depend on each
  other.
- **Keep the scope in profile.** The assertion must contain `identity.assert`,
  and every entry must be an identity-assertion registry token that the challenge
  requested. A delegated-capability token such as `agent.message.send` never
  rides in an assertion.
- **Require issuer equals subject and no owner field.** An identity assertion's
  issuer and subject are the same principal, and a sign-in grant omits
  `requireVerifiedOwner`. A grant that breaks either is not a grant under this
  profile.

The completion endpoint returns one of these typed reasons when it refuses:
`grant:<reason>` for a base-verifier rejection (`signature`, `audience`,
`expired`, `replay` and the rest), or one of the RP-local reasons
`no_context`, `context_expired`, `redirect_mismatch`, `issuer_unresolved`,
`issuer_not_subject`, `grant_id_not_derived`, `mint_window`,
`owner_field_present`, `scope_missing_identity_assert`,
`scope_not_identity_assertion_token`, `scope_not_requested`.

## What it does not do

- **No key transport.** In production the user's agent fetches the RP's Agent Card
  over the network at the derived origin's well-known path, under the
  private-hostname gate with connect-time pinning and a transport refusal of
  redirects, and the RP resolves the issuer's card the same way. This example
  hands the agent the RP's candidate keys directly and gives the RP a small
  in-process directory. The wire artifacts and their verification are identical;
  only the key transport is stubbed. An adopter wires the real fetch in place of
  the directory.
- **No delegated capability.** The profile's optional second grant shape, a
  delegated capability the RP presents back to the agent over INK, is out of
  scope here. This example is the identity-assertion core, which is the only part
  a sign-in requires.
- **No consent UI or session store.** How the agent presents consent and how the
  RP persists a signed-in session are product surface, not protocol. Consent is a
  caller-supplied set of tokens, and a sign-in is the returned subject.

## How it relates to the other examples

The reference sender and receiver show a full INK envelope going from one agent to
another. This example shows the Sign in with INK flow, a different profile that
composes the authorization grant. All three build on the same package surface and
the same signing and verification primitives.

## The button

This example is the backend an RP runs. The control a user clicks to start the
flow is the "Sign in with INK" button. Its assets live in
[`docs/brand`](../../docs/brand), and the sizing, variants and usage rules are on
the [brand page](https://ink.tulpa.network/extensions/sign-in-button/).

## Build and test

```sh
npm run typecheck   # tsc --noEmit
npm test            # vitest run
npm run demo        # the end-to-end walk-through
```

The tests cover the happy-path sign-in, a bare `identity.assert` sign-in, every
fail-closed rejection the completion endpoint can return, the challenge
verification paths, and the agent-side refusals the flow depends on.
