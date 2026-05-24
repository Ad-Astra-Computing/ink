# Key Rotation Authority Rule

> Normative. This is the rule a conforming INK receiver MUST follow when
> verifying a signature attributed to a sender agent.

## Summary

**The Agent Card signing key set, once observed, is authoritative.** A
receiver MUST:

1. Try to verify the signature against the sender's Agent Card `keys.signing`
   set. Iterate through entries in this order: `active` → `retired`. Never
   iterate `revoked` entries.
2. If any entry verifies, accept the signature and record which `keyId` was
   used.
3. If no entry verifies, reject the signature. **Do not fall through** to
   any other key source.

Only when the receiver has **never observed** an Agent Card for the sender
may it use a bootstrap path, either the public key embedded in an
agent ID scheme that supports it, or a key the receiver stored from an
earlier first-contact handshake. This is the *trust-on-first-use* window
and ends the first time a valid Agent Card is observed.

## Why

Rotation and revocation exist so an agent can abandon a compromised key.
The moment the sender publishes an updated Card, any receiver that still
accepts the old key is defeating rotation. Three concrete failure modes
this rule closes:

1. **Stolen old key.** Attacker has a private key the sender has since
   marked `retired` or `revoked`. Without this rule, a receiver with a
   locally-cached copy of that old key might still verify the attacker's
   signed message.
2. **Fallback shadowing.** A receiver that first consults an "authoritative"
   key set and then "as a fallback" consults some other single-key lookup
   can have that lookup return a pre-rotation key, silently accepting the
   old signature after rotation. The rule forbids fallback **after** the
   authoritative set has spoken.
3. **Bootstrap persistence.** Some identity schemes let receivers derive a
   public key from the agent ID. That key is necessarily frozen at creation
   time, rotation by definition can't update it. The rule limits its use
   to first-contact only.

## Status taxonomy

A signing key entry has exactly one of three statuses:

| Status    | Receiver behavior                                             |
|-----------|---------------------------------------------------------------|
| `active`  | Verify signatures made with this key. Normal operation.       |
| `retired` | Verify signatures, but the sender has a newer `active` key.   |
|           | Typical during rotation grace periods. Receivers MAY refuse   |
|           | based on local policy (e.g. reject anything older than 30 d). |
| `revoked` | **Never** verify signatures with this key, even for messages  |
|           | signed before the revocation timestamp. Revocation means the  |
|           | key is compromised or must not be trusted.                    |

Retired vs revoked is the key semantic distinction. Retired is normal
rotation; revoked is a trust statement. Conforming implementations MUST
NOT treat them as equivalent.

## Concrete receiver algorithm

```text
input:  senderId, signature, message
state:  agentCardCache (optional per-receiver cache of observed Cards)

card ← agentCardCache.get(senderId) or fetch Agent Card via published
       endpoint for senderId

if card has a non-empty keys.signing set:
  for entry in card.keys.signing where entry.status ∈ {active, retired}:
    if verify(entry.publicKey, message, signature):
      return ACCEPT, keyIdUsed = entry.keyId
  return REJECT (signature_verification_failed)

else if card does not exist OR has no keys.signing:
  # First-contact / bootstrap only
  bootstrapKey ← extract from senderId (scheme-specific) OR
                 lookup in local connection store
  if bootstrapKey and verify(bootstrapKey, message, signature):
    return ACCEPT, keyIdUsed = "bootstrap"
  return REJECT (unresolvable_sender_key or signature_verification_failed)
```

## Invariants a conforming implementation MUST preserve

1. A `revoked` entry in the Card MUST NEVER be used to verify a signature.
2. A locally-stored single key MUST NOT be treated as `active` if the
   sender's Card disagrees with its status. If the Card lists that public
   key as `retired` or `revoked`, the Card's status wins.
3. If the Card's signing set has been observed and no entry verifies the
   signature, the signature MUST be rejected. The receiver MUST NOT then
   consult another key source.
4. Bootstrap key extraction (deriving a pubkey from an agent ID) MUST be
   disabled once any Card signing set has been observed for that sender.

## Non-goals

- This rule does not specify how a sender rotates keys. See
  [`../specs/ink-key-rotation-spec.md`](../specs/ink-key-rotation-spec.md).
- This rule does not specify receipt / audit integrity under rotation;
  see [`../specs/ink-auditability.md`](../specs/ink-auditability.md).
- This rule does not specify identity proof. INK assumes the identity
  system (AT Protocol, DID, etc.) provides senderId → Agent Card
  resolution.
