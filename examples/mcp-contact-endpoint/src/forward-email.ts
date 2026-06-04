/**
 * Sketch: compose the forwarded email, keeping VERIFIED facts separate from
 * CLAIMED ones (decision 4). The agent DID and the signature are verified; any
 * human name or email in the payload is self-asserted and unverified.
 *
 * Illustrative, not a tested service. sendEmail is a thin wrapper over whatever
 * transactional provider you use.
 */

interface Envelope {
  id: string;
  from: string;            // agent DID — verified
  intent: string;
  provenance?: string;     // human | agent_approved | agent_autonomous
  payload?: {
    context?: string;
    message?: string;
    profileSnapshot?: { name?: string; headline?: string; email?: string };
  };
}

const INBOX = "hello@example.com";

export function buildForwardEmail(envelope: Envelope) {
  const claimed = envelope.payload?.profileSnapshot ?? {};
  const message = envelope.payload?.context ?? envelope.payload?.message ?? "";

  const text = [
    "An agent reached you over INK. The signature is verified; the human details",
    "below are claimed by the sender and are NOT verified.",
    "",
    "VERIFIED",
    `  Agent DID:   ${envelope.from}`,
    `  Provenance:  ${envelope.provenance ?? "unspecified"}`,
    `  Intent:      ${envelope.intent}`,
    "",
    "CLAIMED (self-asserted by the sender, unverified)",
    `  Name:        ${claimed.name ?? "—"}`,
    `  Headline:    ${claimed.headline ?? "—"}`,
    `  Email:       ${claimed.email ?? "—"}`,
    "",
    "Message",
    `  ${message}`,
    "",
    "To respond, accept the connection through INK rather than emailing the",
    "claimed address directly. The claimed email is spoofable until a connection",
    "is established.",
  ].join("\n");

  return {
    to: INBOX,
    // Deliberately NOT the claimed sender address — spoofable. Route replies
    // back through the protocol or a controlled address.
    replyTo: "noreply@example.com",
    subject: `INK ${envelope.intent} from ${envelope.from}`,
    text,
  };
}

export async function sendEmail(env: { RESEND_API_KEY?: string }, msg: ReturnType<typeof buildForwardEmail>): Promise<void> {
  // Wire to your transactional provider. Sketch only.
  void env; void msg;
}
