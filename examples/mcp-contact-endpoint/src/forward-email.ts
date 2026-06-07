/**
 * Sketch: compose the forwarded email, keeping VERIFIED facts separate from
 * CLAIMED ones (decision 4). The agent DID, the signature and the provenance are
 * verified; everything the sender writes into the payload is self-asserted and
 * unverified, and which fields exist depends on the intent.
 *
 * Illustrative, not a tested service. The email is plain TEXT — if you switch to
 * HTML, escape every claimed field, because they are attacker-controlled.
 * sendEmail is a thin wrapper over whatever transactional provider you use.
 */

// We only read a handful of fields, and the payload shape varies per intent, so
// accept the envelope loosely (its real type is MessageEnvelope, whose `payload`
// is `unknown`) and read each field defensively.
interface ForwardableEnvelope {
  id: string;
  from: string; // agent DID — verified
  intent: string;
  provenance?: { origin?: "human" | "agent_approved" | "agent_autonomous" };
  payload?: unknown;
}

const INBOX = "hello@example.com";

function str(v: unknown): string {
  return typeof v === "string" && v.length > 0 ? v : "—";
}

/** The claimed fields worth surfacing, per accepted intent. INK carries no human
 *  name or email in a first-contact payload, so identity stays the DID. */
function claimedLines(intent: string, payload: Record<string, unknown>): string[] {
  if (intent === "connection_request") {
    const ps = (payload.profileSnapshot ?? {}) as Record<string, unknown>;
    const openTo = Array.isArray(ps.openTo) ? (ps.openTo as unknown[]).filter((x) => typeof x === "string").join(", ") : "";
    return [
      `  Headline:    ${str(ps.headline)}`,
      `  Open to:     ${openTo || "—"}`,
      `  Context:     ${str(payload.context)}`,
    ];
  }
  if (intent === "intro_request") {
    return [
      `  Wants intro: ${str(payload.target)}`,
      `  Reason:      ${str(payload.reason)}`,
      `  Context:     ${str(payload.context)}`,
    ];
  }
  if (intent === "ask") {
    return [`  Question:    ${str(payload.question)}`];
  }
  return ["  (no renderable fields for this intent)"];
}

export function buildForwardEmail(envelope: ForwardableEnvelope) {
  const payload = (envelope.payload ?? {}) as Record<string, unknown>;

  const text = [
    "An agent reached you over INK. The signature is verified; the details below",
    "are claimed by the sender and are NOT verified.",
    "",
    "VERIFIED",
    `  Agent DID:   ${envelope.from}`,
    `  Provenance:  ${envelope.provenance?.origin ?? "unspecified"}`,
    `  Intent:      ${envelope.intent}`,
    "",
    "CLAIMED (self-asserted by the sender, unverified)",
    ...claimedLines(envelope.intent, payload),
    "",
    "To respond, accept the connection through INK rather than replying by email.",
    "Until a connection is established there is no verified address for the human",
    "behind this agent.",
  ].join("\n");

  return {
    to: INBOX,
    // Deliberately NOT a sender-supplied address (there is none in the envelope,
    // and any out-of-band one would be spoofable). Route replies back through the
    // protocol or a controlled monitored mailbox.
    replyTo: INBOX,
    subject: `INK ${envelope.intent} from ${envelope.from}`,
    text,
  };
}

export async function sendEmail(env: Record<string, unknown>, msg: ReturnType<typeof buildForwardEmail>): Promise<void> {
  // Wire to your transactional provider (read env.RESEND_API_KEY etc.). Sketch only.
  void env;
  void msg;
}
