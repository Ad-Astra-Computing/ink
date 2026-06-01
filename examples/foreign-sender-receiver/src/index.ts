export {
  evaluateInboundForeign,
  canonicalizeDid,
  isForeignDid,
  normalizeHostSuffixes,
} from "./inbound-policy.js";
export type {
  InkInboundPolicy,
  InboundDecision,
} from "./inbound-policy.js";

export {
  didWebToDocUrl,
  extractDidWebHost,
  isIpLiteralHost,
  isPrivateHost,
} from "./did-web-resolver.js";

export {
  deliverInkEnvelopeToForeign,
  validateOutboundDeliveryUrl,
} from "./outbound-delivery.js";
export type {
  ForeignDeliveryInput,
  ForeignDeliveryResult,
  ForeignDeliveryError,
} from "./outbound-delivery.js";
