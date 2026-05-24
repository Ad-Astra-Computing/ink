import { z } from "zod";
import { IntentTypeSchema } from "./intent.js";
import { InkReceiptDispositionSchema } from "./ink-audit.js";
import { ProfileSnapshotSchema } from "./profile.js";
import { KeyEntrySchema } from "./key-entry.js";
import { InkTransportSchema, AgentCardVisibilitySchema } from "./ink-handshake.js";

export const ThirdPartyAuditServiceSchema = z.object({
  endpoint: z.string().url(),
  did: z.string(),
  publicKey: z.string(),
});

export const AgentCardSchema = z.object({
  protocol: z.literal("ink/0.1"),
  agentId: z.string(),
  ownerDid: z.string().optional(),
  ownerHandle: z.string().optional(),
  atprotoRecordUri: z.string().optional(),
  handle: z.string(),
  displayName: z.string().max(200),
  endpoint: z.string().url(),
  publicKeyMultibase: z.string().startsWith("z"),
  profileSnapshot: ProfileSnapshotSchema.optional(),
  capabilities: z.object({
    intentsAccepted: z.array(IntentTypeSchema),
    intentsSent: z.array(IntentTypeSchema),
    receipts: z.object({
      send: z.boolean(),
      dispositions: z.array(InkReceiptDispositionSchema),
    }).optional(),
    auditExchange: z.boolean().optional(),
    thirdPartyAudit: z.object({
      services: z.array(ThirdPartyAuditServiceSchema),
      submitPolicy: z.enum(["all", "high_value", "none"]),
    }).optional(),
  }),
  availability: z.object({
    timezone: z.string(),
    meetingHours: z.string().optional(),
    responseSla: z.string().optional(),
  }),
  keys: z.object({
    signing: z.array(KeyEntrySchema),
    encryption: z.array(KeyEntrySchema),
  }).optional(),
  currentSigningKeyId: z.string().optional(),
  currentEncryptionKeyId: z.string().optional(),
  keySetVersion: z.number().int().positive().optional(),
  // Containment extension (Phase 1)
  visibility: AgentCardVisibilitySchema.optional(),
  governance: z.object({
    maxAcceptedDelegationDepth: z.number().int().positive().optional(),
    supportedTransports: z.array(InkTransportSchema).optional(),
    supportsCapabilityGatedDiscovery: z.boolean().optional(),
    handshakeBudget: z.object({
      maxChallengesPerCorrelation: z.number().int().positive().optional(),
      maxIntentsPerMinute: z.number().int().positive().optional(),
    }).optional(),
  }).optional(),
});

export type AgentCard = z.infer<typeof AgentCardSchema>;
