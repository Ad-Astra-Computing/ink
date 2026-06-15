import { z } from "zod";
import { isInkTimestamp } from "../crypto/timestamp.js";

export const KeyStatusSchema = z.enum(["active", "retired", "revoked"]);
export type KeyStatus = z.infer<typeof KeyStatusSchema>;

export const KeyRoleSchema = z.enum(["signing", "encryption"]);
export type KeyRole = z.infer<typeof KeyRoleSchema>;

// A key-window timestamp uses INK's strict RFC 3339 profile, not Zod's
// z.string().datetime(), which in this Zod version rejects the numeric `±HH:MM`
// offsets the profile accepts. Keeping this aligned with the verifier's parser
// is what makes the grammar the same everywhere.
const inkTimestamp = z
  .string()
  .refine(isInkTimestamp, { message: "must be a strict RFC 3339 timestamp" });

export const KeyEntrySchema = z.object({
  keyId: z.string().min(1),
  algorithm: z.enum(["Ed25519", "X25519"]),
  publicKeyMultibase: z.string().startsWith("z"),
  status: KeyStatusSchema,
  validFrom: inkTimestamp,
  validUntil: inkTimestamp.optional(),
  revokedAt: inkTimestamp.optional(),
  revokeReason: z.string().optional(),
});

export type KeyEntry = z.infer<typeof KeyEntrySchema>;

export interface CandidateKey {
  keyId: string;
  publicKey: Uint8Array;
  status: KeyStatus;
  /** ISO 8601 timestamp the key becomes usable. Verifier rejects messages
   * whose `body.timestamp` falls outside [validFrom, validUntil]. Optional
   * for backward compat with legacy callers that don't track windows. */
  validFrom?: string;
  /** ISO 8601 timestamp the key stops being usable. Typically set when a
   * key transitions to `retired`. A retired key with no validUntil keeps
   * verifying indefinitely (legacy behavior); set validUntil to bound it. */
  validUntil?: string;
  /** ISO 8601 timestamp the key was revoked. Defensive: status === "revoked"
   * already blocks verification; this field documents the moment. */
  revokedAt?: string;
}

export interface StoredKey {
  keyId: string;
  agentId: string;
  role: KeyRole;
  algorithm: string;
  publicKeyMultibase: string;
  privateKey: Uint8Array | null;
  status: KeyStatus;
  validFrom: string;
  validUntil: string | null;
  revokedAt: string | null;
  createdAt: string;
  updatedAt: string;
}
