import { z } from "zod";

export const AvailabilityConfigSchema = z.object({
  // IANA timezone name. The longest legitimate value is ~50 chars.
  timezone: z.string().max(64),
  // Free-text availability description ("9-5 PT weekdays") capped
  // to a sane display length. Larger values are almost certainly
  // garbage or an attempted DoS.
  meetingHours: z.string().max(200).optional(),
  responseSla: z.string().max(200).optional(),
}).strict();

export const ProfileSnapshotSchema = z.object({
  headline: z.string().max(500),
  skills: z.array(z.string().max(100)).max(50),
  interests: z.array(z.string().max(100)).max(50),
  availability: AvailabilityConfigSchema.optional(),
  openTo: z.array(z.string().max(100)).max(20),
}).strict();

export const ProfileSchema = z.object({
  agentId: z.string(),
  handle: z.string(),
  displayName: z.string().max(200),
  bio: z.string().max(2000),
  snapshots: z.object({
    public: ProfileSnapshotSchema,
    connected: ProfileSnapshotSchema,
    custom: z.record(z.string(), ProfileSnapshotSchema),
  }),
});

export type AvailabilityConfig = z.infer<typeof AvailabilityConfigSchema>;
export type ProfileSnapshot = z.infer<typeof ProfileSnapshotSchema>;
export type Profile = z.infer<typeof ProfileSchema>;
