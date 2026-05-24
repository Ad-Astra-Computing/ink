import { z } from "zod";

export const AvailabilityConfigSchema = z.object({
  timezone: z.string(),
  meetingHours: z.string().optional(),
  responseSla: z.string().optional(),
});

export const ProfileSnapshotSchema = z.object({
  headline: z.string().max(500),
  skills: z.array(z.string().max(100)).max(50),
  interests: z.array(z.string().max(100)).max(50),
  availability: AvailabilityConfigSchema.optional(),
  openTo: z.array(z.string().max(100)).max(20),
});

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
