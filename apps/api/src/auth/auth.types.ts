import { z } from 'zod';

export const authTokenClaimsSchema = z.object({
  appId: z.string(),
  issuer: z.string(),
  issuedAt: z.number(),
  expiration: z.number(),
  sessionId: z.string(),
  userId: z.string(),
});

export type AuthTokenClaims = z.infer<typeof authTokenClaimsSchema>;
