import { z } from 'zod';

export const walletResponseSchema = z.object({
  address: z.string(),
  chain: z.enum(['EVM', 'SOLANA']),
});

export const userProfileResponseSchema = z.object({
  id: z.string(),
  privyUserId: z.string(),
  email: z.string().nullable(),
  createdAt: z.string(),
  wallets: z.array(walletResponseSchema),
});

export type UserProfileResponse = z.infer<typeof userProfileResponseSchema>;
