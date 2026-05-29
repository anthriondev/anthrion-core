import { z } from 'zod';

const clientEnvSchema = z.object({
  NEXT_PUBLIC_PRIVY_APP_ID: z.string().min(1),
  NEXT_PUBLIC_API_URL: z.string().url(),
});

const _parsed = clientEnvSchema.safeParse({
  NEXT_PUBLIC_PRIVY_APP_ID: process.env['NEXT_PUBLIC_PRIVY_APP_ID'],
  NEXT_PUBLIC_API_URL: process.env['NEXT_PUBLIC_API_URL'],
});

if (!_parsed.success) {
  throw new Error(
    `Invalid client environment variables:\n${JSON.stringify(_parsed.error.flatten().fieldErrors, null, 2)}`,
  );
}

export const clientEnv = _parsed.data;
