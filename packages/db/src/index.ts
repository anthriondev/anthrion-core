import { PrismaPg } from '@prisma/adapter-pg';

import { PrismaClient } from './generated/prisma/client';

/**
 * Shared Prisma Client surface (T3.4).
 *
 * The Prisma SCHEMA is the single source of truth and stays at
 * `apps/api/prisma/schema.prisma`. Its `generator client` block OUTPUTS the client
 * into `./generated/prisma` (run `prisma generate` from `apps/api`, done by its
 * postinstall). This package re-exports that client so BOTH `apps/api` and
 * `apps/worker` import `@anthrion/db` — the worker therefore persists results without
 * importing `apps/*` (ARCHITECTURE.md §2).
 *
 * The generated directory is gitignored and `@ts-nocheck` (Prisma-owned code).
 */

// Re-export the full generated surface: PrismaClient, the `Prisma` namespace, enums,
// model types, and input types.
export * from './generated/prisma/client';

/**
 * Build a `PrismaClient` backed by the pg driver adapter (Prisma 7). The single
 * place both apps construct the client from a validated `DATABASE_URL`, so the
 * connection setup is not duplicated.
 */
export function createPrismaClient(databaseUrl: string): PrismaClient {
  return new PrismaClient({ adapter: new PrismaPg(databaseUrl) });
}
