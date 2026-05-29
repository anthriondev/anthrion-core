import { Inject, Injectable, Logger, NotFoundException } from '@nestjs/common';
import { PrivyClient } from '@privy-io/server-auth';
import { z } from 'zod';

import { Prisma, WalletChain } from '@anthrion/db';

import { PRIVY_CLIENT } from '../auth/auth.constants';
import { PrismaService } from '../prisma/prisma.service';

import { type UserProfileResponse, userProfileResponseSchema } from './user.dto';

const privyLinkedAccountSchema = z.object({
  type: z.string(),
  address: z.string().optional(),
  chainType: z.string().optional(),
}).passthrough();

const privyUserProfileSchema = z.object({
  id: z.string(),
  email: z.object({ address: z.string() }).optional(),
  linkedAccounts: z.array(privyLinkedAccountSchema),
}).passthrough();

type PrivyUserProfile = z.infer<typeof privyUserProfileSchema>;

type WalletData = { address: string; chain: WalletChain };

function mapChainType(chainType: string): WalletChain | null {
  if (chainType === 'ethereum') return WalletChain.EVM;
  if (chainType === 'solana') return WalletChain.SOLANA;
  return null;
}

function extractWallets(profile: PrivyUserProfile): WalletData[] {
  return profile.linkedAccounts.flatMap((account) => {
    if (account.type !== 'wallet') return [];
    if (!account.address || !account.chainType) return [];
    const chain = mapChainType(account.chainType);
    if (chain === null) return [];
    return [{ address: account.address, chain }];
  });
}

@Injectable()
export class UserService {
  private readonly logger = new Logger(UserService.name);

  constructor(
    private readonly prisma: PrismaService,
    @Inject(PRIVY_CLIENT) private readonly privyClient: PrivyClient,
  ) {}

  async syncUser(privyUserId: string): Promise<void> {
    const existing = await this.prisma.user.findUnique({
      where: { privyUserId },
      select: { id: true },
    });

    if (existing !== null) return;

    const privyData = await this.fetchPrivyProfile(privyUserId);

    try {
      await this.prisma.user.create({
        data: {
          privyUserId,
          email: privyData?.email ?? null,
          ...(privyData && privyData.wallets.length > 0 && {
            wallets: { createMany: { data: privyData.wallets, skipDuplicates: true } },
          }),
        },
      });
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        // Race condition: another concurrent request created the user first
        return;
      }
      throw error;
    }
  }

  async getProfile(privyUserId: string): Promise<UserProfileResponse> {
    const user = await this.prisma.user.findUnique({
      where: { privyUserId },
      include: { wallets: { select: { address: true, chain: true } } },
    });

    if (user === null) {
      throw new NotFoundException('User not found');
    }

    return userProfileResponseSchema.parse({
      id: user.id,
      privyUserId: user.privyUserId,
      email: user.email,
      createdAt: user.createdAt.toISOString(),
      wallets: user.wallets,
    });
  }

  private async fetchPrivyProfile(
    privyUserId: string,
  ): Promise<{ email: string | null; wallets: WalletData[] } | null> {
    let rawUser: unknown;

    try {
      rawUser = await this.privyClient.getUser(privyUserId);
    } catch (error) {
      this.logger.error(
        `Failed to fetch Privy profile for user ${privyUserId}`,
        error instanceof Error ? error.stack : String(error),
      );
      return null;
    }

    const parsed = privyUserProfileSchema.safeParse(rawUser);

    if (!parsed.success) {
      this.logger.error(
        `Privy profile for user ${privyUserId} failed schema validation`,
        parsed.error.toString(),
      );
      return null;
    }

    return {
      email: parsed.data.email?.address ?? null,
      wallets: extractWallets(parsed.data),
    };
  }
}
