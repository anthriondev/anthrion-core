import { Logger } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { PrismaPg } from '@prisma/adapter-pg';

import { Prisma, WalletChain } from '@anthrion/db';

import { PRIVY_CLIENT } from '../auth/auth.constants';
import { PrismaService } from '../prisma/prisma.service';

import { UserService } from './user.service';

// ─── Unit tests (mocked Prisma + Privy) ─────────────────────────────────────

const mockPrismaUser = {
  findUnique: jest.fn(),
  create: jest.fn(),
};

const mockPrisma = {
  user: mockPrismaUser,
} as unknown as PrismaService;

const mockPrivyClient = {
  getUser: jest.fn(),
};

describe('UserService (unit)', () => {
  let service: UserService;

  beforeEach(async () => {
    jest.clearAllMocks();
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UserService,
        { provide: PrismaService, useValue: mockPrisma },
        { provide: PRIVY_CLIENT, useValue: mockPrivyClient },
      ],
    }).compile();

    service = module.get<UserService>(UserService);
  });

  it('creates a new user when privyUserId is not in DB', async () => {
    mockPrismaUser.findUnique.mockResolvedValueOnce(null);
    mockPrivyClient.getUser.mockResolvedValueOnce({
      id: 'did:privy:test-123',
      email: undefined,
      linkedAccounts: [],
    });
    mockPrismaUser.create.mockResolvedValueOnce({ id: 'db-id-1' });

    await service.syncUser('did:privy:test-123');

    expect(mockPrismaUser.create).toHaveBeenCalledWith({
      data: expect.objectContaining({ privyUserId: 'did:privy:test-123' }),
    });
  });

  it('does NOT create a duplicate when user already exists', async () => {
    mockPrismaUser.findUnique.mockResolvedValueOnce({ id: 'existing-db-id' });

    await service.syncUser('did:privy:existing');

    expect(mockPrismaUser.create).not.toHaveBeenCalled();
    expect(mockPrivyClient.getUser).not.toHaveBeenCalled();
  });

  it('stores email from Privy when available', async () => {
    mockPrismaUser.findUnique.mockResolvedValueOnce(null);
    mockPrivyClient.getUser.mockResolvedValueOnce({
      id: 'did:privy:with-email',
      email: { address: 'user@example.com' },
      linkedAccounts: [],
    });
    mockPrismaUser.create.mockResolvedValueOnce({ id: 'db-id-2' });

    await service.syncUser('did:privy:with-email');

    expect(mockPrismaUser.create).toHaveBeenCalledWith({
      data: expect.objectContaining({ email: 'user@example.com' }),
    });
  });

  it('stores wallets with correct chain mapping from Privy', async () => {
    mockPrismaUser.findUnique.mockResolvedValueOnce(null);
    mockPrivyClient.getUser.mockResolvedValueOnce({
      id: 'did:privy:with-wallets',
      email: undefined,
      linkedAccounts: [
        { type: 'wallet', address: '0xABC', chainType: 'ethereum' },
        { type: 'wallet', address: 'SolAddr', chainType: 'solana' },
        { type: 'wallet', address: 'CosmosAddr', chainType: 'cosmos' }, // unsupported, skipped
        { type: 'email', address: 'user@example.com' },
      ],
    });
    mockPrismaUser.create.mockResolvedValueOnce({ id: 'db-id-3' });

    await service.syncUser('did:privy:with-wallets');

    expect(mockPrismaUser.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        wallets: {
          createMany: {
            data: [
              { address: '0xABC', chain: WalletChain.EVM },
              { address: 'SolAddr', chain: WalletChain.SOLANA },
            ],
            skipDuplicates: true,
          },
        },
      }),
    });
  });

  it('creates user with minimal data when Privy API fails', async () => {
    mockPrismaUser.findUnique.mockResolvedValueOnce(null);
    mockPrivyClient.getUser.mockRejectedValueOnce(new Error('Privy API error'));
    mockPrismaUser.create.mockResolvedValueOnce({ id: 'db-id-4' });

    await service.syncUser('did:privy:api-failure');

    expect(mockPrismaUser.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        privyUserId: 'did:privy:api-failure',
        email: null,
      }),
    });
  });

  it('silently ignores race-condition P2002 error on concurrent sign-up', async () => {
    mockPrismaUser.findUnique.mockResolvedValueOnce(null);
    mockPrivyClient.getUser.mockResolvedValueOnce({
      id: 'did:privy:race',
      email: undefined,
      linkedAccounts: [],
    });
    const p2002 = new Prisma.PrismaClientKnownRequestError('Unique constraint failed', {
      code: 'P2002',
      clientVersion: '7.8.0',
    });
    mockPrismaUser.create.mockRejectedValueOnce(p2002);

    await expect(service.syncUser('did:privy:race')).resolves.toBeUndefined();
  });
});

// ─── Integration tests (real Prisma → Postgres) ─────────────────────────────

describe('UserService (integration)', () => {
  let service: UserService;
  let prisma: PrismaService;
  const ts = Date.now();
  const testPrivyUserId = `did:privy:integration-test-${ts}`;
  const testPrivyUserId2 = `did:privy:integration-test-2-${ts}`;
  const testEmail = `test-wallet-${ts}@example.com`;
  const testWalletAddress = `0xTestEvmAddr${ts}`;

  const mockPrivyNoProfile = {
    getUser: jest.fn().mockRejectedValue(new Error('Privy not available in tests')),
  };

  beforeAll(async () => {
    // Silence error logs for expected Privy API failure
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);

    prisma = new PrismaService();
    await prisma.onModuleInit();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UserService,
        { provide: PrismaService, useValue: prisma },
        { provide: PRIVY_CLIENT, useValue: mockPrivyNoProfile },
      ],
    }).compile();

    service = module.get<UserService>(UserService);
  });

  afterAll(async () => {
    const users = await prisma.user.findMany({
      where: { privyUserId: { in: [testPrivyUserId, testPrivyUserId2] } },
      select: { id: true },
    });
    const ids = users.map((u) => u.id);
    await prisma.wallet.deleteMany({ where: { userId: { in: ids } } });
    await prisma.user.deleteMany({ where: { id: { in: ids } } });
    await prisma.onModuleDestroy();
  });

  it('creates user record in DB on first syncUser call', async () => {
    await service.syncUser(testPrivyUserId);

    const user = await prisma.user.findUnique({ where: { privyUserId: testPrivyUserId } });
    expect(user).not.toBeNull();
    expect(user?.privyUserId).toBe(testPrivyUserId);
  });

  it('does NOT create duplicate on second syncUser call with same privyUserId', async () => {
    await service.syncUser(testPrivyUserId);

    const users = await prisma.user.findMany({ where: { privyUserId: testPrivyUserId } });
    expect(users).toHaveLength(1);
  });

  it('stores wallet records linked to correct user', async () => {
    const mockPrivyWithWallet = {
      getUser: jest.fn().mockResolvedValue({
        id: testPrivyUserId2,
        email: { address: testEmail },
        linkedAccounts: [
          { type: 'wallet', address: testWalletAddress, chainType: 'ethereum' },
        ],
      }),
    };

    const module2: TestingModule = await Test.createTestingModule({
      providers: [
        UserService,
        { provide: PrismaService, useValue: prisma },
        { provide: PRIVY_CLIENT, useValue: mockPrivyWithWallet },
      ],
    }).compile();

    const service2 = module2.get<UserService>(UserService);
    await service2.syncUser(testPrivyUserId2);

    const user = await prisma.user.findUnique({
      where: { privyUserId: testPrivyUserId2 },
      include: { wallets: true },
    });

    expect(user).not.toBeNull();
    expect(user?.email).toBe(testEmail);
    expect(user?.wallets).toHaveLength(1);
    expect(user?.wallets[0]?.address).toBe(testWalletAddress);
    expect(user?.wallets[0]?.chain).toBe(WalletChain.EVM);
  });
});
