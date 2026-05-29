import { INestApplication, NotFoundException } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import request from 'supertest';

import { AuthGuard } from '../auth/auth.guard';
import { AuthService } from '../auth/auth.service';

import { userProfileResponseSchema } from './user.dto';
import { UsersController } from './user.controller';
import { UserService } from './user.service';

const validClaims = {
  appId: 'test-app',
  issuer: 'privy.io',
  issuedAt: 1700000000,
  expiration: 9999999999,
  sessionId: 'sess-1',
  userId: 'did:privy:controller-test',
};

const mockProfile = {
  id: 'db-id-1',
  privyUserId: 'did:privy:controller-test',
  email: 'test@example.com',
  createdAt: '2026-01-01T00:00:00.000Z',
  wallets: [{ address: '0xABC', chain: 'EVM' as const }],
};

const mockAuthService = { verifyToken: jest.fn() };
const mockUserService = { getProfile: jest.fn() };

describe('UsersController (integration)', () => {
  let app: INestApplication;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      controllers: [UsersController],
      providers: [
        { provide: AuthService, useValue: mockAuthService },
        { provide: UserService, useValue: mockUserService },
      ],
    }).compile();

    app = module.createNestApplication();
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  it('returns 401 when no Authorization header', async () => {
    await request(app.getHttpServer()).get('/users/me').expect(401);
  });

  it('returns 401 when token is invalid', async () => {
    const { UnauthorizedException } = await import('@nestjs/common');
    mockAuthService.verifyToken.mockRejectedValueOnce(
      new UnauthorizedException('Invalid token'),
    );

    await request(app.getHttpServer())
      .get('/users/me')
      .set('Authorization', 'Bearer bad-token')
      .expect(401);
  });

  it('returns 200 with user profile for a valid token', async () => {
    mockAuthService.verifyToken.mockResolvedValueOnce(validClaims);
    mockUserService.getProfile.mockResolvedValueOnce(mockProfile);

    const response = await request(app.getHttpServer())
      .get('/users/me')
      .set('Authorization', 'Bearer valid-token')
      .expect(200);

    expect(mockUserService.getProfile).toHaveBeenCalledWith(validClaims.userId);
    expect(response.body).toEqual(mockProfile);
  });

  it('response body matches userProfileResponseSchema', async () => {
    mockAuthService.verifyToken.mockResolvedValueOnce(validClaims);
    mockUserService.getProfile.mockResolvedValueOnce(mockProfile);

    const response = await request(app.getHttpServer())
      .get('/users/me')
      .set('Authorization', 'Bearer valid-token')
      .expect(200);

    expect(() => userProfileResponseSchema.parse(response.body)).not.toThrow();
  });

  it('returns 404 when user is not found in DB', async () => {
    mockAuthService.verifyToken.mockResolvedValueOnce(validClaims);
    mockUserService.getProfile.mockRejectedValueOnce(
      new NotFoundException('User not found'),
    );

    await request(app.getHttpServer())
      .get('/users/me')
      .set('Authorization', 'Bearer valid-token')
      .expect(404);
  });

  it('profile for user with null email contains email: null', async () => {
    mockAuthService.verifyToken.mockResolvedValueOnce(validClaims);
    mockUserService.getProfile.mockResolvedValueOnce({
      ...mockProfile,
      email: null,
      wallets: [],
    });

    const response = await request(app.getHttpServer())
      .get('/users/me')
      .set('Authorization', 'Bearer valid-token')
      .expect(200);

    expect(response.body.email).toBeNull();
    expect(response.body.wallets).toHaveLength(0);
  });
});
