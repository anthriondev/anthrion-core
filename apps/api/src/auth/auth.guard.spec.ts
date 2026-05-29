import { Controller, Get, INestApplication, Req, UseGuards } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import request from 'supertest';

import { type AuthenticatedRequest, AuthGuard } from './auth.guard';
import { AuthService } from './auth.service';

const validClaims = {
  appId: 'test-app-id',
  issuer: 'privy.io',
  issuedAt: 1700000000,
  expiration: 1700086400,
  sessionId: 'session-abc',
  userId: 'did:privy:user-abc',
};

@Controller('test')
class TestController {
  @Get('protected')
  @UseGuards(AuthGuard)
  getProtected(@Req() req: AuthenticatedRequest): { userId: string } {
    return { userId: req.privyUser.userId };
  }
}

const mockAuthService = {
  verifyToken: jest.fn(),
};

describe('AuthGuard (integration)', () => {
  let app: INestApplication;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      controllers: [TestController],
      providers: [{ provide: AuthService, useValue: mockAuthService }],
    }).compile();

    app = module.createNestApplication();
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  it('returns 401 when Authorization header is absent', async () => {
    await request(app.getHttpServer()).get('/test/protected').expect(401);
  });

  it('returns 401 when Authorization header is not Bearer', async () => {
    await request(app.getHttpServer())
      .get('/test/protected')
      .set('Authorization', 'Basic dXNlcjpwYXNz')
      .expect(401);
  });

  it('returns 401 when AuthService.verifyToken throws', async () => {
    const { UnauthorizedException } = await import('@nestjs/common');
    mockAuthService.verifyToken.mockRejectedValueOnce(
      new UnauthorizedException('Invalid or expired token'),
    );

    await request(app.getHttpServer())
      .get('/test/protected')
      .set('Authorization', 'Bearer invalid-token')
      .expect(401);
  });

  it('returns 200 with userId for a valid token', async () => {
    mockAuthService.verifyToken.mockResolvedValueOnce(validClaims);

    const response = await request(app.getHttpServer())
      .get('/test/protected')
      .set('Authorization', 'Bearer valid-token')
      .expect(200);

    expect(response.body).toEqual({ userId: validClaims.userId });
  });
});
