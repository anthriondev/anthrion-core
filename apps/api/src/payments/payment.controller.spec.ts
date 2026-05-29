import { INestApplication, UnauthorizedException } from '@nestjs/common';
import { Test, type TestingModule } from '@nestjs/testing';
import request from 'supertest';

import { AuthService } from '../auth/auth.service';

import { PaymentsController } from './payment.controller';
import { PaymentService } from './payment.service';

/**
 * PaymentsController integration tests (T5.4) — supertest with a mocked AuthService +
 * PaymentService (mirrors ScansController spec). Covers auth enforcement, routing, and that the
 * authenticated user id is scoped through to the service (a user only reads its own status). The
 * real DB eligibility logic is exercised in payment.service.spec.ts.
 */

const validClaims = {
  appId: 'test-app',
  issuer: 'privy.io',
  issuedAt: 1700000000,
  expiration: 9999999999,
  sessionId: 'sess-1',
  userId: 'did:privy:payment-controller',
};

const mockAuthService = { verifyToken: jest.fn() };
const mockPaymentService = { getFreeTrialStatus: jest.fn() };

describe('PaymentsController (integration)', () => {
  let app: INestApplication;

  beforeEach(async () => {
    jest.clearAllMocks();
    const moduleRef: TestingModule = await Test.createTestingModule({
      controllers: [PaymentsController],
      providers: [
        { provide: AuthService, useValue: mockAuthService },
        { provide: PaymentService, useValue: mockPaymentService },
      ],
    }).compile();
    app = moduleRef.createNestApplication();
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  it('GET /payments/free-trial returns 401 without an Authorization header', async () => {
    await request(app.getHttpServer()).get('/payments/free-trial').expect(401);
    expect(mockPaymentService.getFreeTrialStatus).not.toHaveBeenCalled();
  });

  it('GET /payments/free-trial returns 401 with an invalid token', async () => {
    mockAuthService.verifyToken.mockRejectedValueOnce(new UnauthorizedException('Invalid token'));
    await request(app.getHttpServer())
      .get('/payments/free-trial')
      .set('Authorization', 'Bearer bad')
      .expect(401);
    expect(mockPaymentService.getFreeTrialStatus).not.toHaveBeenCalled();
  });

  it('GET /payments/free-trial returns the status scoped to the authenticated user', async () => {
    mockAuthService.verifyToken.mockResolvedValueOnce(validClaims);
    const status = { status: 'available', walletAddress: '0xWallet0000000000000000000000000000001234' };
    mockPaymentService.getFreeTrialStatus.mockResolvedValueOnce(status);

    const res = await request(app.getHttpServer())
      .get('/payments/free-trial')
      .set('Authorization', 'Bearer good')
      .expect(200);

    // The authenticated user id (NOT a client-supplied one) is what scopes the read.
    expect(mockPaymentService.getFreeTrialStatus).toHaveBeenCalledWith(validClaims.userId);
    expect(res.body).toEqual(status);
  });
});
