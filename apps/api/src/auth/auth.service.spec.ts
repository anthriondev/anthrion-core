import { UnauthorizedException } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';

import { PRIVY_CLIENT } from './auth.constants';
import { AuthService } from './auth.service';

const validClaims = {
  appId: 'test-app-id',
  issuer: 'privy.io',
  issuedAt: 1700000000,
  expiration: 1700086400,
  sessionId: 'session-123',
  userId: 'did:privy:user-123',
};

const mockPrivyClient = {
  verifyAuthToken: jest.fn(),
};

describe('AuthService', () => {
  let service: AuthService;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: PRIVY_CLIENT, useValue: mockPrivyClient },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  it('returns validated claims for a valid token', async () => {
    mockPrivyClient.verifyAuthToken.mockResolvedValueOnce(validClaims);

    const result = await service.verifyToken('valid-token');

    expect(result).toEqual(validClaims);
    expect(mockPrivyClient.verifyAuthToken).toHaveBeenCalledWith('valid-token');
  });

  it('throws UnauthorizedException when the SDK rejects the token', async () => {
    mockPrivyClient.verifyAuthToken.mockRejectedValueOnce(new Error('invalid token'));

    await expect(service.verifyToken('bad-token')).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('throws UnauthorizedException when claims fail schema validation', async () => {
    mockPrivyClient.verifyAuthToken.mockResolvedValueOnce({ userId: 'only-this-field' });

    await expect(service.verifyToken('partial-token')).rejects.toBeInstanceOf(UnauthorizedException);
  });
});
