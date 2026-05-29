import { Readable } from 'node:stream';

import { INestApplication, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { Test, type TestingModule } from '@nestjs/testing';
import request from 'supertest';

import { paymentRequiredResponseSchema } from '@anthrion/shared';

import { AuthService } from '../auth/auth.service';

import { ArtifactStorageService } from './artifact-storage.service';
import { PaymentRequiredException } from './payment-required.exception';
import { ScanStreamService } from './scan-stream.service';
import { ScansController } from './scan.controller';
import { ScanService } from './scan.service';

/**
 * ScansController integration tests (T4.1) — supertest with mocked AuthService +
 * ScanService (mirrors UsersController spec). Covers auth enforcement, routing, and
 * that responses pass through. The real DB/queue behaviour is in scan.service.spec.ts.
 */

const validClaims = {
  appId: 'test-app',
  issuer: 'privy.io',
  issuedAt: 1700000000,
  expiration: 9999999999,
  sessionId: 'sess-1',
  userId: 'did:privy:scan-controller',
};

const mockAuthService = { verifyToken: jest.fn() };
const mockScanService = {
  createScan: jest.fn(),
  getScanById: jest.fn(),
  listScans: jest.fn(),
  getOwnedScanStatus: jest.fn(),
  getReportArtifactForOwner: jest.fn(),
};
// The controller also injects ScanStreamService (for the SSE route, T4.2); these tests
// don't exercise streaming, so a stub provider satisfies DI.
const mockScanStreamService = { observe: jest.fn() };
// ArtifactStorageService (T6.1 report download) — stubbed; the download tests set its return.
const mockArtifactStorageService = { getObjectStream: jest.fn() };

describe('ScansController (integration)', () => {
  let app: INestApplication;

  beforeEach(async () => {
    jest.clearAllMocks();
    const moduleRef: TestingModule = await Test.createTestingModule({
      controllers: [ScansController],
      providers: [
        { provide: AuthService, useValue: mockAuthService },
        { provide: ScanService, useValue: mockScanService },
        { provide: ScanStreamService, useValue: mockScanStreamService },
        { provide: ArtifactStorageService, useValue: mockArtifactStorageService },
      ],
    }).compile();
    app = moduleRef.createNestApplication();
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  // ── AuthGuard ───────────────────────────────────────────────────────────────

  it('POST /scans returns 401 without an Authorization header', async () => {
    await request(app.getHttpServer())
      .post('/scans')
      .send({ scanType: 'web-app-vuln', target: { url: 'https://x.example' } })
      .expect(401);
    expect(mockScanService.createScan).not.toHaveBeenCalled();
  });

  it('GET /scans returns 401 with an invalid token', async () => {
    mockAuthService.verifyToken.mockRejectedValueOnce(new UnauthorizedException('Invalid token'));
    await request(app.getHttpServer()).get('/scans').set('Authorization', 'Bearer bad').expect(401);
  });

  // ── POST /scans ──────────────────────────────────────────────────────────────

  it('POST /scans creates a scan for the authenticated user and returns 201', async () => {
    mockAuthService.verifyToken.mockResolvedValueOnce(validClaims);
    const created = { scanId: 'scan-1', status: 'QUEUED', scanType: 'web-app-vuln', createdAt: '2026-01-01T00:00:00.000Z' };
    mockScanService.createScan.mockResolvedValueOnce(created);

    const body = { scanType: 'web-app-vuln', target: { url: 'https://x.example' } };
    const res = await request(app.getHttpServer())
      .post('/scans')
      .set('Authorization', 'Bearer good')
      .send(body)
      .expect(201);

    // No X-PAYMENT header on a first call → the payment header arg is undefined (T5.2).
    expect(mockScanService.createScan).toHaveBeenCalledWith(validClaims.userId, body, undefined);
    expect(res.body).toEqual(created);
  });

  it('POST /scans forwards the X-PAYMENT header to the service (x402 paid retry, T5.2)', async () => {
    mockAuthService.verifyToken.mockResolvedValueOnce(validClaims);
    const created = { scanId: 'scan-2', status: 'QUEUED', scanType: 'web-app-vuln', createdAt: '2026-01-01T00:00:00.000Z' };
    mockScanService.createScan.mockResolvedValueOnce(created);

    const body = { scanType: 'web-app-vuln', target: { url: 'https://x.example' } };
    await request(app.getHttpServer())
      .post('/scans')
      .set('Authorization', 'Bearer good')
      .set('X-PAYMENT', 'base64-x402-payload')
      .send(body)
      .expect(201);

    expect(mockScanService.createScan).toHaveBeenCalledWith(validClaims.userId, body, 'base64-x402-payload');
  });

  it('POST /scans propagates a 402 (payment required) from the service', async () => {
    mockAuthService.verifyToken.mockResolvedValueOnce(validClaims);
    const requirements = {
      scheme: 'exact', network: 'base', maxAmountRequired: '10000', resource: '/scans/scan-3',
      description: 'ANTHRION security scan', mimeType: 'application/json', payTo: '0xTreasury',
      maxTimeoutSeconds: 60, asset: '0xUSDC', extra: { name: 'USDC', version: '2' },
    };
    const body402 = paymentRequiredResponseSchema.parse({
      x402Version: 1,
      accepts: [requirements],
      error: 'Payment required to run this scan',
    });
    mockScanService.createScan.mockRejectedValueOnce(new PaymentRequiredException(body402));

    const res = await request(app.getHttpServer())
      .post('/scans')
      .set('Authorization', 'Bearer good')
      .send({ scanType: 'web-app-vuln', target: { url: 'https://x.example' } })
      .expect(402);
    expect(res.body).toEqual(body402);
  });

  // ── GET /scans and GET /scans/:id ─────────────────────────────────────────────

  it('GET /scans lists the user’s scans', async () => {
    mockAuthService.verifyToken.mockResolvedValueOnce(validClaims);
    const list = { scans: [{ id: 's1', status: 'DONE', scanType: 'web-app-vuln', targetUrl: 'https://x.example', createdAt: '2026-01-01T00:00:00.000Z', finishedAt: '2026-01-01T00:01:00.000Z' }] };
    mockScanService.listScans.mockResolvedValueOnce(list);

    const res = await request(app.getHttpServer()).get('/scans').set('Authorization', 'Bearer good').expect(200);
    expect(mockScanService.listScans).toHaveBeenCalledWith(validClaims.userId);
    expect(res.body).toEqual(list);
  });

  it('GET /scans/:id returns the scan detail', async () => {
    mockAuthService.verifyToken.mockResolvedValueOnce(validClaims);
    const detail = {
      id: 's1', status: 'DONE', scanType: 'web-app-vuln', targetUrl: 'https://x.example',
      targetKind: null, failureReason: null, createdAt: '2026-01-01T00:00:00.000Z',
      startedAt: '2026-01-01T00:00:01.000Z', finishedAt: '2026-01-01T00:01:00.000Z',
      payment: { kind: 'FREE_PRICING', status: 'SETTLED' }, reportAvailable: true, findings: [],
    };
    mockScanService.getScanById.mockResolvedValueOnce(detail);

    const res = await request(app.getHttpServer()).get('/scans/s1').set('Authorization', 'Bearer good').expect(200);
    expect(mockScanService.getScanById).toHaveBeenCalledWith(validClaims.userId, 's1');
    expect(res.body).toEqual(detail);
  });

  it('GET /scans/:id propagates 404 when the service rejects (not found / not owned)', async () => {
    mockAuthService.verifyToken.mockResolvedValueOnce(validClaims);
    mockScanService.getScanById.mockRejectedValueOnce(new NotFoundException('Scan not found'));
    await request(app.getHttpServer()).get('/scans/other-user-scan').set('Authorization', 'Bearer good').expect(404);
  });

  // ── GET /scans/:id/report (T6.1) ─────────────────────────────────────────────

  it('GET /scans/:id/report streams the PDF for the owner with an attachment disposition', async () => {
    mockAuthService.verifyToken.mockResolvedValueOnce(validClaims);
    mockScanService.getReportArtifactForOwner.mockResolvedValueOnce({
      bucket: 'anthrion',
      objectKey: 'scans/s1/report.pdf',
      contentType: 'application/pdf',
      sizeBytes: 9,
    });
    mockArtifactStorageService.getObjectStream.mockResolvedValueOnce(Readable.from(Buffer.from('%PDF-1.7\n')));

    const res = await request(app.getHttpServer())
      .get('/scans/s1/report')
      .set('Authorization', 'Bearer good')
      .expect(200);

    expect(mockScanService.getReportArtifactForOwner).toHaveBeenCalledWith(validClaims.userId, 's1');
    expect(mockArtifactStorageService.getObjectStream).toHaveBeenCalledWith('anthrion', 'scans/s1/report.pdf');
    expect(res.headers['content-type']).toMatch(/application\/pdf/);
    expect(res.headers['content-disposition']).toBe('attachment; filename="anthrion-report-s1.pdf"');
  });

  it('GET /scans/:id/report returns 404 (not 500) when no report / not owned, without touching storage', async () => {
    mockAuthService.verifyToken.mockResolvedValueOnce(validClaims);
    mockScanService.getReportArtifactForOwner.mockRejectedValueOnce(
      new NotFoundException('Report not available for this scan'),
    );
    await request(app.getHttpServer()).get('/scans/s1/report').set('Authorization', 'Bearer good').expect(404);
    expect(mockArtifactStorageService.getObjectStream).not.toHaveBeenCalled();
  });

  it('GET /scans/:id/report requires authentication', async () => {
    await request(app.getHttpServer()).get('/scans/s1/report').expect(401);
    expect(mockScanService.getReportArtifactForOwner).not.toHaveBeenCalled();
  });
});
