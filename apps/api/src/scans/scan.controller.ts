import {
  Body,
  Controller,
  Get,
  Headers,
  Param,
  Post,
  Req,
  Sse,
  StreamableFile,
  UseGuards,
  type MessageEvent,
} from '@nestjs/common';
import type { Observable } from 'rxjs';

import { AuthGuard, type AuthenticatedRequest } from '../auth/auth.guard';

import { ArtifactStorageService } from './artifact-storage.service';
import { ScanOwnerGuard } from './scan-owner.guard';
import { ScanStreamService } from './scan-stream.service';
import { scanIdParamSchema, type CreateScanResponse, type ScanDetailResponse, type ScanListResponse } from './scan.dto';
import { ScanService } from './scan.service';

/**
 * Scan orchestration endpoints (T4.1). All routes are protected — the authenticated
 * Privy user id (`req.privyUser.userId`) scopes every operation; the service enforces
 * that a user only sees their own scans (Part B).
 */
@Controller('scans')
@UseGuards(AuthGuard)
export class ScansController {
  constructor(
    private readonly scanService: ScanService,
    private readonly scanStream: ScanStreamService,
    private readonly artifactStorage: ArtifactStorageService,
  ) {}

  /**
   * Create a scan. x402-native (T5.2): returns 201 when the scan is created (free-pricing or a
   * settled payment), or 402 with `PaymentRequirements` when a priced scan needs payment. The
   * `X-PAYMENT` header (base64 x402 payload, present on a paid retry) is external data and is
   * validated downstream by the payment layer (CLAUDE.md §3).
   */
  @Post()
  create(
    @Req() req: AuthenticatedRequest,
    @Body() body: unknown,
    @Headers('x-payment') paymentHeader?: string,
  ): Promise<CreateScanResponse> {
    return this.scanService.createScan(req.privyUser.userId, body, paymentHeader);
  }

  @Get()
  list(@Req() req: AuthenticatedRequest): Promise<ScanListResponse> {
    return this.scanService.listScans(req.privyUser.userId);
  }

  @Get(':id')
  getOne(@Req() req: AuthenticatedRequest, @Param('id') id: string): Promise<ScanDetailResponse> {
    return this.scanService.getScanById(req.privyUser.userId, id);
  }

  /**
   * Download a scan's PDF security report (T6.1). Owner-only: the service resolves the
   * report artifact scoped to the caller's scan, returning 404 if the scan is not theirs /
   * missing OR has no report (FAILED, or report generation failed) — never a 500. The PDF
   * is streamed from MinIO via {@link StreamableFile} with an attachment disposition.
   */
  @Get(':id/report')
  async downloadReport(@Req() req: AuthenticatedRequest, @Param('id') id: string): Promise<StreamableFile> {
    // Validate the path param with Zod before use (CLAUDE.md §3).
    const scanId = scanIdParamSchema.parse(id);
    const artifact = await this.scanService.getReportArtifactForOwner(req.privyUser.userId, scanId);
    const stream = await this.artifactStorage.getObjectStream(artifact.bucket, artifact.objectKey);
    return new StreamableFile(stream, {
      type: artifact.contentType,
      disposition: `attachment; filename="anthrion-report-${scanId}.pdf"`,
      length: artifact.sizeBytes,
    });
  }

  /**
   * SSE stream of a scan's progress (T4.2). `ScanOwnerGuard` authorizes ownership BEFORE
   * the stream opens, so a non-owner / missing scan gets a clean 404 (no existence leak).
   * NestJS `@Sse` owns the SSE protocol + flushing; the Observable is torn down on client
   * disconnect / terminal event (ScanStreamService).
   */
  @Sse(':id/stream')
  @UseGuards(ScanOwnerGuard)
  stream(@Req() req: AuthenticatedRequest, @Param('id') id: string): Observable<MessageEvent> {
    return this.scanStream.observe(id, () => this.scanService.getOwnedScanStatus(req.privyUser.userId, id));
  }
}
