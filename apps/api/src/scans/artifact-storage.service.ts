import type { Readable } from 'node:stream';

import { Injectable, Optional } from '@nestjs/common';
import { Client as MinioClient } from 'minio';

import { env } from '@anthrion/shared';

/**
 * Read-side MinIO access for `api` (T6.1). The worker (`MinioArtifactStore`) WRITES
 * artifacts; this service READS one back so the download endpoint can stream the report
 * PDF to its owner. Kept separate from the worker store on purpose — different process,
 * different concern (read-only here), and `apps/*` must not import each other
 * (ARCHITECTURE.md §2).
 *
 * SDK: official `minio` client (v8.0.7), `.d.ts` read before use (CLAUDE.md §6):
 * `getObject(bucket, key) => Promise<stream.Readable>`. Config comes from the Zod-validated
 * `env` (same MINIO_* vars the worker uses). Streaming the object (rather than buffering)
 * keeps memory flat for large reports and lets NestJS pipe it straight to the response.
 */
@Injectable()
export class ArtifactStorageService {
  private readonly client: MinioClient;

  // `@Optional()` so Nest DI does not try to resolve a MinioClient provider (there is
  // none); tests may still pass a client. Absent → the env-configured client is built.
  constructor(@Optional() client?: MinioClient) {
    this.client =
      client ??
      new MinioClient({
        endPoint: env.MINIO_ENDPOINT,
        port: env.MINIO_PORT,
        // Phase 1 local/compose MinIO is plain HTTP (mirrors the worker store).
        useSSL: false,
        accessKey: env.MINIO_ACCESS_KEY,
        secretKey: env.MINIO_SECRET_KEY,
      });
  }

  /** Open a read stream for a stored object. Rejects if the object is missing. */
  getObjectStream(bucket: string, objectKey: string): Promise<Readable> {
    return this.client.getObject(bucket, objectKey);
  }
}
