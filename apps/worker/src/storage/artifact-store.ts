import { Client as MinioClient } from 'minio';

import { env } from '@anthrion/shared';

/**
 * MinIO artifact storage (T3.4, Part B).
 *
 * SDK: the official `minio` client (v8.0.7) — its `.d.ts` was read before integrating
 * (CLAUDE.md §6): `new Client(ClientOptions)`, `bucketExists`, `makeBucket`,
 * `putObject(bucket, key, Buffer, size, metaData)`. Config comes from the Zod-validated
 * `env` (MINIO_* from T0.3/T0.5). Runs in the host worker process (not in the sandbox),
 * so it reaches MinIO on localhost directly.
 *
 * Structured data (`Finding`s) goes to Postgres; MinIO holds BLOB artifacts. In Phase 1
 * the engine does not emit screenshots (the web scan does not capture them yet — see the
 * T3.4 report), so the one real artifact is the scan-log/transcript: the full
 * `ScanRunResult` as a JSON blob, archived per scan.
 */

/** Reference to a stored object — persisted on the `Artifact` row in Postgres. */
export interface ArtifactRef {
  bucket: string;
  objectKey: string;
  contentType: string;
  sizeBytes: number;
}

/** Storage surface the worker depends on (interface → stubbable in unit tests). */
export interface ArtifactStore {
  /** Create the bucket if it does not exist (idempotent). */
  ensureBucket(): Promise<void>;
  /** Upload the scan-log JSON transcript; returns its object reference. */
  uploadScanLog(scanId: string, json: string): Promise<ArtifactRef>;
  /** Upload the PDF security report (T6.1); returns its object reference. */
  uploadReportPdf(scanId: string, pdf: Buffer): Promise<ArtifactRef>;
}

export class MinioArtifactStore implements ArtifactStore {
  private readonly client: MinioClient;
  private readonly bucket: string;

  constructor(client?: MinioClient, bucket: string = env.MINIO_BUCKET) {
    this.client =
      client ??
      new MinioClient({
        endPoint: env.MINIO_ENDPOINT,
        port: env.MINIO_PORT,
        // Phase 1 local/compose MinIO is plain HTTP. A TLS endpoint would flip this
        // (env-driven) later; kept simple and explicit for now.
        useSSL: false,
        accessKey: env.MINIO_ACCESS_KEY,
        secretKey: env.MINIO_SECRET_KEY,
      });
    this.bucket = bucket;
  }

  async ensureBucket(): Promise<void> {
    if (!(await this.client.bucketExists(this.bucket))) {
      await this.client.makeBucket(this.bucket);
    }
  }

  async uploadScanLog(scanId: string, json: string): Promise<ArtifactRef> {
    const objectKey = `scans/${scanId}/scan-log.json`;
    const contentType = 'application/json';
    const body = Buffer.from(json, 'utf8');
    await this.client.putObject(this.bucket, objectKey, body, body.length, {
      'Content-Type': contentType,
    });
    return { bucket: this.bucket, objectKey, contentType, sizeBytes: body.length };
  }

  /**
   * Upload the PDF security report (T6.1). The object key is deterministic
   * (`scans/<id>/report.pdf`) so re-generating a scan's report overwrites the same blob —
   * "one report PDF per scan" holds at the storage layer too, not just the DB row.
   */
  async uploadReportPdf(scanId: string, pdf: Buffer): Promise<ArtifactRef> {
    const objectKey = `scans/${scanId}/report.pdf`;
    const contentType = 'application/pdf';
    await this.client.putObject(this.bucket, objectKey, pdf, pdf.length, {
      'Content-Type': contentType,
    });
    return { bucket: this.bucket, objectKey, contentType, sizeBytes: pdf.length };
  }
}
