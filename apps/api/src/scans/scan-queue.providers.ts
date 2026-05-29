import { Inject, Injectable, type OnApplicationShutdown, type Provider } from '@nestjs/common';

import { ScanQueueProducer, env } from '@anthrion/shared';

/**
 * Wiring for the BullMQ scan-queue producer in `api` (T4.1, Part C).
 *
 * `api` is the producer (ARCHITECTURE.md §3). The producer is provided as a singleton
 * built from the validated `REDIS_URL` (the producer takes its connection from the
 * caller, T3.1) and closed on application shutdown so the Redis connection is released
 * cleanly (requires `app.enableShutdownHooks()` in main.ts).
 */

/** DI token for the injected {@link ScanQueueProducer}. */
export const SCAN_QUEUE_PRODUCER = 'SCAN_QUEUE_PRODUCER';

export const scanQueueProducerProvider: Provider = {
  provide: SCAN_QUEUE_PRODUCER,
  useFactory: (): ScanQueueProducer => new ScanQueueProducer({ url: env.REDIS_URL }),
};

/** Closes the producer's Redis connection when the app shuts down. */
@Injectable()
export class ScanQueueShutdown implements OnApplicationShutdown {
  constructor(@Inject(SCAN_QUEUE_PRODUCER) private readonly producer: ScanQueueProducer) {}

  async onApplicationShutdown(): Promise<void> {
    await this.producer.close();
  }
}
