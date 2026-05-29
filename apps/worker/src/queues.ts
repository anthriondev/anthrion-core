// Queue identity for the worker. The canonical values live in `@anthrion/shared`
// (single source of truth shared by the producer in `api` and this consumer); this
// module re-exports them so the worker keeps a local queue-constants entry point.
export { SCAN_QUEUE_NAME, SCAN_JOB_NAME } from '@anthrion/shared';
