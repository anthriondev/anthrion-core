// Test env bootstrap. Importing `@anthrion/shared` evaluates its env schema, which
// validates `process.env` at load time (T0.3). Set the required vars here BEFORE
// that import runs. Mirrors apps/api/jest.setup.ts. Values are only applied when not
// already set, so a real environment (e.g. CI, or a custom REDIS_URL) takes priority.
//
// This file is NOT a test (it does not match `*.test.ts`) and is excluded from the
// build. Import it FIRST in a test file so it runs before any `@anthrion/shared` import.
const defaults: Record<string, string> = {
  NODE_ENV: 'test',
  DATABASE_URL: 'postgresql://postgres:postgres@localhost:5436/anthrion',
  REDIS_URL: 'redis://localhost:6380',
  MINIO_ENDPOINT: 'localhost',
  MINIO_PORT: '9002',
  MINIO_ACCESS_KEY: 'minioadmin',
  MINIO_SECRET_KEY: 'minioadmin',
  PRIVY_APP_ID: 'test-privy-app-id',
  PRIVY_APP_SECRET: 'test-privy-app-secret',
  OPENROUTER_API_KEY: 'test-openrouter-key',
  LLM_MODEL_LIGHT: 'test-light/test-model',
  LLM_MODEL_HEAVY: 'test-heavy/test-model',
  PAYMENT_USDC_BASE_ADDRESS: '0x0000000000000000000000000000000000000000',
  PAYMENT_USDC_SOLANA_ADDRESS: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
};

for (const [key, value] of Object.entries(defaults)) {
  process.env[key] ??= value;
}
