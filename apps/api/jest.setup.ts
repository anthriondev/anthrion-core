process.env['NODE_ENV'] = 'test';
process.env['DATABASE_URL'] = 'postgresql://postgres:postgres@localhost:5436/anthrion';
process.env['REDIS_URL'] = 'redis://localhost:6380';
process.env['MINIO_ENDPOINT'] = 'localhost';
process.env['MINIO_PORT'] = '9002';
process.env['MINIO_ACCESS_KEY'] = 'minioadmin';
process.env['MINIO_SECRET_KEY'] = 'minioadmin';
process.env['PRIVY_APP_ID'] = 'test-privy-app-id';
process.env['PRIVY_APP_SECRET'] = 'test-privy-app-secret';
process.env['OPENROUTER_API_KEY'] = 'test-openrouter-key';
process.env['LLM_MODEL_LIGHT'] = 'test-light/test-model';
process.env['LLM_MODEL_HEAVY'] = 'test-heavy/test-model';
process.env['PAYMENT_USDC_BASE_ADDRESS'] = '0x0000000000000000000000000000000000000000';
process.env['PAYMENT_USDC_SOLANA_ADDRESS'] = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
// Rate limiting (T-B1.1) — OFF by default in the suite so existing controller
// integration tests are not affected. The throttler's own spec sets it back to
// false (or uses its own small limits) to verify enforcement explicitly.
process.env['RATE_LIMIT_DISABLED'] = 'true';
