import baseConfig from '@anthrion/config/eslint';

export default [
  // The Prisma-generated client is not our source — never lint it.
  { ignores: ['src/generated/**'] },
  ...baseConfig,
  {
    // local overrides — none for now
  },
];
