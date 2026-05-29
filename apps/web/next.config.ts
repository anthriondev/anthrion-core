import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // @anthrion/ui and @anthrion/shared are published as TypeScript source (no prebuilt
  // dist consumed here), so Next must transpile them. Web imports @anthrion/shared only
  // via its bullmq-free subpaths (/scan-api, /scan-stream), never the package barrel.
  transpilePackages: ['@anthrion/ui', '@anthrion/shared'],
};

export default nextConfig;
