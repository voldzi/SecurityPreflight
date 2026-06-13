/** @type {import('next').NextConfig} */
const nextConfig = {
  transpilePackages: [
    "@security-preflight/core",
    "@security-preflight/config",
    "@security-preflight/report",
    "@security-preflight/scanners"
  ]
};

export default nextConfig;
