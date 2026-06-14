const basePath = process.env.NEXT_PUBLIC_SECURITY_PREFLIGHT_BASE_PATH?.trim().replace(/\/$/, "") ?? "";

/** @type {import('next').NextConfig} */
const nextConfig = {
  basePath: basePath || undefined,
  trailingSlash: true,
  transpilePackages: [
    "@security-preflight/core",
    "@security-preflight/config",
    "@security-preflight/report",
    "@security-preflight/scanners"
  ]
};

export default nextConfig;
