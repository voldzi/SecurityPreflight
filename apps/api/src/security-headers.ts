import type { FastifyReply } from "fastify";

const contentSecurityPolicy = [
  "default-src 'none'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
  "form-action 'none'",
  "object-src 'none'"
].join("; ");

export function applySecurityHeaders(reply: FastifyReply): void {
  reply.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  reply.header("Content-Security-Policy", contentSecurityPolicy);
  reply.header("X-Content-Type-Options", "nosniff");
  reply.header("X-Frame-Options", "DENY");
  reply.header("Referrer-Policy", "strict-origin-when-cross-origin");
  reply.header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()");
  reply.header("Cross-Origin-Opener-Policy", "same-origin");
  reply.header("X-DNS-Prefetch-Control", "off");
}
