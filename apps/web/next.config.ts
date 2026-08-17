import type { NextConfig } from "next";

// The FastAPI backend the UI consumes exclusively (never Postgres/MinIO/RabbitMQ/Python
// directly - see apps/web/README.md). API_BASE_URL is the server-side address (used by
// Server Components/Route Handlers, which run in Node and can reach any host/port). The
// rewrite below gives the *browser* a same-origin "/api/*" path that proxies to the same
// backend, so client-side code (the SSE live-run view, the experiment studio wizard) never
// needs FastAPI to grant CORS to the Next.js origin.
const apiBaseUrl = process.env.API_BASE_URL ?? "http://localhost:8000";

const nextConfig: NextConfig = {
  // Self-contained server bundle for the Docker image (apps/web/Dockerfile) - no
  // node_modules copy needed at runtime.
  output: "standalone",
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${apiBaseUrl}/:path*`,
      },
    ];
  },
};

export default nextConfig;
