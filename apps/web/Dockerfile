# ZeroShield web application container image (V2 Phase 4).
#
# Multi-stage build producing Next.js's "standalone" output (next.config.ts) - a
# minimal, self-contained server bundle, so the runtime stage never needs the full
# node_modules tree. src/lib/api/client.ts's server-side fetches read API_BASE_URL
# at request time, so those follow whatever docker-compose.yml sets for the
# container. next.config.ts's rewrites() (the browser-facing same-origin "/api/*"
# proxy) is different: Next.js resolves rewrite destinations at `next build` time,
# so API_BASE_URL must also be passed as a build ARG (below), matching the
# container's runtime value - see docker-compose.yml's `web` service for why.

FROM node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:22-slim AS builder
WORKDIR /app
# next.config.ts's rewrites() reads API_BASE_URL at config-load time, which for
# `next build` happens during THIS build step - a runtime-only env var (as
# docker-compose.yml sets for the container) is too late, since by then the
# rewrite destination is already baked into .next/routes-manifest.json. Must be
# passed as a build arg too, matching the same value the container gets at runtime.
ARG API_BASE_URL=http://api:8000
ENV API_BASE_URL=$API_BASE_URL
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:22-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
# Docker always sets HOSTNAME to the container ID by default, and Next.js's
# standalone server.js binds to $HOSTNAME instead of every interface -
# without this override the server is unreachable via localhost/127.0.0.1/
# ::1 from inside its own container (only reachable via the container's
# real bridge-network IP, which is why a healthcheck run inside the
# container failed while the host-published port kept working). This bit
# a Docker healthcheck added in the final release verification pass, not a
# byte of application code.
ENV HOSTNAME=0.0.0.0
COPY --from=builder /app/public ./public
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static

EXPOSE 3000
CMD ["node", "server.js"]
