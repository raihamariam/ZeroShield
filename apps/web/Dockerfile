# ZeroShield web application container image (V2 Phase 4).
#
# Multi-stage build producing Next.js's "standalone" output (next.config.ts) - a
# minimal, self-contained server bundle, so the runtime stage never needs the full
# node_modules tree. The backend base URL is read from API_BASE_URL at container
# start (see next.config.ts / src/lib/api/client.ts), never baked into the image -
# the same image works against any ZeroShield API instance docker-compose.yml points
# it at.

FROM node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:22-slim AS builder
WORKDIR /app
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
