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
COPY --from=builder /app/public ./public
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static

EXPOSE 3000
CMD ["node", "server.js"]
