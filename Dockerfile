# ─── Stage 1: Build & Compile ──────────────────────────────────────────
FROM node:22-slim AS builder

WORKDIR /build

RUN corepack enable && corepack prepare pnpm@latest --activate
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY tsconfig.json tsup.config.ts ./
COPY src/ ./src/
RUN pnpm run build
RUN pnpm prune --prod

# ─── Stage 2: Distroless Minimal Non-Root Runtime ──────────────────────
FROM gcr.io/distroless/nodejs20-debian12:nonroot AS runtime

LABEL maintainer="RitualDev Lab <team@ritualdev.com>"
LABEL org.opencontainers.image.title="AgentShield"
LABEL org.opencontainers.image.description="AI Agent Runtime Defense & Kernel Sandbox Engine"
LABEL org.opencontainers.image.source="https://github.com/RitualDev-Lab/AgentShield"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

COPY --from=builder /build/package.json ./package.json
COPY --from=builder /build/dist ./dist
COPY --from=builder /build/node_modules ./node_modules

USER nonroot:nonroot

ENV NODE_ENV=production

ENTRYPOINT ["/nodejs/bin/node", "dist/cli.js"]
CMD ["start"]
