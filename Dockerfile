# ─── Stage 1: Build & Compile ──────────────────────────────────────────
FROM node:22-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c AS builder

WORKDIR /build

RUN corepack enable && corepack prepare pnpm@9.15.4 --activate
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY tsconfig.json tsup.config.ts ./
COPY src/ ./src/
RUN pnpm run build
RUN pnpm prune --prod

# ─── Stage 2: Distroless Minimal Non-Root Runtime ──────────────────────
FROM gcr.io/distroless/nodejs20-debian12:nonroot@sha256:a6dd456208a5482cc23ce75d5a9fa1eb0337c8651811e5f8f307bfeb15a51fb7 AS runtime

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
