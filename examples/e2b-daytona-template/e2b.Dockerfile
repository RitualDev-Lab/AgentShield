# Official RitualDev-Lab E2B / Daytona MicroVM Sandbox Template
# Bundles AgentShield (>=0.2.2) + DBShield (>=0.2.1) in a non-root air-gapped workspace.
FROM node:22-bookworm-slim

LABEL org.opencontainers.image.title="AgentShield + DBShield E2B/Daytona Sandbox" \
      org.opencontainers.image.description="Hardened non-root cloud sandbox microVM with AgentShield zero-leak redaction and DBShield SQL wire firewall" \
      org.opencontainers.image.source="https://github.com/RitualDev-Lab/AgentShield" \
      org.opencontainers.image.licenses="Apache-2.0"

# Install minimal runtime utilities and bubblewrap for nested kernel confinement
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      git \
      bubblewrap \
      jq \
    && rm -rf /var/lib/apt/lists/*

# Install canonical RitualDev-Lab defense CLIs globally (pinned minimum versions)
RUN npm install -g \
      @ritualdev-lab/agentshield@>=0.2.2 \
      @ritualdev-lab/dbshield@>=0.2.1 \
    && npm cache clean --force

# Create unprivileged agent user (UID 10001)
RUN groupadd -g 10001 agent && useradd -m -u 10001 -g 10001 -s /bin/bash agent

WORKDIR /workspace
COPY --chown=10001:10001 entrypoint.sh /usr/local/bin/ritual-entrypoint.sh
RUN chmod 0755 /usr/local/bin/ritual-entrypoint.sh

# Enforce strict offline air-gapped defaults
ENV RITUAL_AIR_GAPPED=1 \
    AGENTSHIELD_AIR_GAPPED=1 \
    AGENTSHIELD_MODE=strict \
    DBSHIELD_SAFETY_TIER=STRICT \
    NODE_ENV=production

USER 10001:10001

ENTRYPOINT ["/usr/local/bin/ritual-entrypoint.sh"]
CMD ["bash"]
