FROM node:20-bookworm-slim AS deps

ENV NODE_ENV=production \
  PLAYWRIGHT_BROWSERS_PATH=/app/ms-playwright
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

FROM node:20-bookworm-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    NODE_ENV=production \
  PLAYWRIGHT_BROWSERS_PATH=/app/ms-playwright \
  HOME=/tmp \
  XDG_CONFIG_HOME=/tmp/.chromium-config \
  XDG_CACHE_HOME=/tmp/.chromium-cache \
  XDG_RUNTIME_DIR=/tmp/.chromium-runtime \
    HOST=0.0.0.0 \
  PORT=3000

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    sqlmap \
    dnsutils \
    whois \
    curl \
    netcat-openbsd \
    openssl \
    tini \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./package.json
COPY src ./src

RUN npx playwright install --with-deps chromium

# Run as an unprivileged user by default.
RUN groupadd --system --gid 10001 appgroup \
  && ln -sf /app/node_modules/.bin/playwright /usr/local/bin/playwright \
  && useradd --system --uid 10001 --gid appgroup --home-dir /app --shell /usr/sbin/nologin appuser \
  && chown -R appuser:appgroup /app

USER appuser

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -fsS http://127.0.0.1:3000/health || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "src/server.js"]
