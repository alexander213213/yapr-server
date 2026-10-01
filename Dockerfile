# ---- build: full dev deps for tsc ----
FROM node:22-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# ---- runtime: prod deps only (node:sqlite is stdlib, no native toolchain needed) ----
FROM node:22-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/dist ./dist
COPY scripts/healthcheck.cjs ./scripts/healthcheck.cjs
RUN useradd --system --create-home --home-dir /home/yapr yapr \
  && mkdir -p /data && chown yapr:yapr /data
USER yapr
VOLUME ["/data"]
ENV YAPR_SERVER_DATA_DIR=/data
EXPOSE 9000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "scripts/healthcheck.cjs"]
CMD ["node", "dist/server.js"]
