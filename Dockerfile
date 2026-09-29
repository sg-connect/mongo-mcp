# syntax=docker/dockerfile:1
# mongo-mcp — read-only MongoDB MCP server over HTTP. See docker-compose.yml.
#
# Secrets never enter the image: connection strings come from .env.sandbox /
# .env.production via env_file, and connections.json / users.json are
# bind-mounted read-only at runtime.

FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci --legacy-peer-deps --ignore-scripts
COPY src ./src
RUN npm run build

FROM node:24-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --legacy-peer-deps --ignore-scripts && npm cache clean --force
COPY --from=build /app/dist ./dist
RUN mkdir -p /app/config /data && chown -R node:node /data
USER node

ENV MONGO_MCP_HTTP_HOST=0.0.0.0 \
    MONGO_MCP_HTTP_PORT=8765 \
    MONGO_MCP_CONFIG=/app/config/connections.json \
    MONGO_MCP_USERS_FILE=/app/config/users.json \
    MONGO_MCP_AUDIT_LOG=/data/audit.jsonl \
    MONGO_MCP_TRUST_PROXY=1

EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -qO- http://127.0.0.1:8765/healthz >/dev/null || exit 1

CMD ["node", "dist/cli.js"]
