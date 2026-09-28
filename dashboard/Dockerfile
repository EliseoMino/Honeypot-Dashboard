# Dashboard image: a static build served by nginx.
#
# nginx is the only process that can reach the backend, and it does so with the
# proxy client certificate from var/certs. The browser only ever speaks plain
# HTTP to this container, and it never holds a private key.

FROM node:22-alpine AS build

WORKDIR /app

# Installed from the lockfile before the sources are copied, so a source change
# does not reinstall the dependency tree.
COPY dashboard/package.json dashboard/package-lock.json ./
RUN npm ci

COPY dashboard/tsconfig.json dashboard/vite.config.ts dashboard/index.html ./
COPY dashboard/src ./src
RUN npm run build


FROM nginx:1.29-alpine

COPY infrastructure/nginx/nginx.conf /etc/nginx/conf.d/default.conf
COPY infrastructure/nginx/honeypot-proxy.conf /etc/nginx/honeypot-proxy.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 8080

# wget is what the alpine image ships, and it goes through the same proxy path a
# browser uses, so a green healthcheck also proves the mTLS hop is configured.
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=5 \
    CMD ["wget", "--quiet", "--tries=1", "--spider", "http://127.0.0.1:8080/healthz"]
