# syntax=docker/dockerfile:1
ARG NODE_VERSION=24.21.0
ARG GO_VERSION=1.27.2
FROM node:${NODE_VERSION}-bookworm-slim AS web-build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY web/ web/
COPY scripts/build.mjs scripts/vendor-terminal.mjs scripts/
RUN node scripts/build.mjs web

FROM golang:${GO_VERSION}-bookworm AS server-build
WORKDIR /src
COPY remote-access/go.mod remote-access/go.sum ./
RUN go mod download
COPY remote-access/ ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/infrascope ./cmd/infrascope

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates openssl && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 infrascope && useradd --uid 10001 --gid infrascope --no-create-home infrascope
WORKDIR /app
COPY --from=server-build /out/infrascope /app/infrascope
COPY --from=web-build /src/dist /app/web
COPY deploy/offline/runtime/ /app/offline/
USER 10001:10001
ENV REMOTE_STATIC_DIR=/app/web REMOTE_LISTEN=0.0.0.0:8443
EXPOSE 8443
ENTRYPOINT ["/app/infrascope"]
CMD ["serve"]
