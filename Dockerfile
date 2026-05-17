# ── Build ─────────────────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS builder

# ca-certificates are copied into the final stage so the service can reach
# Keycloak over HTTPS.
RUN apk add --no-cache ca-certificates

WORKDIR /src

# Download dependencies before copying source so this layer is cache-friendly:
# source changes do not invalidate the module cache.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
        -ldflags="-s -w" \
        -trimpath \
        -o /icecast-keycloak-auth \
        ./cmd/server

# ── Final ──────────────────────────────────────────────────────────────────────
FROM scratch

# TLS root certificates – required for HTTPS calls to Keycloak.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

COPY --from=builder /icecast-keycloak-auth /icecast-keycloak-auth

EXPOSE 8080

# Run as nobody (UID/GID 65534) – no privileges, no shell, no package manager.
USER 65534:65534

ENTRYPOINT ["/icecast-keycloak-auth"]
