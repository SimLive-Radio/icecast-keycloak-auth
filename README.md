# icecast-keycloak-auth

A lightweight authentication proxy that lets [Icecast](https://icecast.org/) delegate stream access control to [Keycloak](https://www.keycloak.org/).

Icecast only knows one source password — everyone who knows it can stream. This service sits in between: Icecast calls out on every connection attempt, this service validates the credentials against Keycloak using the [Resource Owner Password Credentials (ROPC)](https://www.rfc-editor.org/rfc/rfc6749#section-4.3) flow and checks that the user holds the required client role. No role, no stream.

Users and roles live entirely in Keycloak. This service stores nothing.

[![Go 1.26](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Table of Contents

- [icecast-keycloak-auth](#icecast-keycloak-auth)
  - [Table of Contents](#table-of-contents)
  - [How It Works](#how-it-works)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
    - [Build from source](#build-from-source)
    - [Docker](#docker)
  - [Configuration](#configuration)
    - [Minimal example](#minimal-example)
    - [Keycloak setup](#keycloak-setup)
  - [Running](#running)
    - [Health check](#health-check)
  - [API](#api)
    - [POST /auth](#post-auth)
  - [Metrics](#metrics)
  - [Logs](#logs)
  - [Development](#development)
    - [Run all tests](#run-all-tests)
    - [Run tests with verbose output](#run-tests-with-verbose-output)
    - [Run a specific package](#run-a-specific-package)
    - [Build](#build)
    - [Lint](#lint)
  - [Contributing](#contributing)

---

## How It Works

```
Listener connects to Icecast
        │
        ▼
Icecast POSTs to /auth (URL auth)
        │
        ├─ action ≠ stream_auth  ──► 200  (listener bookkeeping, no credential check)
        │
        ├─ user or pass empty    ──► 401
        │
        ├─ Keycloak ROPC token request
        │       fails            ──► 401
        │
        ├─ Decode JWT payload
        │   resource_access[CLIENT_ID].roles contains REQUIRED_CLIENT_ROLE?
        │
        ├─ No                    ──► 403
        └─ Yes                   ──► 200  +  icecast-auth-user: 1
```

Keycloak is the single source of truth. The JWT returned by ROPC is decoded locally — no additional API call is made to verify roles (the token comes directly from Keycloak over a server-to-server connection, so signature verification is not required).

---

## Prerequisites

| Requirement | Version |
|---|---|
| Go | 1.26 or later |
| Keycloak | 21 or later (any version with OIDC ROPC support) |
| Icecast | 2.4 or later (with `<authentication>` URL auth support) |

An OpenTelemetry-compatible metrics collector (e.g. [Grafana Alloy](https://grafana.com/oss/alloy/), [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/)) is optional but recommended.

---

## Installation

### Build from source

```bash
git clone https://github.com/your-org/icecast-keycloak-auth.git
cd icecast-keycloak-auth
go build -o icecast-keycloak-auth ./cmd/server
```

### Docker

The included `Dockerfile` produces a minimal image based on `scratch` — no OS, no shell, no package manager. The binary is statically linked (`CGO_ENABLED=0`) so no libc is needed. Only two files exist in the final image: the binary and a CA certificate bundle for HTTPS connections to Keycloak.

```bash
# Build the image
docker build -t icecast-keycloak-auth .

# Run
docker run --rm \
  -e KEYCLOAK_BASE_URL=https://auth.example.com \
  -e KEYCLOAK_REALM=radio \
  -e KEYCLOAK_CLIENT_ID=icecast \
  -e REQUIRED_CLIENT_ROLE=streamer \
  -p 8080:8080 \
  icecast-keycloak-auth
```

---

## Configuration

All configuration is done via environment variables. The service refuses to start if any required variable is missing and prints every missing variable at once.

| Variable | Required | Default | Description |
|---|---|---|---|
| `KEYCLOAK_BASE_URL` | **Yes** | — | Base URL of your Keycloak instance, e.g. `https://auth.example.com` |
| `KEYCLOAK_REALM` | **Yes** | — | Realm name |
| `KEYCLOAK_CLIENT_ID` | **Yes** | — | Client configured with ROPC (Direct Access Grants enabled) |
| `REQUIRED_CLIENT_ROLE` | **Yes** | — | Client role a user must hold to be allowed to stream |
| `LISTEN_ADDR` | No | `:8080` | Address and port the HTTP server binds to |
| `KEYCLOAK_CLIENT_SECRET` | No | — | Leave empty for public clients |
| `LOG_LEVEL` | No | `info` | One of `debug`, `info`, `warn`, `error` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | No | — | OTLP collector endpoint. If not set OTEL is disabled |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | No | `grpc` | `grpc` or `http/protobuf` |
| `OTEL_EXPORTER_OTLP_HEADERS` | No | — | Comma-separated `Key=Value` pairs sent with every export request |
| `OTEL_METRIC_EXPORT_INTERVAL` | No | `15s` | How often metrics are pushed (e.g. `30s`, `1m`) |
| `OTEL_SERVICE_NAME` | No | `icecast-keycloak-auth` | Service name reported in telemetry |
| `OTEL_RESOURCE_ATTRIBUTES` | No | — | Extra OTel resource attributes, comma-separated `key=value` |
| `LOKI_SERVICE_LABEL` | No | `icecast-auth` | Value of the static `service` field in every log line |
| `LOKI_ENV_LABEL` | No | `production` | Value of the static `env` field in every log line |

If the OTLP collector is unreachable the service starts anyway and logs a warning — metrics are simply not exported until the collector becomes available on the next push interval.

### Minimal example

```bash
export KEYCLOAK_BASE_URL=https://auth.example.com
export KEYCLOAK_REALM=radio
export KEYCLOAK_CLIENT_ID=icecast
export REQUIRED_CLIENT_ROLE=streamer
./icecast-keycloak-auth
```

### Keycloak setup

1. Create a client (e.g. `icecast`) in your realm.
2. Under **Settings → Capability config**, enable **Direct access grants**.
3. Create a client role (e.g. `streamer`).
4. Assign the role to every user who should be allowed to stream.

---

## Running

```bash
./icecast-keycloak-auth
# 2026-05-14T12:00:00Z INFO server starting addr=:8080 service=icecast-auth env=production
```

### Health check

```
GET /health  →  200 OK
```

Suitable for use as a Kubernetes liveness/readiness probe or a Docker `HEALTHCHECK`.

---

## API

### POST /auth

Called by Icecast on every connection attempt. The body is `application/x-www-form-urlencoded`.

**Request fields**

| Field | Description |
|---|---|
| `action` | `stream_auth`, `listener_add`, or `listener_remove` |
| `user` | Username supplied by the connecting client |
| `pass` | Password supplied by the connecting client |
| `ip` | Client IP address (logged only, not used for access decisions) |
| `agent` | User-Agent string (logged only) |

**Responses**

| Code | Header | Meaning |
|---|---|---|
| `200` | `icecast-auth-user: 1` | Access granted |
| `401` | — | Bad credentials or Keycloak unreachable |
| `403` | — | Valid credentials but required client role is missing |
| `405` | — | Non-POST request |

Only `stream_auth` triggers a credential check. All other actions (`listener_add`, `listener_remove`, etc.) are always approved — they represent bookkeeping events, not access decisions.

---

## Metrics

Metrics are pushed via OTLP at a configurable interval (default 15 s). No pull/scrape endpoint is exposed.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `auth_requests_total` | Counter | `action`, `result` | All requests through `/auth`, labelled by result (`success` / `unauthorized` / `forbidden` / `passthrough`) |
| `auth_duration_seconds` | Histogram | `action` | End-to-end latency for each auth request |
| `keycloak_requests_total` | Counter | `result` | Keycloak ROPC calls, labelled `success` or `error` |
| `keycloak_duration_seconds` | Histogram | — | Latency of the Keycloak token request |
| `role_denied_total` | Counter | `required_role` | Requests denied because the user lacked the required role |

---

## Logs

Logs are emitted as JSON on stdout, suitable for ingestion by Loki or any JSON-aware log aggregator.

```json
{
  "time":        "2026-05-14T12:34:56.789Z",
  "level":       "INFO",
  "msg":         "auth request",
  "service":     "icecast-auth",
  "env":         "production",
  "action":      "stream_auth",
  "user":        "max.mustermann",
  "ip":          "203.0.113.42",
  "result":      "success",
  "duration_ms": 143
}
```

The `service` and `env` fields are static Loki labels configured via `LOKI_SERVICE_LABEL` and `LOKI_ENV_LABEL`. Passwords and tokens are never written to logs.


---

## Development

### Run all tests

```bash
go test ./...
```

### Run tests with verbose output

```bash
go test ./... -v
```

### Run a specific package

```bash
go test ./internal/keycloak/... -v
go test ./features/... -v
```

### Build

```bash
go build ./cmd/server
```

### Lint

```bash
go vet ./...
```

The test suite includes unit tests for every package and feature tests that exercise the full request path against a real HTTP mock of Keycloak — no external services required.

---

## Contributing

Contributions are welcome. Please:

1. Fork the repository and create a feature branch from `main`.
2. Write tests for any new behaviour.
3. Ensure `go test ./...` and `go vet ./...` pass cleanly.
4. Open a pull request with a clear description of what changed and why.

For larger changes, open an issue first to discuss the approach.
