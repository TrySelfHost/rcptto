# syntax=docker/dockerfile:1
#
# Multi-stage build for rcptto-server.
#
# Dependencies are vendored (see docs/DEPENDENCIES.md), so the build stage needs
# no network access and no module proxy — `docker build` works offline.

# ---- build ----------------------------------------------------------------
FROM golang:1.22-alpine AS build

WORKDIR /src

# Copy the module definition and vendored dependencies first so this layer is
# cached unless the dependency set actually changes.
COPY go.mod go.sum ./
COPY vendor/ ./vendor/

COPY . .

# CGO is disabled to produce a fully static binary that runs on a distroless or
# scratch base. -trimpath keeps build paths out of the binary; -s -w strip debug
# symbols to reduce size.
RUN CGO_ENABLED=0 GOOS=linux go build \
      -mod=vendor \
      -trimpath \
      -ldflags="-s -w" \
      -o /out/rcptto-server \
      ./cmd/rcptto-server

# ---- runtime ---------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

# The image carries CA certificates (from distroless) for any outbound TLS, and
# runs as an unprivileged user by default.
COPY --from=build /out/rcptto-server /usr/local/bin/rcptto-server

EXPOSE 8080
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/rcptto-server"]
