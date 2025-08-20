# Build stage
FROM golang:1.24-bookworm AS builder

# Build arguments
ARG GOARCH

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    ca-certificates \
    less \
    jq \
    sqlite3 \
    dnsutils && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
# GOARCH will use the build arg if provided, otherwise defaults to host architecture
RUN GOOS=linux CGO_ENABLED=0 GOARCH=${GOARCH} go build \
    -mod=readonly \
    -ldflags="-s -w -X github.com/juanfont/headscale/hscontrol/types.Version=$(git describe --always --tags --dirty)" \
    -tags ts2019 \
    -o headscale \
    ./cmd/headscale

# Final stage - using alpine
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    shadow \
    su-exec \
    tzdata

# Copy the binary from builder
COPY --from=builder /app/headscale /usr/local/bin/headscale

# Copy example config (optional, users should mount their own)
COPY config-example.yaml /etc/headscale/config.yaml

# Create headscale user and group with configurable IDs
RUN addgroup -g 1000 -S headscale && \
    adduser -u 1000 -S headscale -G headscale

# Create necessary directories
RUN mkdir -p /etc/headscale \
             /var/lib/headscale \
             /var/run/headscale \
             /data && \
    chown -R headscale:headscale /etc/headscale \
                                  /var/lib/headscale \
                                  /var/run/headscale \
                                  /data

# Create entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Expose ports
EXPOSE 8080 9090

# Set default environment variables
ENV HEADSCALE_DB_TYPE=sqlite3 \
    HEADSCALE_DB_PATH=/data/headscale.db \
    PUID=1000 \
    PGID=1000

# Use the entrypoint script
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Default command
CMD ["serve"]