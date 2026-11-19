# Build binary statically using Go alpine
FROM golang:alpine AS builder

WORKDIR /app

# Cache Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and build static binary
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /app/pinaak .

# Minimal runtime image with CA certificates for HTTPS probing
FROM alpine:latest

LABEL org.opencontainers.image.source="https://github.com/R0X4R/pinaak"
LABEL org.opencontainers.image.description="Origin IP discovery behind CDNs and WAFs"
LABEL org.opencontainers.image.licenses="MIT"

RUN apk --no-cache add ca-certificates bind-tools

COPY --from=builder /app/pinaak /usr/local/bin/pinaak

ENTRYPOINT ["pinaak"]
