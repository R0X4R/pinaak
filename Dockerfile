# Build binary statically using Go alpine
FROM golang:alpine AS builder

WORKDIR /app

# Cache Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and build static binary
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /app/pinaak main.go

# Minimal runtime image with CA certificates for HTTPS probing
FROM alpine:latest

RUN apk --no-cache add ca-certificates bind-tools

COPY --from=builder /app/pinaak /usr/local/bin/pinaak

ENTRYPOINT ["pinaak"]
