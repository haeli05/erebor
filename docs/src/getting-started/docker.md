# Docker Deployment

## Docker Compose (Development)

The simplest way to run Erebor with all dependencies:

```yaml
# docker-compose.yml
version: '3.8'

services:
  gateway:
    build: .
    ports:
      - "8080:8080"
    environment:
      - RUST_LOG=info
      - JWT_SECRET=${JWT_SECRET}
      - VAULT_MASTER_KEY=${VAULT_MASTER_KEY}
      - SIWE_DOMAIN=localhost
      - DATABASE_URL=postgres://erebor:erebor@postgres:5432/erebor
      - REDIS_URL=redis://redis:6379
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: erebor
      POSTGRES_PASSWORD: erebor
      POSTGRES_DB: erebor
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U erebor"]
      interval: 5s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 5s
      retries: 5

volumes:
  pgdata:
```

```bash
# Generate secrets
export JWT_SECRET=$(openssl rand -base64 32)
export VAULT_MASTER_KEY=$(openssl rand -hex 32)

# Start everything
docker compose up -d

# Check health
curl http://localhost:8080/health
```

## Dockerfile

```dockerfile
# Build stage
FROM rust:1.75-slim as builder
WORKDIR /app
COPY . .
RUN cargo build --release -p erebor-gateway

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/erebor-gateway /usr/local/bin/
EXPOSE 8080
CMD ["erebor-gateway"]
```

## Production Docker Compose

For production, add TLS, proper secrets management, and resource limits:

```yaml
version: '3.8'

services:
  gateway:
    image: ghcr.io/haeli05/erebor:latest
    restart: always
    ports:
      - "8080:8080"
    environment:
      - RUST_LOG=info
      - JWT_SECRET_FILE=/run/secrets/jwt_secret
      - VAULT_MASTER_KEY_FILE=/run/secrets/vault_key
      - DATABASE_URL=postgres://erebor:${DB_PASSWORD}@postgres:5432/erebor
      - REDIS_URL=redis://redis:6379
    secrets:
      - jwt_secret
      - vault_key
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '1.0'
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:16-alpine
    restart: always
    environment:
      POSTGRES_USER: erebor
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_DB: erebor
    volumes:
      - pgdata:/var/lib/postgresql/data
    deploy:
      resources:
        limits:
          memory: 1G

  redis:
    image: redis:7-alpine
    restart: always
    command: redis-server --maxmemory 256mb --maxmemory-policy allkeys-lru
    deploy:
      resources:
        limits:
          memory: 512M

secrets:
  jwt_secret:
    file: ./secrets/jwt_secret
  vault_key:
    file: ./secrets/vault_key

volumes:
  pgdata:
```

## Reverse Proxy (TLS)

Use Caddy for automatic HTTPS:

```
# Caddyfile
erebor.yourdomain.com {
    reverse_proxy gateway:8080
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
    }
}
```
