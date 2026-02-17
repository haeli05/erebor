# Self-Hosting Guide

This guide covers deploying Erebor in production.

## Docker Compose (Simple)

```yaml
version: '3.8'
services:
  gateway:
    image: erebor:latest
    build: .
    ports: ["8080:8080"]
    depends_on: [postgres, redis]
    environment:
      RUST_LOG: info
      JWT_SECRET: ${JWT_SECRET}
      VAULT_MASTER_KEY: ${VAULT_MASTER_KEY}
      DATABASE_URL: postgres://erebor:${DB_PASSWORD}@postgres:5432/erebor
      REDIS_URL: redis://redis:6379
      SIWE_DOMAIN: ${SIWE_DOMAIN:-localhost}
      GOOGLE_CLIENT_ID: ${GOOGLE_CLIENT_ID:-}
      GOOGLE_CLIENT_SECRET: ${GOOGLE_CLIENT_SECRET:-}
      GOOGLE_REDIRECT_URI: ${GOOGLE_REDIRECT_URI:-}
    restart: unless-stopped

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: erebor
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_DB: erebor
    volumes:
      - pgdata:/var/lib/postgresql/data
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    command: redis-server --maxmemory 256mb --maxmemory-policy allkeys-lru
    restart: unless-stopped

volumes:
  pgdata:
```

### Deploy

```bash
# Generate secrets
export JWT_SECRET=$(openssl rand -hex 32)
export VAULT_MASTER_KEY=$(openssl rand -hex 32)
export DB_PASSWORD=$(openssl rand -hex 16)
export SIWE_DOMAIN=yourdomain.com

# Save secrets securely
echo "JWT_SECRET=$JWT_SECRET" >> .env.production
echo "VAULT_MASTER_KEY=$VAULT_MASTER_KEY" >> .env.production
echo "DB_PASSWORD=$DB_PASSWORD" >> .env.production

# Start
docker compose --env-file .env.production up -d
```

## Reverse Proxy (Nginx)

```nginx
server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/api.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Rate limiting headers for Erebor
        proxy_pass_header X-Real-IP;
    }

    # Health check (no auth)
    location /health {
        proxy_pass http://127.0.0.1:8080/health;
    }
}
```

## Kubernetes (Helm)

Basic deployment manifest:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: erebor-gateway
spec:
  replicas: 3
  selector:
    matchLabels:
      app: erebor-gateway
  template:
    metadata:
      labels:
        app: erebor-gateway
    spec:
      containers:
      - name: gateway
        image: erebor:latest
        ports:
        - containerPort: 8080
        env:
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: erebor-secrets
              key: jwt-secret
        - name: VAULT_MASTER_KEY
          valueFrom:
            secretKeyRef:
              name: erebor-secrets
              key: vault-master-key
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: erebor-secrets
              key: database-url
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          periodSeconds: 10
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: erebor-gateway
spec:
  selector:
    app: erebor-gateway
  ports:
  - port: 80
    targetPort: 8080
  type: ClusterIP
```

## Scaling Considerations

| Service | Scaling | Notes |
|---------|---------|-------|
| Gateway | Horizontal | Stateless — scale freely behind a load balancer |
| Auth | Horizontal | Stateless after JWT issuance (sessions in Redis) |
| Vault | Careful | Stateful — encrypted storage must be consistent |
| PostgreSQL | Vertical / Read replicas | ACID required for key metadata |
| Redis | Cluster | Sessions, nonces, rate limits |

## Backup Strategy

### Critical Data

1. **`VAULT_MASTER_KEY`** — Without this, all encrypted shares are unrecoverable. Store in multiple secure locations (HSM, sealed envelope, etc.)
2. **PostgreSQL** — Contains user data and encrypted key shares

```bash
# Database backup
pg_dump -h localhost -U erebor erebor | gzip > erebor_backup_$(date +%Y%m%d).sql.gz

# Verify backup
gunzip -c erebor_backup_*.sql.gz | head -20
```

### What NOT to Back Up

- Redis — ephemeral data (sessions, nonces). Lost Redis = users re-authenticate.
- Logs — useful but not critical for recovery.

## Monitoring

### Health Check

```bash
# Simple uptime check
curl -sf http://localhost:8080/health || alert "Erebor is down"
```

### Recommended Metrics

- Request latency (p50, p95, p99) per endpoint
- Error rate by status code
- Active sessions count
- Key operations per minute (signing, rotation)
- Rate limiter rejections
