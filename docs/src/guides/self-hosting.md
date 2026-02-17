# Self-Hosting Guide

Erebor is designed to be self-hosted. This guide covers deploying to your own infrastructure.

## Minimum Requirements

| Component | Dev | Production |
|-----------|-----|-----------|
| CPU | 1 core | 2+ cores |
| RAM | 512 MB | 2+ GB |
| Disk | 1 GB | 20+ GB (PostgreSQL data) |
| OS | Linux, macOS | Linux (Debian/Ubuntu recommended) |

## Architecture Options

### Single Server (Simple)

Everything on one machine via Docker Compose:

```
┌──────────────────────────────┐
│         Single Server        │
│                              │
│  ┌────────┐  ┌──────────┐   │
│  │Gateway │  │PostgreSQL│   │
│  └────────┘  └──────────┘   │
│  ┌────────┐  ┌──────────┐   │
│  │ Caddy  │  │  Redis   │   │
│  │ (TLS)  │  │          │   │
│  └────────┘  └──────────┘   │
└──────────────────────────────┘
```

Good for: startups, small teams, <10k users.

### Multi-Service (Scalable)

Each module as a separate deployment:

```
┌──────────┐     ┌──────────┐     ┌──────────┐
│  Auth    │     │  Vault   │     │  Chain   │
│ (2 pods) │     │ (1 pod)  │     │ (2 pods) │
└────┬─────┘     └────┬─────┘     └────┬─────┘
     │                │                │
     └────────────────┼────────────────┘
                      │
              ┌───────▼───────┐
              │   PostgreSQL  │
              │   (managed)   │
              └───────────────┘
```

- Auth: scale horizontally (stateless after JWT issuance)
- Vault: scale carefully (stateful, encrypted storage)
- Chain: scale per chain traffic

## Step-by-Step Deployment

### 1. Provision a Server

```bash
# Ubuntu 22.04+ recommended
sudo apt update && sudo apt upgrade -y
sudo apt install -y docker.io docker-compose-v2 git
sudo systemctl enable docker
```

### 2. Clone and Configure

```bash
git clone https://github.com/haeli05/erebor.git
cd erebor

# Generate secrets
mkdir -p secrets
openssl rand -hex 32 > secrets/vault_key
openssl rand -base64 32 > secrets/jwt_secret

# Create .env
cat > .env << EOF
RUST_LOG=info
JWT_SECRET=$(cat secrets/jwt_secret)
VAULT_MASTER_KEY=$(cat secrets/vault_key)
SIWE_DOMAIN=yourdomain.com
DB_PASSWORD=$(openssl rand -base64 24)
EOF
```

### 3. Start Services

```bash
docker compose up -d
```

### 4. Set Up TLS

Using Caddy (automatic HTTPS):

```bash
# Install Caddy
sudo apt install -y caddy

# Configure
cat > /etc/caddy/Caddyfile << EOF
erebor.yourdomain.com {
    reverse_proxy localhost:8080
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
    }
}
EOF

sudo systemctl restart caddy
```

### 5. Verify

```bash
curl https://erebor.yourdomain.com/health
# {"status":"ok","version":"0.1.0"}
```

## Backup Strategy

### Database Backup

```bash
# Daily PostgreSQL backup
pg_dump -h localhost -U erebor erebor | gzip > backup-$(date +%Y%m%d).sql.gz

# Automate with cron
echo "0 3 * * * pg_dump -h localhost -U erebor erebor | gzip > /backups/erebor-\$(date +\%Y\%m\%d).sql.gz" | crontab -
```

### Key Material Backup

The master encryption key (`VAULT_MASTER_KEY`) is the most critical secret. If lost, encrypted shares cannot be decrypted.

- Store in a KMS (AWS KMS, GCP KMS) for production
- Keep an offline backup in a secure location (hardware security module, safe deposit box)
- The master key + database backup = full recovery capability

### Recovery Procedure

1. Restore PostgreSQL from backup
2. Configure `VAULT_MASTER_KEY` (from KMS or offline backup)
3. Start Erebor services
4. Verify: encrypted shares decrypt correctly, wallets are accessible

## Monitoring

### Health Check

```bash
# Simple cron health check
*/5 * * * * curl -sf http://localhost:8080/health || echo "Erebor down" | mail -s "Alert" admin@example.com
```

### Metrics to Watch

- API response times (p50, p95, p99)
- Error rates by endpoint
- Rate limiter triggers
- Authentication success/failure ratio
- Key operations per minute (signing, rotation)
- Database connection pool usage
- Memory usage (watch for leaks)

## Updating

```bash
cd erebor
git pull
docker compose build
docker compose up -d
```

For zero-downtime updates, use rolling deployment with a load balancer in front of multiple gateway instances.
