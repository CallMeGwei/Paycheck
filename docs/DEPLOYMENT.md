# Production Deployment Guide

This guide covers deploying Paycheck to a production Linux server.

## Prerequisites

- Linux server (Ubuntu 22.04+ or similar)
- Rust toolchain (for building) or pre-built binary, OR Docker
- SQLite 3.35+ (included in Docker image)
- Reverse proxy (nginx, Caddy, etc.)
- Domain with TLS certificate

---

## Quick Start with Docker

The fastest way to deploy:

```bash
# 1. Generate master key
openssl rand -base64 32 > master.key
chmod 400 master.key

# 2. Create docker-compose.yml (or use the one in the repo)
# 3. Edit environment variables in docker-compose.yml

# 4. Start
docker compose up -d

# 5. Check logs for bootstrap operator API key
docker compose logs paycheck | grep "BOOTSTRAP OPERATOR"
```

### Docker Compose Configuration

```yaml
services:
  paycheck:
    build: .
    # Or use pre-built: image: ghcr.io/CallMeGwei/Paycheck:latest
    container_name: paycheck
    restart: unless-stopped
    ports:
      - "127.0.0.1:4242:4242"
    volumes:
      - paycheck-data:/var/lib/paycheck
      - ./master.key:/etc/paycheck/master.key:ro
    environment:
      - PAYCHECK_MASTER_KEY_FILE=/etc/paycheck/master.key
      - BASE_URL=https://api.yourdomain.com
      - BOOTSTRAP_OPERATOR_EMAIL=admin@yourdomain.com
      - PAYCHECK_CONSOLE_ORIGINS=https://admin.yourdomain.com

volumes:
  paycheck-data:
```

### Docker Commands

```bash
# Build image
docker build -t paycheck .

# View logs
docker compose logs -f paycheck

# Backup database
docker compose exec paycheck sqlite3 /var/lib/paycheck/paycheck.db ".backup '/var/lib/paycheck/backup.db'"
docker cp paycheck:/var/lib/paycheck/backup.db ./backup.db

# Key rotation
docker compose down
docker run --rm -v paycheck-data:/var/lib/paycheck \
  -v ./master.key:/etc/paycheck/master.key:ro \
  -v ./master.key.new:/etc/paycheck/master.key.new:ro \
  paycheck --rotate-key \
  --old-key-file /etc/paycheck/master.key \
  --new-key-file /etc/paycheck/master.key.new
mv master.key.new master.key
docker compose up -d
```

---

## Manual Deployment (without Docker)

## 1. Build the Binary

On your build machine:

```bash
# Clone and build release binary
git clone https://github.com/CallMeGwei/Paycheck.git
cd paycheck
cargo build --release

# Binary is at target/release/paycheck
```

Or cross-compile for your target:

```bash
# For x86_64 Linux (musl for static linking)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## 2. Server Setup

### Create Service User

```bash
# Create dedicated user (no login shell)
sudo useradd --system --shell /usr/sbin/nologin --create-home paycheck

# Create directories
sudo mkdir -p /etc/paycheck
sudo mkdir -p /var/lib/paycheck
sudo mkdir -p /var/log/paycheck

# Set ownership
sudo chown paycheck:paycheck /var/lib/paycheck
sudo chown paycheck:paycheck /var/log/paycheck
```

### Install Binary

```bash
# Copy binary to server
sudo cp target/release/paycheck /usr/local/bin/paycheck
sudo chmod 755 /usr/local/bin/paycheck
```

## 3. Master Key Setup (Critical)

The master key encrypts all project private keys and payment provider credentials at rest. This is the most sensitive secret in the system.

```bash
# Generate master key
openssl rand -base64 32 | sudo tee /etc/paycheck/master.key > /dev/null

# Set strict permissions (REQUIRED - server refuses to start otherwise)
sudo chown paycheck:paycheck /etc/paycheck/master.key
sudo chmod 400 /etc/paycheck/master.key
```

**Security requirements:**
- File must be readable only by the service user
- Permissions must be exactly `0400` (enforced at startup)
- Never commit to version control
- Back up securely (encrypted, offline)

## 4. Environment Configuration

Create `/etc/paycheck/paycheck.env`:

```bash
# Required
PAYCHECK_MASTER_KEY_FILE=/etc/paycheck/master.key
BASE_URL=https://api.yourdomain.com
BOOTSTRAP_OPERATOR_EMAIL=admin@yourdomain.com

# Database paths
DATABASE_PATH=/var/lib/paycheck/paycheck.db
AUDIT_DATABASE_PATH=/var/lib/paycheck/paycheck_audit.db

# Network
HOST=127.0.0.1
PORT=4242

# Admin UI CORS (your admin dashboard domain)
PAYCHECK_CONSOLE_ORIGINS=https://admin.yourdomain.com

# Email (optional - orgs can configure their own)
PAYCHECK_RESEND_API_KEY=re_xxxxxxxxxxxxx
PAYCHECK_DEFAULT_FROM_EMAIL=noreply@yourdomain.com

# Audit log retention for public (end-user) actions (days, 0 = never purge)
# Internal actions (operator, org_member, system) are kept forever for audit trail
# PUBLIC_AUDIT_LOG_RETENTION_DAYS=90

# Rate limiting (defaults shown, adjust as needed)
# RATE_LIMIT_STRICT_RPM=10
# RATE_LIMIT_STANDARD_RPM=30
# RATE_LIMIT_RELAXED_RPM=60
# RATE_LIMIT_ORG_OPS_RPM=3000

# Logging level
RUST_LOG=paycheck=info,tower_http=info
```

Secure the env file:

```bash
sudo chown root:paycheck /etc/paycheck/paycheck.env
sudo chmod 640 /etc/paycheck/paycheck.env
```

## 5. Systemd Service

Create `/etc/systemd/system/paycheck.service`:

```ini
[Unit]
Description=Paycheck Licensing Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=paycheck
Group=paycheck
WorkingDirectory=/var/lib/paycheck
EnvironmentFile=/etc/paycheck/paycheck.env
ExecStart=/usr/local/bin/paycheck
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ReadWritePaths=/var/lib/paycheck /var/log/paycheck
ReadOnlyPaths=/etc/paycheck

# Resource limits
LimitNOFILE=65535
MemoryMax=512M

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable paycheck
sudo systemctl start paycheck

# Check status
sudo systemctl status paycheck
sudo journalctl -u paycheck -f
```

## 6. Reverse Proxy (nginx)

Create `/etc/nginx/sites-available/paycheck`:

```nginx
# Rate limiting zone
limit_req_zone $binary_remote_addr zone=paycheck_limit:10m rate=30r/s;

upstream paycheck {
    server 127.0.0.1:4242;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    # TLS configuration
    ssl_certificate /etc/letsencrypt/live/api.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    # Security headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Logging
    access_log /var/log/nginx/paycheck_access.log;
    error_log /var/log/nginx/paycheck_error.log;

    location / {
        limit_req zone=paycheck_limit burst=50 nodelay;

        proxy_pass http://paycheck;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";

        # Timeouts
        proxy_connect_timeout 10s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }

    # Health check endpoint (no rate limit)
    location = /health {
        proxy_pass http://paycheck;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name api.yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

Enable the site:

```bash
sudo ln -s /etc/nginx/sites-available/paycheck /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

## 7. TLS Certificate (Let's Encrypt)

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d api.yourdomain.com
```

## 8. First Boot

On first start, the bootstrap operator is created if `BOOTSTRAP_OPERATOR_EMAIL` is set:

```bash
# Check logs for the API key
sudo journalctl -u paycheck | grep "BOOTSTRAP OPERATOR"
```

**Save the API key immediately** - it's only shown once.

Use this key to:
1. Create additional operators
2. Create organizations for your customers
3. Access the operator API

## 9. Backup Strategy

### Database Backups

SQLite databases should be backed up using `sqlite3` to ensure consistency:

```bash
#!/bin/bash
# /etc/paycheck/backup.sh

BACKUP_DIR=/var/backups/paycheck
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup main database
sqlite3 /var/lib/paycheck/paycheck.db ".backup '$BACKUP_DIR/paycheck_$DATE.db'"

# Backup audit database
sqlite3 /var/lib/paycheck/paycheck_audit.db ".backup '$BACKUP_DIR/audit_$DATE.db'"

# Compress
gzip $BACKUP_DIR/paycheck_$DATE.db
gzip $BACKUP_DIR/audit_$DATE.db

# Remove backups older than 30 days
find $BACKUP_DIR -name "*.db.gz" -mtime +30 -delete

echo "Backup completed: $DATE"
```

Add to cron:

```bash
# Daily backups at 3 AM
0 3 * * * /etc/paycheck/backup.sh >> /var/log/paycheck/backup.log 2>&1
```

### Master Key Backup

The master key is critical - without it, encrypted data is unrecoverable:

1. Create an encrypted backup:
   ```bash
   gpg --symmetric --cipher-algo AES256 /etc/paycheck/master.key
   ```
2. Store the encrypted file offline (USB drive, safety deposit box)
3. Store the GPG passphrase separately from the encrypted file

## 10. Monitoring

### Health Check

```bash
curl https://api.yourdomain.com/health
# Returns: {"status":"ok"}
```

### Systemd Watchdog

Add to the service file for automatic restart on hang:

```ini
[Service]
WatchdogSec=30
```

### External Monitoring

Set up uptime monitoring (UptimeRobot, Pingdom, etc.) to check:
- `GET /health` - returns 200
- Response time < 500ms

### Log Monitoring

Key log patterns to alert on:
- `Failed to` - operation failures
- `panic` - application crashes
- `UNAUTHORIZED` spikes - potential attacks

## 11. Key Rotation

Rotate the master key periodically or after suspected compromise:

```bash
# Generate new key
openssl rand -base64 32 | sudo tee /etc/paycheck/master.key.new > /dev/null
sudo chown paycheck:paycheck /etc/paycheck/master.key.new
sudo chmod 400 /etc/paycheck/master.key.new

# Stop service
sudo systemctl stop paycheck

# Run rotation
sudo -u paycheck /usr/local/bin/paycheck --rotate-key \
  --old-key-file /etc/paycheck/master.key \
  --new-key-file /etc/paycheck/master.key.new

# Replace old key
sudo mv /etc/paycheck/master.key.new /etc/paycheck/master.key

# Restart service
sudo systemctl start paycheck

# Securely delete old key backup if you made one
```

## 12. Security Checklist

Before going live:

- [ ] Master key file has `0400` permissions
- [ ] Master key is backed up securely (encrypted, offline)
- [ ] TLS certificate is valid and auto-renews
- [ ] `PAYCHECK_CONSOLE_ORIGINS` is set to your admin UI domain(s)
- [ ] Firewall allows only 80/443 from internet
- [ ] Port 4242 is not exposed to internet
- [ ] Database files are in a directory with restricted permissions
- [ ] Log rotation is configured
- [ ] Backup script is running and tested
- [ ] Monitoring alerts are configured
- [ ] Bootstrap operator API key is saved securely
- [ ] `PAYCHECK_ENV` is NOT set to `dev`

## 13. Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PAYCHECK_MASTER_KEY_FILE` | Yes | - | Path to master encryption key |
| `BASE_URL` | Yes | - | Public URL of the API |
| `HOST` | No | `127.0.0.1` | Listen address |
| `PORT` | No | `4242` | Listen port |
| `DATABASE_PATH` | No | `paycheck.db` | Main database path |
| `AUDIT_DATABASE_PATH` | No | `paycheck_audit.db` | Audit database path |
| `BOOTSTRAP_OPERATOR_EMAIL` | No | - | Create first operator on empty DB |
| `PAYCHECK_CONSOLE_ORIGINS` | Yes | - | Comma-separated admin UI origins |
| `PAYCHECK_RESEND_API_KEY` | No | - | System Resend API key |
| `PAYCHECK_DEFAULT_FROM_EMAIL` | No | - | Default from address |
| `PAYCHECK_SUCCESS_PAGE_URL` | No | `{BASE_URL}/success` | Post-payment redirect |
| `AUDIT_LOG_ENABLED` | No | `true` | Enable audit logging |
| `PUBLIC_AUDIT_LOG_RETENTION_DAYS` | No | `0` | Days to keep public (end-user) audit logs (0 = never purge) |
| `RATE_LIMIT_STRICT_RPM` | No | `10` | Strict tier rate limit |
| `RATE_LIMIT_STANDARD_RPM` | No | `30` | Standard tier rate limit |
| `RATE_LIMIT_RELAXED_RPM` | No | `60` | Relaxed tier rate limit |
| `RATE_LIMIT_ORG_OPS_RPM` | No | `3000` | Org API rate limit |
| `RUST_LOG` | No | `paycheck=debug` | Log level filter |

## 14. Troubleshooting

### Server won't start

```bash
# Check logs
sudo journalctl -u paycheck -n 50

# Common issues:
# - Master key file permissions not 0400
# - Master key file not found
# - Database path not writable
# - Port already in use
```

### Database locked errors

SQLite can only handle one writer at a time. If you see "database is locked":

1. Check for multiple Paycheck instances
2. Check for backup scripts holding locks
3. Consider using WAL mode (already enabled by default)

### Memory usage growing

The activation rate limiter stores entries in memory. If memory grows:

1. Check rate limit settings aren't too generous
2. The cleanup task runs every 5 minutes automatically

### Webhook failures

If payment webhooks aren't working:

1. Verify the webhook URL is accessible from the internet
2. Check the webhook secret matches in org config
3. Review nginx logs for blocked requests
4. Ensure TLS certificate is valid

## 15. Scaling Considerations

Paycheck uses SQLite, which is excellent for indie scale (thousands of orgs, millions of licenses). If you outgrow it:

1. **Vertical scaling**: SQLite handles large databases well. A single server can handle significant load.

2. **Read replicas**: Use Litestream for real-time SQLite replication to read replicas.

3. **Multiple instances**: Run multiple Paycheck instances behind a load balancer, each with its own SQLite database. Use consistent hashing to route requests.

4. **PostgreSQL migration**: For massive scale, the codebase can be adapted to PostgreSQL.

For most indie developers, a single $20/month VPS will handle everything for years.
