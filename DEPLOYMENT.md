# Authy OIDC Server - Deployment & Security Guide

## Table of Contents

1. [Security Improvements Overview](#security-improvements-overview)
2. [Environment Setup](#environment-setup)
3. [Production Deployment](#production-deployment)
4. [Security Checklist](#security-checklist)
5. [Monitoring & Maintenance](#monitoring--maintenance)
6. [Troubleshooting](#troubleshooting)

## Security Improvements Overview

### Critical Security Enhancements Implemented

1. **Secret Management**
   - Environment-based configuration using `python-decouple`
   - No hardcoded secrets in codebase
   - Separate `.env.example` for documentation

2. **Enhanced OAuth2 Validator**
   - Rate limiting per client
   - Token blacklisting
   - Refresh token rotation
   - Authorization code replay protection
   - Comprehensive audit logging

3. **Security Middleware Suite**
   - Rate limiting middleware
   - Security headers (CSP, HSTS, etc.)
   - Audit logging for sensitive operations
   - IP whitelisting for admin access
   - Request size limiting
   - Session security enhancements

4. **Improved Settings Configuration**
   - Environment-specific settings
   - Production-ready security defaults
   - Comprehensive logging setup
   - Cache configuration with Redis support
   - Email configuration for notifications

## Environment Setup

### 1. Generate Secure Keys

```bash
# Generate Django Secret Key
python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'

# Generate RSA Key Pair for OIDC
openssl genrsa -out oidc_private.pem 4096
openssl rsa -in oidc_private.pem -pubout -out oidc_public.pem

# Generate secure client secrets
python -c 'import secrets; print(secrets.token_urlsafe(64))'
```

### 2. Create Production .env File

```bash
cp .env.example .env
# Edit .env with your production values
```

### 3. Database Setup

For production, use PostgreSQL:

```bash
# Install PostgreSQL
sudo apt-get install postgresql postgresql-contrib

# Create database and user
sudo -u postgres psql
CREATE DATABASE authy_oidc_db;
CREATE USER authy_user WITH ENCRYPTED PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE authy_oidc_db TO authy_user;
```

### 4. Redis Setup (for caching and sessions)

```bash
# Install Redis
sudo apt-get install redis-server

# Configure Redis for production
sudo nano /etc/redis/redis.conf
# Set: requirepass your_redis_password
# Set: maxmemory 256mb
# Set: maxmemory-policy allkeys-lru

sudo systemctl restart redis
```

## Production Deployment

### Using Docker

```bash
# Build production image
docker build -f Dockerfile.prod -t authy-oidc:latest .

# Run with docker-compose
docker-compose -f docker-compose.prod.yml up -d
```

### Using Gunicorn + Nginx

#### 1. Install Dependencies

```bash
pip install gunicorn psycopg2-binary redis django-redis
```

#### 2. Gunicorn Configuration

Create `gunicorn_config.py`:

```python
bind = "127.0.0.1:8000"
workers = 4
worker_class = "sync"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50
preload_app = True
accesslog = "/var/log/gunicorn/access.log"
errorlog = "/var/log/gunicorn/error.log"
loglevel = "info"
```

#### 3. Systemd Service

Create `/etc/systemd/system/authy-oidc.service`:

```ini
[Unit]
Description=Authy OIDC Server
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/authy-oidc
Environment="PATH=/opt/authy-oidc/venv/bin"
ExecStart=/opt/authy-oidc/venv/bin/gunicorn config.wsgi:application -c gunicorn_config.py

[Install]
WantedBy=multi-user.target
```

#### 4. Nginx Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name auth.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/auth.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.yourdomain.com/privkey.pem;

    # SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    location /static/ {
        alias /opt/authy-oidc/staticfiles/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=auth:10m rate=10r/s;
    limit_req zone=auth burst=20 nodelay;
}

server {
    listen 80;
    server_name auth.yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

## Security Checklist

### Pre-Deployment

- [ ] All secrets moved to environment variables
- [ ] DEBUG = False in production
- [ ] ALLOWED_HOSTS configured correctly
- [ ] Database using strong passwords
- [ ] Redis configured with authentication
- [ ] SSL certificates installed
- [ ] Firewall rules configured
- [ ] Admin IP whitelist configured
- [ ] Rate limiting tested
- [ ] Logging configured and tested

### Post-Deployment

- [ ] Security headers verified (use securityheaders.com)
- [ ] SSL configuration tested (use ssllabs.com)
- [ ] OAuth2 flows tested
- [ ] Token rotation working
- [ ] Rate limiting effective
- [ ] Monitoring alerts configured
- [ ] Backup strategy implemented
- [ ] Incident response plan documented

## Monitoring & Maintenance

### 1. Setup Monitoring

#### Prometheus + Grafana

```python
# Add to settings.py
if not DEBUG:
    INSTALLED_APPS += ['django_prometheus']
    MIDDLEWARE.insert(0, 'django_prometheus.middleware.PrometheusBeforeMiddleware')
    MIDDLEWARE.append('django_prometheus.middleware.PrometheusAfterMiddleware')
```

#### Sentry for Error Tracking

```python
# Already configured in settings_improved.py
# Just set SENTRY_DSN in .env
```

### 2. Log Aggregation

Use ELK Stack or similar:

```yaml
# filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/authy-oidc/*.log
  fields:
    service: authy-oidc

output.elasticsearch:
  hosts: ["localhost:9200"]
```

### 3. Database Maintenance

```bash
# Regular backups
pg_dump authy_oidc_db > backup_$(date +%Y%m%d).sql

# Vacuum and analyze
psql -U authy_user -d authy_oidc_db -c "VACUUM ANALYZE;"
```

### 4. Security Updates

```bash
# Check for security updates
pip list --outdated
safety check

# Update dependencies
pip install --upgrade -r requirements/base.txt
```

## Troubleshooting

### Common Issues

1. **Rate Limiting Too Aggressive**
   - Adjust limits in `middleware.py`
   - Check Redis memory usage

2. **Token Validation Failures**
   - Check RSA key configuration
   - Verify clock synchronization (NTP)

3. **Session Issues**
   - Verify Redis connection
   - Check session timeout settings

4. **CORS Errors**
   - Update CORS_ALLOWED_ORIGINS in settings
   - Verify preflight requests handling

### Debug Commands

```bash
# Test database connection
python manage.py dbshell

# Test Redis connection
redis-cli ping

# Check Django configuration
python manage.py check --deploy

# View recent logs
tail -f /var/log/gunicorn/error.log
tail -f /var/log/nginx/error.log
```

## Performance Optimization

### 1. Database Optimization

```python
# Add connection pooling
DATABASES['default']['CONN_MAX_AGE'] = 600
DATABASES['default']['OPTIONS'] = {
    'connect_timeout': 10,
    'options': '-c statement_timeout=30000'
}
```

### 2. Caching Strategy

```python
# Cache user permissions
from django.core.cache import cache

def get_user_permissions(user_id):
    cache_key = f'user_perms:{user_id}'
    perms = cache.get(cache_key)
    if not perms:
        perms = calculate_permissions(user_id)
        cache.set(cache_key, perms, timeout=300)
    return perms
```

### 3. Query Optimization

```python
# Use select_related and prefetch_related
entities = Entity.objects.select_related('parent').prefetch_related('child_entities')
```

## Additional Security Recommendations

1. **Implement 2FA/MFA**
   - Use django-otp or similar
   - Support TOTP/SMS/WebAuthn

2. **Add Intrusion Detection**
   - Implement fail2ban
   - Monitor for suspicious patterns

3. **Regular Security Audits**
   - Penetration testing
   - Code reviews
   - Dependency scanning

4. **Compliance**
   - GDPR compliance for EU users
   - Data retention policies
   - Privacy policy implementation

## Support & Contact

For security issues, please email: security@yourdomain.com
For general support: support@yourdomain.com

## License

[Your License Here]
