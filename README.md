# Document Converter API — Development & Production Deployment Guide

FastAPI conversion service (PDF / Word / Excel / PPTX / HEIC / images / OCR) plus a Go JWT auth service,
deployed on a **Hostinger VPS (Ubuntu 24.04)** behind **Nginx + HTTPS**, running in **hardened Docker containers**.

> **Assumptions** (adjust to your real project): FastAPI entry point is `app.main:app`, the Go auth service
> listens on `:8080`, and it uses PostgreSQL. Check `Procfile`, `go-auth/config/database.go` and `example_env`
> for the real commands and variable names. Replace `example.com` with your domain everywhere.

---

## Table of Contents

1. [Architecture](#1-architecture)
2. [Local development](#2-local-development)
3. [Fix these in the code BEFORE going public](#3-fix-these-in-the-code-before-going-public)
4. [Hostinger VPS: first-time setup](#4-hostinger-vps-first-time-setup)
5. [Server hardening (SSH, firewall, fail2ban, updates)](#5-server-hardening)
6. [Install Docker](#6-install-docker)
7. [Deploy the application](#7-deploy-the-application)
8. [Nginx + free HTTPS certificate](#8-nginx--free-https-certificate)
9. [Application-level security](#9-application-level-security)
10. [Cleanup, backups, logs, monitoring](#10-cleanup-backups-logs-monitoring)
11. [Monitoring, logging, auditing & alerting](#11-monitoring-logging-auditing--alerting)
12. [Update / rollback workflow](#12-update--rollback-workflow)
13. [Verification & troubleshooting](#13-verification--troubleshooting)
14. [Final security checklist](#14-final-security-checklist)
15. [If you think you were hacked](#15-if-you-think-you-were-hacked)

---

## 1. Architecture

```
Internet
   │  :80 / :443 only
   ▼
┌─────────────────────────┐
│ UFW + Hostinger firewall│  (everything else blocked)
└───────────┬─────────────┘
            ▼
┌─────────────────────────┐
│ Nginx (host)            │  TLS, rate limits, upload size limit, headers
└───────┬───────────┬─────┘
        │           │
 127.0.0.1:8000  127.0.0.1:8080       ← bound to loopback, NOT public
        ▼           ▼
 ┌────────────┐ ┌────────────┐   ┌──────────────┐
 │ FastAPI    │ │ Go auth    │──▶│ PostgreSQL   │  (no published port)
 │ container  │ │ container  │   │ container    │
 └─────┬──────┘ └────────────┘   └──────────────┘
       ▼
  ./data/uploads  ./data/converted_files  ./data/outputs   (volumes)
```

Why this layout:

- Only Nginx is exposed. App and DB ports are never reachable from the internet.
- The converter processes **untrusted files** (LibreOffice, Ghostscript, Tesseract, Pillow). Running them in a
  container with dropped privileges limits the damage if one of those tools has a vulnerability.

**Server size:** LibreOffice + OCR + background removal (`rembg`) are memory-hungry. Use at least
**2 vCPU / 4 GB RAM** (8 GB is comfortable) and add 2 GB swap (section 4).

---

## 2. Local development

### Prerequisites
Python 3.11+, Go 1.22+ (for `go-auth`), Git, and system tools:

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y libreoffice ghostscript tesseract-ocr poppler-utils libheif-dev fonts-dejavu fonts-liberation
# macOS: brew install libreoffice ghostscript tesseract poppler libheif
```
(Your `apt.txt` already lists the system packages the app needs. That is the source of truth.)

### Run the FastAPI app

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# background removal (separate pins):
pip install -r requirements-rembg.txt -c constraints-rembg.txt

cp example_env .env          # then edit values
python run.py                # or: uvicorn app.main:app --reload --port 8000
```

- Interactive docs (dev only): http://localhost:8000/docs
- Quick manual tests: `api.http` (VS Code REST Client) or `frontend/test_new_api.html`
- Frontend: set the API base URL in `frontend/js/config.js`

### Run the Go auth service

```bash
cd go-auth
cp example_env .env          # DB credentials, JWT secret, SMTP settings
go run .
# tests: go-auth/tests/auth_test.http
```

### `.gitignore` (add/verify — your tree shows user data inside the repo)

```gitignore
.env
*.env
!example_env
go-auth/.env
.venv/
__pycache__/
*.pyc
uploads/
converted_files/
outputs/
data/
*.log
```

Remove already-committed user files and make sure no secret was ever committed:

```bash
git rm -r --cached uploads converted_files outputs 2>/dev/null
git commit -m "Stop tracking runtime data"
git log --all --oneline -- .env go-auth/.env     # should print nothing
```
If a secret **was** committed, treat it as leaked and rotate it (new JWT secret, DB password, SMTP password).

### `.dockerignore`

```
.git
.venv
__pycache__
uploads
converted_files
outputs
data
.env
*.md
FULL_PROJECT_DOCUMENTATION.txt
openapi.json
frontend/test_new_api.html
```

---

## 3. Fix these in the code BEFORE going public

These are the highest-risk spots for a file-conversion service. Do them first. They matter more than any server setting.

### 3.1 Disable API docs, restrict hosts and CORS in production (`app/main.py`)

```python
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

IS_PROD = os.getenv("APP_ENV") == "production"

app = FastAPI(
    docs_url=None if IS_PROD else "/docs",
    redoc_url=None if IS_PROD else "/redoc",
    openapi_url=None if IS_PROD else "/openapi.json",
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["example.com", "www.example.com", "localhost", "127.0.0.1"],
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o],  # never "*" with credentials
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok"}
```

### 3.2 SSRF protection (CRITICAL for `url_to_pdf.py`, `html_to_pdf.py`, `http_download.py`)

Any feature that fetches a user-supplied URL can be abused to reach your server's internal services.
Validate **every** URL (and every redirect target) before fetching:

```python
import ipaddress, socket
from urllib.parse import urlparse

def assert_public_url(url: str) -> None:
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Invalid URL")
    port = p.port or (443 if p.scheme == "https" else 80)
    for info in socket.getaddrinfo(p.hostname, port):
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:          # blocks 127.x, 10.x, 172.16.x, 192.168.x, 169.254.x, ::1 ...
            raise ValueError("URL not allowed")
```

Also: set connect/read timeouts, cap download size (e.g. 20 MB), limit redirects and re-validate each hop, and
if you render pages with a headless browser, treat the rendered page as hostile (no file:// access, no
credentials, strict timeout).

### 3.3 Authenticate and authorize every endpoint

- The Go service issues JWTs. **FastAPI must verify them** (signature, expiry) with a dependency on every
  conversion/editor/download route. Don't trust a user ID sent in the request body.
- `JWT_SECRET` must be random, at least 32 bytes, identical in both services, and only in `.env`.
- Download/preview routes must check that the file/job belongs to the caller. Job IDs should be random (uuid4),
  never sequential.
- Never expose directory listings (`StaticFiles` over `uploads/`, `converted_files/` or `outputs/` is a data leak).

### 3.4 Validate uploads (you already have `file_type.py` and `image_validation.py`)

- Enforce a max size and allowed extensions **and** check magic bytes, not just the extension.
- Save to disk under a **server-generated name** (`uuid4().hex + ext`). Never use the client filename in a path.
- Limit pixel count and page count to stop decompression bombs:

```python
from PIL import Image
Image.MAX_IMAGE_PIXELS = 100_000_000   # raises DecompressionBombError above this
```
- Cap PDF page counts and spreadsheet sizes before processing.

### 3.5 Run external tools safely and with limits

```python
import subprocess, uuid, shutil, tempfile

profile = f"/tmp/lo_{uuid.uuid4().hex}"           # separate LibreOffice profile per job
try:
    subprocess.run(
        ["soffice", f"-env:UserInstallation=file://{profile}",
         "--headless", "--convert-to", "pdf", "--outdir", out_dir, in_path],
        timeout=120, check=True, capture_output=True,
    )
finally:
    shutil.rmtree(profile, ignore_errors=True)
```

- Always pass arguments as a **list**, never `shell=True` with user data.
- Always set `timeout=`.
- Limit simultaneous conversions (e.g. `asyncio.Semaphore(2)` or a job queue via `worker.py`) so a few big
  uploads can't exhaust RAM.

### 3.6 Contact form (`services/contact_email.py`)

Rate-limit it, validate the email format, strip newlines from header fields (email header injection), and
consider a CAPTCHA, because open contact forms get used to spam.

### 3.7 Dependencies

```bash
pip install pip-audit && pip-audit -r requirements.txt
cd go-auth && go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...
```
Pin versions in `requirements.txt` and re-run these monthly.

---

## 4. Hostinger VPS: first-time setup

1. In hPanel → **VPS → Operating System**, choose **Ubuntu 24.04** (a plain one or the Docker template, both work).
2. Point DNS: create **A** records for `example.com` and `www` to the VPS IPv4 address (hPanel → Domains → DNS).
3. Log in as root once (hPanel browser terminal or `ssh root@SERVER_IP`) and update everything:

```bash
apt update && apt full-upgrade -y && apt autoremove -y
timedatectl set-timezone UTC
```

4. Create a normal admin user (replace `deploy`):

```bash
adduser deploy
usermod -aG sudo deploy
```

5. Add swap (2 GB) so conversions don't get OOM-killed:

```bash
fallocate -l 2G /swapfile && chmod 600 /swapfile
mkswap /swapfile && swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab
sysctl vm.swappiness=10 && echo 'vm.swappiness=10' > /etc/sysctl.d/99-swap.conf
```

6. **Enable Hostinger backups/snapshots** in hPanel and take a snapshot now (before hardening), so you can roll back.

---

## 5. Server hardening

### 5.1 SSH keys only, no root login

**On your own computer** (skip if you already have a key):

```bash
ssh-keygen -t ed25519 -C "you@example.com"
ssh-copy-id deploy@SERVER_IP
```

**Open a NEW terminal and confirm `ssh deploy@SERVER_IP` works with the key** before you continue, and keep the
old session open while you do the next part (otherwise you can lock yourself out).

On the server:

```bash
sudo tee /etc/ssh/sshd_config.d/00-hardening.conf >/dev/null <<'EOF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 20
X11Forwarding no
AllowUsers deploy
EOF
sudo sshd -t && sudo systemctl restart ssh
sudo sshd -T | grep -E 'passwordauthentication|permitrootlogin'   # must show "no"
```
The file is named `00-` on purpose: sshd uses the **first** value it reads, and the cloud-init file
`50-cloud-init.conf` may otherwise re-enable passwords.

If you lock yourself out, use the Hostinger **browser terminal** (hPanel → VPS → Browser terminal) to fix it.

### 5.2 Firewall (UFW) and Hostinger firewall

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw limit OpenSSH          # allows SSH but rate-limits brute force
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
sudo ufw status verbose
```

Also in **hPanel → VPS → Security → Firewall**, create a rule set: allow TCP 22, 80, 443 and drop the rest,
and attach it to your VPS. Restrict port 22 to your own IP if it's static.

> **Docker bypasses UFW** for any port it *publishes*. That's why every published port in this guide is bound
> to `127.0.0.1:` (never `"8000:8000"`).

### 5.3 fail2ban (bans IPs that brute-force)

```bash
sudo apt install -y fail2ban
sudo tee /etc/fail2ban/jail.local >/dev/null <<'EOF'
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
backend = systemd

[recidive]
enabled  = true
bantime  = 1w
findtime = 1d
maxretry = 3
EOF
sudo systemctl enable --now fail2ban
sudo fail2ban-client status sshd
```

### 5.4 Automatic security updates

```bash
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades     # choose "Yes"
```

### 5.5 Small extras

```bash
# Kernel network hardening
sudo tee /etc/sysctl.d/99-hardening.conf >/dev/null <<'EOF'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
EOF
sudo sysctl --system

# Intrusion/rootkit checks (optional but cheap)
sudo apt install -y auditd rkhunter
```

---

## 6. Install Docker

```bash
sudo apt install -y ca-certificates curl git
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Rotate container logs so the disk never fills up
sudo tee /etc/docker/daemon.json >/dev/null <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "5" },
  "no-new-privileges": true
}
EOF
sudo systemctl restart docker
```

(Adding your user to the `docker` group is convenient, but it is effectively root access. Only do it for `deploy`.)

```bash
sudo usermod -aG docker deploy   # log out and back in afterwards
```

---

## 7. Deploy the application

### 7.1 Get the code

```bash
sudo mkdir -p /opt/converter && sudo chown deploy:deploy /opt/converter
cd /opt/converter
git clone git@github.com:YOUR_USER/YOUR_REPO.git .    # use a read-only deploy key for private repos
mkdir -p data/uploads data/converted_files data/outputs data/models data/pgdata data/logs
sudo chown -R 1000:1000 data/uploads data/converted_files data/outputs data/models data/logs   # container user UID
```

### 7.2 Secrets (`.env`)

Use the variable names from your own `example_env`. These are typical values:

```bash
cp example_env .env
cp go-auth/example_env go-auth/.env
chmod 600 .env go-auth/.env

openssl rand -hex 32        # run for JWT_SECRET
openssl rand -base64 24     # run for DB password
```

`.env` (root):

```env
APP_ENV=production
DEBUG=false
ALLOWED_ORIGINS=https://example.com,https://www.example.com
JWT_SECRET=<generated 64 hex chars>
MAX_UPLOAD_MB=50

POSTGRES_USER=converter
POSTGRES_PASSWORD=<generated>
POSTGRES_DB=converter_auth
```

`go-auth/.env` (same `JWT_SECRET`, DB host is the compose service name `db`):

```env
APP_ENV=production
PORT=8080
JWT_SECRET=<same value as above>
DB_HOST=db
DB_PORT=5432
DB_USER=converter
DB_PASSWORD=<same as POSTGRES_PASSWORD>
DB_NAME=converter_auth
# SMTP settings for go-auth/services/email.go
```

Never commit these files. If your Go code falls back to a default JWT secret when the variable is missing, remove that fallback so the app refuses to start instead.

### 7.3 `Dockerfile` for FastAPI

Adapt your existing Dockerfile or use this:

```dockerfile
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/home/app

WORKDIR /app

# System tools: LibreOffice, Ghostscript, Tesseract, Poppler, HEIF, fonts ...
COPY apt.txt .
RUN apt-get update \
 && xargs -a apt.txt apt-get install -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements-rembg.txt constraints-rembg.txt ./
RUN pip install --no-cache-dir -r requirements.txt gunicorn \
 && pip install --no-cache-dir -r requirements-rembg.txt -c constraints-rembg.txt

# Non-root user
RUN useradd -u 1000 -m -d /home/app app \
 && mkdir -p /app/uploads /app/converted_files /app/outputs /app/logs \
 && chown -R app:app /app /home/app
COPY --chown=app:app app ./app
COPY --chown=app:app frontend ./frontend
COPY --chown=app:app run.py ./run.py

USER app
EXPOSE 8000

CMD ["gunicorn", "app.main:app", "-k", "uvicorn.workers.UvicornWorker", \
     "-w", "2", "-b", "0.0.0.0:8000", "--timeout", "300", \
     "--forwarded-allow-ips", "*"]
```

Notes: `apt.txt` must contain only package names, one per line (remove comment lines). `--forwarded-allow-ips "*"`
is safe here only because the port is published on loopback and reached only through Nginx. Check your
`Procfile`: if it defines a separate worker process (`app/worker.py`), add a second `worker` service in compose
using the same image and that command.

### 7.4 `go-auth/Dockerfile`

```dockerfile
FROM golang:1.22-alpine AS build          # match the version in go-auth/go.mod
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /auth .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /auth /auth
EXPOSE 8080
ENTRYPOINT ["/auth"]
```

### 7.5 `docker-compose.yml` (project root)

```yaml
services:
  api:
    build: .
    container_name: converter-api
    restart: unless-stopped
    env_file: .env
    ports:
      - "127.0.0.1:8000:8000"        # loopback only!
    volumes:
      - ./data/uploads:/app/uploads
      - ./data/converted_files:/app/converted_files
      - ./data/outputs:/app/outputs
      - ./data/models:/home/app/.u2net   # rembg model cache
      - ./data/logs:/app/logs            # audit / activity logs (section 11)
    tmpfs:
      - /tmp:size=1g
    security_opt:
      - no-new-privileges:true
    cap_drop: [ALL]
    pids_limit: 512
    mem_limit: 3g
    cpus: 2
    # Enable after the first successful deploy (extra hardening):
    # read_only: true
    # tmpfs: [ "/tmp:size=1g", "/home/app/.config", "/home/app/.cache" ]
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health')"]
      interval: 30s
      timeout: 5s
      retries: 3
    depends_on:
      - auth

  auth:
    build: ./go-auth
    container_name: converter-auth
    restart: unless-stopped
    env_file: ./go-auth/.env
    ports:
      - "127.0.0.1:8080:8080"
    security_opt:
      - no-new-privileges:true
    cap_drop: [ALL]
    read_only: true
    mem_limit: 256m
    depends_on:
      db:
        condition: service_healthy

  db:
    image: postgres:16-alpine
    container_name: converter-db
    restart: unless-stopped
    env_file: .env
    volumes:
      - ./data/pgdata:/var/lib/postgresql/data
    # no "ports:" — the database is reachable only from other containers
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $${POSTGRES_USER} -d $${POSTGRES_DB}"]
      interval: 10s
      timeout: 5s
      retries: 5
```

If your auth service uses another database, replace the `db` service accordingly. Add a `worker:` service if your Procfile has one.

### 7.6 Start it

```bash
docker compose build
docker compose up -d
docker compose ps
docker compose logs -f api         # Ctrl+C to stop following
curl -s http://127.0.0.1:8000/health
```

Confirm only loopback is published: `docker ps --format '{{.Names}} {{.Ports}}'` must show `127.0.0.1:8000->8000`
(never `0.0.0.0:`).

---

## 8. Nginx + free HTTPS certificate

```bash
sudo apt install -y nginx certbot python3-certbot-nginx
```

### 8.1 Global settings

`/etc/nginx/conf.d/00-global.conf`:

```nginx
server_tokens off;

# Rate-limit zones (per client IP)
limit_req_zone  $binary_remote_addr zone=api:10m    rate=10r/s;
limit_req_zone  $binary_remote_addr zone=upload:10m rate=30r/m;
limit_req_zone  $binary_remote_addr zone=auth:10m   rate=5r/m;
limit_conn_zone $binary_remote_addr zone=perip:10m;
limit_req_status 429;

# JSON access log (used in section 11). $uri, not $request_uri, so query strings/tokens are not logged
log_format json_combined escape=json
  '{"time":"$time_iso8601","ip":"$remote_addr","method":"$request_method","uri":"$uri",'
  '"status":$status,"bytes":$body_bytes_sent,"rt":$request_time,"req_id":"$request_id",'
  '"host":"$host","ua":"$http_user_agent"}';
```

`/etc/nginx/snippets/security-headers.conf`:

```nginx
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
add_header X-Content-Type-Options    "nosniff" always;
add_header X-Frame-Options           "DENY" always;
add_header Referrer-Policy           "strict-origin-when-cross-origin" always;
add_header Permissions-Policy        "camera=(), microphone=(), geolocation=()" always;
# Add a Content-Security-Policy once you've tested it against your frontend.
```

### 8.2 Get the certificate

Create a minimal site first so certbot can validate the domain:

```bash
sudo tee /etc/nginx/sites-available/converter >/dev/null <<'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name example.com www.example.com;
    root /var/www/html;
}
EOF
sudo ln -sf /etc/nginx/sites-available/converter /etc/nginx/sites-enabled/converter
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx

sudo certbot certonly --nginx -d example.com -d www.example.com --agree-tos -m you@example.com
sudo systemctl status certbot.timer     # auto-renewal; test: sudo certbot renew --dry-run
```

### 8.3 Final site config

`/etc/nginx/sites-available/converter`:

```nginx
# HTTP → HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name example.com www.example.com;
    return 301 https://example.com$request_uri;
}

# www → apex
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name www.example.com;
    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    return 301 https://example.com$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name example.com;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    include snippets/security-headers.conf;

    # Max upload size — keep equal to MAX_UPLOAD_MB in .env
    client_max_body_size 50m;
    client_body_timeout  60s;
    client_header_timeout 15s;
    keepalive_timeout    30s;
    limit_conn perip 20;

    # Block hidden files and common scanner targets
    location ~ /\.            { deny all; return 404; }
    location ~* \.(env|git|sql|bak|ini|log|yml|yaml)$ { deny all; return 404; }

    # Readiness details are for the server's own health script only
    location = /ready { return 404; }

    # Go auth service — strict rate limit against password guessing.
    # Match the prefix to the routes in go-auth/routes/routes.go.
    location /auth/ {
        limit_req zone=auth burst=5 nodelay;
        proxy_pass http://127.0.0.1:8080/;
        include snippets/proxy-common.conf;
    }

    # Conversion/upload endpoints
    location ~ ^/api/.*(convert|upload|editor) {
        limit_req zone=upload burst=10 nodelay;
        proxy_pass http://127.0.0.1:8000;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        include snippets/proxy-common.conf;
    }

    # Everything else (FastAPI + frontend)
    location / {
        limit_req zone=api burst=30 nodelay;
        proxy_pass http://127.0.0.1:8000;
        proxy_read_timeout 120s;
        include snippets/proxy-common.conf;
    }
}
```

`/etc/nginx/snippets/proxy-common.conf`:

```nginx
proxy_http_version 1.1;
proxy_set_header Host              $host;
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header X-Forwarded-For   $remote_addr;   # overwrite, don't trust client-supplied values
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header Connection        "";
proxy_set_header X-Request-ID      $request_id;
```

```bash
sudo nginx -t && sudo systemctl reload nginx
```

Adjust the `location` regexes to your real route prefixes (see `app/api/routes.py` and `app/api/routers/`).
Frontend API URL in `frontend/js/config.js` should be `https://example.com`.

---

## 9. Application-level security

Summary of what protects you at each layer:

| Layer | Protection |
|---|---|
| Network | Hostinger firewall + UFW (22/80/443 only), fail2ban, loopback-only app ports |
| TLS | Let's Encrypt, TLS 1.2+, HSTS, auto-renewal |
| Nginx | Rate limits (general / upload / auth), body-size limit, timeouts, hidden-file blocking, headers |
| Containers | Non-root user, all capabilities dropped, `no-new-privileges`, memory/CPU/PID limits, DB not published |
| App | JWT verification everywhere, CORS allow-list, docs disabled, TrustedHost, upload validation, SSRF guard, tool timeouts |
| Data | Random filenames, auto-delete of old files, `.env` mode 600, backups |
| Monitoring | JSON audit logs, login / unauthorized-access tracking, SSH-login alerts, fail2ban, health checks, daily report (section 11) |

Extra recommendations:

- **Egress filtering** (advanced): since the app fetches URLs, block the containers from reaching the host's
  private network, e.g. `sudo iptables -I DOCKER-USER -d 10.0.0.0/8 -j DROP` (repeat for `172.16.0.0/12`,
  `192.168.0.0/16`, `169.254.0.0/16`). Do this in addition to the SSRF code check. Persist rules with `iptables-persistent`.
- **Cloudflare (free plan)** in front of the domain adds DDoS protection and bot filtering. If you enable the
  proxy, restrict ports 80/443 on the VPS to Cloudflare's IP ranges and use their real-IP header.
- **Password rules / login lockout** in `go-auth/handlers/auth.go`: hash with bcrypt/argon2, add a delay or
  lockout after repeated failures, short-lived access tokens (15–60 min), verify email before activation.
- **Do not log** tokens, passwords or full file contents.

---

## 10. Cleanup, backups, logs, monitoring

### 10.1 Delete old user files automatically

Converted files contain user data. Don't keep them forever. (Use this **or** `app/cleanup_old_files.py`, not both.)

```bash
sudo tee /etc/cron.d/converter-cleanup >/dev/null <<'EOF'
# every 15 min: delete files older than 60 min
*/15 * * * * root find /opt/converter/data/uploads /opt/converter/data/converted_files /opt/converter/data/outputs -type f -mmin +60 -delete
*/30 * * * * root find /opt/converter/data/outputs -type d -empty -mmin +120 -delete
EOF
```

### 10.2 Database backup (daily, keep 7 days)

```bash
sudo mkdir -p /opt/backups && sudo chown deploy:deploy /opt/backups
cat > /opt/converter/backup.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cd /opt/converter
STAMP=$(date +%F_%H%M)
docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' | gzip > /opt/backups/db_$STAMP.sql.gz
find /opt/backups -name 'db_*.sql.gz' -mtime +7 -delete
EOF
chmod 700 /opt/converter/backup.sh
( crontab -l 2>/dev/null; echo "30 3 * * * /opt/converter/backup.sh" ) | crontab -
```

Copy backups **off the server** too (Hostinger snapshots, `rclone` to S3/Backblaze, or `rsync` to another machine).
A backup stored only on the same VPS is lost along with the VPS. Restore test:
`gunzip -c db_XXXX.sql.gz | docker compose exec -T db psql -U converter converter_auth`.

### 10.3 Quick log commands

(The full monitoring, alerting and audit setup is in [section 11](#11-monitoring-logging-auditing--alerting).)

```bash
docker compose logs --tail=100 -f api auth     # app logs
sudo tail -f /var/log/nginx/access.log /var/log/nginx/error.log
sudo fail2ban-client status sshd               # banned IPs
sudo journalctl -u ssh --since today | grep -i failed
docker stats                                   # CPU/RAM per container
df -h && free -h                               # disk and memory
```

Set up a free external uptime monitor (UptimeRobot / Better Stack) on `https://example.com/health` with email alerts.

---

## 11. Monitoring, Logging, Auditing & Alerting

Goal: you should know **who logged in, who failed to log in, who tried to access something they shouldn't,
what each user did, whether every service is healthy, and be alerted on your phone within a minute**, not
discover it a week later.

### 11.1 What you'll have

| What | Where it is recorded | Alert? |
|---|---|---|
| Every API request, user, IP, status, duration | FastAPI audit log (`data/logs/audit.log`) + Nginx JSON log | 5xx / 401 / 403 spikes |
| Login success / failure, register, password reset | Go auth service logs (JSON) + Nginx log | Brute-force bans |
| Unauthorized access (401/403), bad tokens, forbidden file access | Audit log, Nginx log | Yes (fail2ban + spike check) |
| Uploads, conversions, downloads, deletes, rejected files, SSRF blocks | Audit log | SSRF/rejected: review daily |
| SSH logins (success + failed), `sudo` use | `journalctl`, `auditd`, PAM hook | **Every SSH login** |
| Changes to critical files (`.env`, SSH keys, sudoers, nginx, cron) | `auditd` | Review / `ausearch` |
| Banned IPs | fail2ban | **Every ban** |
| Service health (site, API, auth, DB, nginx, firewall) | `healthcheck.sh` every minute | **Down / recovered** |
| Disk, RAM, TLS certificate expiry | `healthcheck.sh` | Yes |
| Summary of the last 24 h | Daily report | Telegram message |
| Server dead / internet outage | External uptime monitor + heartbeat | Yes |

### 11.2 Alert channel (Telegram, free, 2 minutes)

1. In Telegram open **@BotFather** → `/newbot` → copy the **token**.
2. Send any message to your new bot, then open `https://api.telegram.org/bot<TOKEN>/getUpdates` and copy the
   number in `"chat":{"id": ...}`.

```bash
sudo tee /etc/converter-alerts.env >/dev/null <<'EOF'
TELEGRAM_TOKEN=123456:ABC-your-token
TELEGRAM_CHAT_ID=123456789
# Optional: dead-man's-switch URL from UptimeRobot/Better Stack/healthchecks.io (see 11.8)
HEARTBEAT_URL=
EOF
sudo chmod 600 /etc/converter-alerts.env

sudo tee /usr/local/bin/notify.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
# usage: notify.sh "message"
source /etc/converter-alerts.env
curl -s -m 10 -X POST "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
  -d chat_id="${TELEGRAM_CHAT_ID}" \
  --data-urlencode text="[$(hostname)] $1" >/dev/null || true
EOF
sudo chmod 755 /usr/local/bin/notify.sh
sudo /usr/local/bin/notify.sh "✅ Alert channel works"
```

(For Slack/Discord/email, only the `curl` line changes. Everything below calls `notify.sh`.)
Alerts can't be sent if the whole VPS is down, which is why 11.8 adds an *external* monitor.

### 11.3 Application activity & audit log (FastAPI)

Create `app/security_logging.py`. It writes one JSON object per line to stdout (visible in `docker logs`) and to
a rotating file (`data/logs/audit.log`, 10 MB × 10 files):

```python
import json, logging, os
from logging.handlers import RotatingFileHandler
from fastapi import Request

LOG_DIR = os.getenv("LOG_DIR", "/app/logs")


class JsonFormatter(logging.Formatter):
    def format(self, record):
        data = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "msg": record.getMessage(),          # the event name
        }
        data.update(getattr(record, "fields", {}))
        return json.dumps(data, default=str)


def _build():
    lg = logging.getLogger("audit")
    if lg.handlers:
        return lg
    lg.setLevel(logging.INFO)
    lg.propagate = False
    handlers = [logging.StreamHandler()]
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        handlers.append(RotatingFileHandler(f"{LOG_DIR}/audit.log", maxBytes=10_000_000, backupCount=10))
    except OSError:
        pass                                      # file logging optional (e.g. read-only FS)
    for h in handlers:
        h.setFormatter(JsonFormatter())
        lg.addHandler(h)
    return lg


audit = _build()


def client_ip(request: Request) -> str:
    # Safe: the app port is loopback-only, so only Nginx can set this header.
    return request.headers.get("x-real-ip") or (request.client.host if request.client else "-")


def audit_event(event: str, request: Request | None = None, level: int = logging.INFO, **fields):
    if request is not None:
        fields.setdefault("ip", client_ip(request))
        fields.setdefault("user", getattr(request.state, "user_id", None))
        fields.setdefault("request_id", getattr(request.state, "request_id", None))
    audit.log(level, event, extra={"fields": fields})
```

**Log every request** with a middleware in `app/main.py`. Unauthorized, rate-limited and failing requests
automatically become WARNING/ERROR events:

```python
import logging, time, uuid
from fastapi import Request
from app.security_logging import audit_event

@app.middleware("http")
async def activity_log(request: Request, call_next):
    request.state.request_id = rid = uuid.uuid4().hex[:12]
    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        audit_event("unhandled_exception", request, logging.ERROR,
                    method=request.method, path=request.url.path)
        raise

    if request.url.path not in ("/health", "/ready"):      # don't spam the log with health checks
        status = response.status_code
        event, level = "request", logging.INFO
        if status in (401, 403):  event, level = "unauthorized_access", logging.WARNING
        elif status == 429:       event, level = "rate_limited", logging.WARNING
        elif status >= 500:       event, level = "server_error", logging.ERROR
        audit_event(event, request, level,
                    method=request.method, path=request.url.path,   # path only; never log query strings (tokens)
                    status=status, ms=round((time.perf_counter() - start) * 1000),
                    ua=request.headers.get("user-agent", "")[:120])
    response.headers["X-Request-ID"] = rid
    return response
```

**Record who the user is** in your JWT dependency, and log bad tokens:

```python
def get_current_user(request: Request, token: str = Depends(bearer)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])   # use your real decode logic
    except Exception:
        audit_event("token_invalid", request, logging.WARNING)
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    request.state.user_id = payload["sub"]
    return payload
```

**Add business events** in the routers and converters (use the names below so searching is easy):

```python
audit_event("file_uploaded", request, kind="pdf_to_word", ext=ext, size=size)       # no file names/content
audit_event("upload_rejected", request, logging.WARNING, reason="bad_magic_bytes", ext=ext)
audit_event("conversion_done", request, job_id=job_id, kind="pdf_to_pptx", ms=elapsed_ms)
audit_event("conversion_failed", request, logging.ERROR, job_id=job_id, error=type(e).__name__)
audit_event("file_downloaded", request, job_id=job_id)
audit_event("forbidden_file_access", request, logging.WARNING, job_id=job_id)       # job belongs to someone else
audit_event("ssrf_blocked", request, logging.WARNING, host=host)                    # from assert_public_url()
```

Also add the `/ready` readiness endpoint (detailed dependency check, used by the health script in 11.8):

```python
import os, shutil
from fastapi.responses import JSONResponse

@app.get("/ready", include_in_schema=False)
def ready():
    checks = {
        "soffice":   shutil.which("soffice") is not None,
        "ghostscript": shutil.which("gs") is not None,
        "tesseract": shutil.which("tesseract") is not None,
        "uploads_writable": os.access("/app/uploads", os.W_OK),
        "disk_free_1gb": shutil.disk_usage("/app/uploads").free > 1_000_000_000,
    }
    return JSONResponse(checks, status_code=200 if all(checks.values()) else 503)
```
Nginx returns 404 for `/ready` from outside (section 8.3); only the server itself can call it.

Add a `/health` route to the Go service as well (return 200 after a quick DB ping) so it can be checked too.

### 11.4 Auth service logging (Go): logins and failures

Create `go-auth/utils/audit.go`:

```go
package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"strings"
)

func InitLogger() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
}

// HashID lets you correlate events per user without writing the email into the logs.
func HashID(s string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(s))))
	return hex.EncodeToString(h[:6])
}
```

Call `utils.InitLogger()` at the start of `main()`, then log in `handlers/auth.go`
(`ip` = the `X-Real-IP` header that Nginx sets; with Gin: `c.GetHeader("X-Real-IP")`):

```go
slog.Info("login_success",  "user", utils.HashID(email), "ip", ip)
slog.Warn("login_failed",   "user", utils.HashID(email), "ip", ip, "reason", "bad_password")  // or "unknown_user"
slog.Warn("account_locked", "user", utils.HashID(email), "ip", ip)
slog.Info("register",       "user", utils.HashID(email), "ip", ip)
slog.Info("password_reset_requested", "user", utils.HashID(email), "ip", ip)
slog.Info("password_changed", "user", userID, "ip", ip)
slog.Warn("token_invalid",  "ip", ip, "reason", "expired")      // in middleware/jwt.go
```
**Never log passwords, tokens or reset links.** Use the same message for "wrong password" and "unknown user" in the
HTTP response (no user enumeration), but keep the distinct `reason` in the log.

Read them with `docker compose logs auth | grep login_failed`.

### 11.5 Nginx access logs (JSON + request IDs)

The JSON `log_format` was added in section 8.1 and the request-ID header in `proxy-common.conf`. Enable the logs
in the HTTPS `server {}` block of `/etc/nginx/sites-available/converter` (next to `include snippets/security-headers.conf;`):

```nginx
    access_log /var/log/nginx/converter_access.log;                    # classic format (fail2ban reads this)
    access_log /var/log/nginx/converter_access.json.log json_combined; # JSON (for jq / dashboards)
    error_log  /var/log/nginx/converter_error.log warn;
```
```bash
sudo nginx -t && sudo systemctl reload nginx
```
The same `X-Request-ID` appears in Nginx logs, the app's audit log and the response header, so one request
can be traced end to end. Never put tokens in URLs/query strings, because the classic log records them.

Keep 30 days of Nginx logs:

```bash
sudo sed -i 's/rotate 14/rotate 30/' /etc/logrotate.d/nginx
```

### 11.6 Server logins, sudo and file-change auditing

**Instant alert on every SSH login (and `sudo`)**. You'll see immediately if someone else gets in:

```bash
sudo tee /usr/local/bin/login-alert.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
[ "$PAM_TYPE" = "open_session" ] || exit 0
( /usr/local/bin/notify.sh "🔐 ${PAM_SERVICE} session: user=${PAM_USER} by=${PAM_RUSER:-} from=${PAM_RHOST:-local}" & ) >/dev/null 2>&1
exit 0
EOF
sudo chmod 755 /usr/local/bin/login-alert.sh

# SSH logins
echo 'session optional pam_exec.so quiet /usr/local/bin/login-alert.sh' | sudo tee -a /etc/pam.d/sshd
# sudo usage (optional)
echo 'session optional pam_exec.so quiet /usr/local/bin/login-alert.sh' | sudo tee -a /etc/pam.d/sudo
```
Keep a second SSH session open while testing. Log in from another terminal; you should get a Telegram message.

**auditd**: records changes to the files an attacker would touch:

```bash
sudo tee /etc/audit/rules.d/converter.rules >/dev/null <<'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group  -p wa -k identity
-w /etc/sudoers   -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /home/deploy/.ssh/ -p wa -k ssh_keys
-w /root/.ssh/ -p wa -k ssh_keys
-w /opt/converter/.env -p wa -k app_secrets
-w /opt/converter/go-auth/.env -p wa -k app_secrets
-w /opt/converter/docker-compose.yml -p wa -k app_config
-w /etc/nginx/ -p wa -k nginx_conf
-w /etc/docker/ -p wa -k docker_conf
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k root_commands
EOF
sudo augenrules --load
sudo auditctl -l | head
```

Query it:

```bash
sudo ausearch -k ssh_keys -ts today -i        # who touched SSH keys
sudo ausearch -k root_commands -ts today -i | tail -50   # commands run as root via sudo
sudo aureport --auth --summary                # authentication summary
```

**Login history commands:**

```bash
last -a | head -20                  # successful logins (user, time, IP)
sudo lastb | head -20               # FAILED logins
w                                   # who is logged in right now
sudo journalctl -u ssh --since today | grep -E "Accepted|Failed|Invalid user"
sudo journalctl _COMM=sudo --since today    # sudo activity
```

### 11.7 Automatic blocking and alerts (fail2ban for Nginx + app)

Filters (`/etc/fail2ban/filter.d/`):

```bash
# Repeated failed logins/registration/reset on the auth service (adjust the path to your routes)
sudo tee /etc/fail2ban/filter.d/nginx-auth-fail.conf >/dev/null <<'EOF'
[Definition]
failregex = ^<HOST> - \S+ \[[^\]]+\] "(POST|PUT) /auth/\S*(login|register|forgot|reset)\S* HTTP/[\d.]+" (401|403|429)
ignoreregex =
EOF

# Floods of 401/403 on any URL (token guessing, endpoint probing)
sudo tee /etc/fail2ban/filter.d/nginx-unauthorized.conf >/dev/null <<'EOF'
[Definition]
failregex = ^<HOST> - \S+ \[[^\]]+\] "[A-Z]+ [^"]*" (401|403) 
ignoreregex =
EOF
```

Alert action:

```bash
sudo tee /etc/fail2ban/action.d/telegram.conf >/dev/null <<'EOF'
[Definition]
actionstart =
actionstop  =
actioncheck =
actionban   = /usr/local/bin/notify.sh "🚫 fail2ban BANNED <ip> (jail: <name>, failures: <failures>)"
actionunban =
EOF
```

Jails + alert on every ban (separate file so it doesn't clash with `jail.local` from section 5.3):

```bash
sudo tee /etc/fail2ban/jail.d/10-converter.local >/dev/null <<'EOF'
[DEFAULT]
action = %(action_)s
         telegram

[nginx-auth-fail]
enabled  = true
port     = http,https
filter   = nginx-auth-fail
logpath  = /var/log/nginx/converter_access.log
maxretry = 5
findtime = 10m
bantime  = 2h

[nginx-unauthorized]
enabled  = true
port     = http,https
filter   = nginx-unauthorized
logpath  = /var/log/nginx/converter_access.log
maxretry = 40
findtime = 10m
bantime  = 1h

[nginx-limit-req]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/converter_error.log
maxretry = 10
findtime = 5m
bantime  = 1h

[nginx-botsearch]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/*access.log
maxretry = 3
bantime  = 1d
EOF

# Test the patterns against real logs (should report "matched" lines after some failed logins)
sudo fail2ban-regex /var/log/nginx/converter_access.log /etc/fail2ban/filter.d/nginx-auth-fail.conf
sudo systemctl restart fail2ban
sudo fail2ban-client status
sudo fail2ban-client status nginx-auth-fail
```

Useful: `sudo fail2ban-client set <jail> unbanip <IP>` (if you ban yourself), `sudo fail2ban-client banned`.
Add your own static IP to `ignoreip` in `[DEFAULT]` if you test a lot.

### 11.8 Health checking

Three layers:

1. **Container health** — `healthcheck:` in compose (already added) marks `converter-api` as `healthy/unhealthy`
   (`docker ps`, `docker inspect`).
2. **Server-side checker (every minute)**: checks the public site, readiness, each container, nginx, fail2ban, UFW,
   disk, RAM, certificate expiry, and 5xx / 401-403 spikes. It alerts **once** when a problem starts and
   once when it recovers (no spam), and restarts unhealthy containers.
3. **External monitor**: sees the outage when the whole server is down.

`/usr/local/bin/healthcheck.sh`:

```bash
sudo tee /usr/local/bin/healthcheck.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
DOMAIN="example.com"
LOG=/var/log/nginx/converter_access.log
STATE=/var/tmp/healthcheck-state
mkdir -p "$STATE"
source /etc/converter-alerts.env 2>/dev/null

alert() { /usr/local/bin/notify.sh "$1"; }

# check <id> <message> <command...>   → alerts once on failure, once on recovery
check() {
  local id=$1 msg=$2; shift 2
  if "$@" >/dev/null 2>&1; then
    if [ -f "$STATE/$id" ]; then rm -f "$STATE/$id"; alert "✅ RECOVERED: $msg"; fi
  else
    if [ ! -f "$STATE/$id" ]; then touch "$STATE/$id"; alert "🚨 PROBLEM: $msg"; fi
  fi
}

container_ok() { [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = "true" ] \
  && [ "$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$1")" != "unhealthy" ]; }
site_ok()    { [ "$(curl -s -o /dev/null -m 10 -w '%{http_code}' "https://$DOMAIN/health")" = "200" ]; }
disk_ok()    { [ "$(df --output=pcent / | tail -1 | tr -dc 0-9)" -lt 85 ]; }
mem_ok()     { [ "$(free | awk '/Mem:/ {printf "%d", $7/$2*100}')" -gt 10 ]; }
cert_ok()    { openssl x509 -checkend 1209600 -noout -in "/etc/letsencrypt/live/$DOMAIN/cert.pem"; }  # >14 days left
ufw_ok()     { ufw status | grep -q "Status: active"; }
err5xx_ok()  { [ "$(tail -n 1000 "$LOG" | awk '$9>=500' | wc -l)" -lt 20 ]; }
unauth_ok()  { [ "$(tail -n 1000 "$LOG" | awk '$9==401||$9==403' | wc -l)" -lt 100 ]; }

check site   "Website https://$DOMAIN/health is DOWN"           site_ok
check ready  "API readiness failing (soffice/gs/tesseract/disk)" curl -fs -m 10 http://127.0.0.1:8000/ready
check auth   "Auth service /health failing"                      curl -fs -m 10 http://127.0.0.1:8080/health
for c in converter-api converter-auth converter-db; do
  check "c_$c" "Container $c is not running / unhealthy" container_ok "$c"
done
check nginx  "nginx is not running"      systemctl is-active --quiet nginx
check f2b    "fail2ban is not running"   systemctl is-active --quiet fail2ban
check ufw    "UFW firewall is NOT active" ufw_ok
check disk   "Disk usage above 85%"      disk_ok
check mem    "Available RAM below 10%"   mem_ok
check cert   "TLS certificate expires in < 14 days (renewal failing?)" cert_ok
check e5xx   "Spike of 5xx errors (≥20 in last 1000 requests)"        err5xx_ok
check eauth  "Spike of 401/403 (≥100 in last 1000 requests): possible attack" unauth_ok

# Auto-heal: restart containers Docker reports as unhealthy
for c in converter-api; do
  if [ "$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$c" 2>/dev/null)" = "unhealthy" ]; then
    docker restart "$c" >/dev/null && alert "♻️ Restarted unhealthy container $c"
  fi
done

# Dead-man's switch: external service alerts you if these pings STOP (server or cron dead)
[ -n "${HEARTBEAT_URL:-}" ] && curl -fsS -m 10 "$HEARTBEAT_URL" >/dev/null 2>&1
exit 0
EOF
sudo chmod 755 /usr/local/bin/healthcheck.sh

echo '* * * * * root /usr/local/bin/healthcheck.sh' | sudo tee /etc/cron.d/converter-health
sudo /usr/local/bin/healthcheck.sh && echo "ran OK"
```

Test an alert: `docker stop converter-auth`. Within about a minute you get "PROBLEM", then start it again and you
get "RECOVERED". (If you have not added the Go `/health` route yet, the `auth` check will alert until you do.)
The 5xx and 401/403 checks are rough heuristics that look at the last 1000 requests. Tune the numbers to your traffic.

**External monitors (free tiers: UptimeRobot, Better Stack, healthchecks.io)**: set up:

- HTTPS monitor on `https://example.com/health` (alerts if the server, Nginx or the app is unreachable)
- SSL-expiry monitor
- A **heartbeat/cron monitor** → paste its URL into `HEARTBEAT_URL` in `/etc/converter-alerts.env`. The server pings it
  every minute; if pings stop, you're alerted even if the VPS is completely dead.

### 11.9 Daily activity report

```bash
sudo apt install -y jq goaccess

sudo tee /usr/local/bin/daily-report.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
LOG=/var/log/nginx/converter_access.log
Y=$(date -d yesterday +%d/%b/%Y)
LINES=$(zcat -f "$LOG" "$LOG.1" 2>/dev/null | grep "\[$Y")
cnt() { echo "$LINES" | awk -v c="$1" "$2" | wc -l; }
APPLOG=/opt/converter/data/logs/audit.log

REPORT="📊 Daily report $(hostname) — $Y
Requests: $(echo "$LINES" | grep -c .)
401/403: $(cnt x '$9==401||$9==403')   429: $(cnt x '$9==429')   5xx: $(cnt x '$9>=500')
SSH accepted: $(journalctl -u ssh --since yesterday --until today 2>/dev/null | grep -c 'Accepted')
SSH failed/invalid: $(journalctl -u ssh --since yesterday --until today 2>/dev/null | grep -cE 'Failed password|Invalid user')
Currently banned (sshd): $(fail2ban-client status sshd 2>/dev/null | awk -F: '/Currently banned/{print $2}')
App events: logins failed=$(docker compose -f /opt/converter/docker-compose.yml logs --since 24h auth 2>/dev/null | grep -c login_failed), \
ssrf_blocked=$(grep -c ssrf_blocked "$APPLOG" 2>/dev/null), upload_rejected=$(grep -c upload_rejected "$APPLOG" 2>/dev/null)
Disk: $(df -h / | awk 'NR==2{print $5}')  RAM free: $(free -h | awk '/Mem:/{print $7}')
Top IPs:
$(echo "$LINES" | awk '{print $1}' | sort | uniq -c | sort -rn | head -5)"
/usr/local/bin/notify.sh "$REPORT"
EOF
sudo chmod 755 /usr/local/bin/daily-report.sh
echo '0 8 * * * root /usr/local/bin/daily-report.sh' | sudo tee /etc/cron.d/converter-report
```

### 11.10 Live views and periodic audits

```bash
sudo goaccess /var/log/nginx/converter_access.log --log-format=COMBINED   # interactive traffic dashboard in the terminal
docker stats                                                               # live CPU/RAM per container
sudo apt install -y lynis && sudo lynis audit system                       # server hardening score + suggestions (monthly)
sudo rkhunter --update && sudo rkhunter --check --sk                       # rootkit scan (monthly)
```

If you want graphs (CPU, RAM, disk, per-container), install **Netdata** or **Grafana + Prometheus**, but **never expose
dashboards publicly**. Bind them to `127.0.0.1` and open them through an SSH tunnel:
`ssh -L 19999:127.0.0.1:19999 deploy@SERVER_IP` → http://localhost:19999.

### 11.11 Retention & privacy

| Log | Retention |
|---|---|
| Nginx access/error | 30 days (logrotate, set above) |
| App audit log | ~100 MB rotating (10 files × 10 MB), roughly weeks |
| Docker container logs | 5 × 10 MB per container (daemon.json, section 6) |
| systemd journal (SSH, sudo) | cap at 1 GB / 90 days (below) |
| auditd | `/var/log/audit` (default rotation); archive if you need more |

```bash
sudo mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nSystemMaxUse=1G\nMaxRetentionSec=90day\n' | sudo tee /etc/systemd/journald.conf.d/size.conf
sudo systemctl restart systemd-journald
```

IP addresses and user IDs are personal data. Mention logging and the retention period in your privacy policy,
keep logs readable only by root/`deploy` (`chmod 750 data/logs`), and **never** log passwords, tokens, full emails,
or file contents. If logs must survive a server compromise, ship them off-box (Better Stack, Grafana Cloud/Loki, or
`rclone` of `/opt/converter/data/logs` and `/var/log/nginx` to object storage). An attacker with root can edit local logs.

### 11.12 Investigation cheat sheet

```bash
cd /opt/converter

# Failed logins (auth service) and who/where
docker compose logs --since 24h auth | grep login_failed | jq -r '[.time,.user,.ip,.reason]|@tsv' 2>/dev/null

# All unauthorized access attempts recorded by the API
jq -c 'select(.msg=="unauthorized_access")' data/logs/audit.log | tail -20

# Everything one user did / everything one IP did
jq -c 'select(.user=="USER_ID")' data/logs/audit.log | tail -50
grep '^1.2.3.4 ' /var/log/nginx/converter_access.log | tail -50

# Top IPs causing 401/403 and top requested paths
awk '$9==401||$9==403{print $1}' /var/log/nginx/converter_access.log | sort | uniq -c | sort -rn | head
awk '{print $7}' /var/log/nginx/converter_access.log | sort | uniq -c | sort -rn | head

# Suspicious events
jq -c 'select(.msg|test("ssrf_blocked|upload_rejected|forbidden_file_access"))' data/logs/audit.log | tail -20

# Trace one request across Nginx + app via X-Request-ID
grep REQUEST_ID data/logs/audit.log /var/log/nginx/converter_access.json.log

# Connections, processes, recently changed files
sudo ss -tulpn                                         # listening sockets (only sshd/nginx public)
sudo ss -tnp state established | head -30
ps aux --sort=-%cpu | head
find /opt/converter -type f -mtime -1 -not -path '*/data/*' -not -path '*/.git/*'   # code/config changed in last day
docker diff converter-api                              # files changed inside the container (unexpected = investigate)
docker events --since 1h --until 0s                    # container start/stop/exec activity
```

### 11.13 What to do when an alert fires

| Alert | Likely cause | Action |
|---|---|---|
| 🔐 SSH/sudo session you didn't start | Stolen key or password | Section 15 immediately; check `last -a`, `ausearch -k ssh_keys` |
| 🚫 fail2ban ban (sshd / auth) | Brute-force bots (normal) | Nothing, unless bans are constant → consider restricting SSH to your IP |
| Spike of 401/403 | Token guessing, scanner, broken frontend token | Check top IPs (11.12), ban/Cloudflare-block the IP; verify frontend isn't looping |
| Spike of 5xx | Bug, OOM, LibreOffice hang, bad deploy | `docker compose logs api`, `docker stats`, roll back (section 12) |
| Container unhealthy / restarted | OOM (exit 137), crash loop | Lower concurrency, raise `mem_limit`, check logs |
| Readiness failing | Missing tool, disk full | `docker compose exec api which soffice gs tesseract`, `df -h`, cleanup cron |
| Disk > 85% | Uploads not cleaned, logs, Docker images | Check `du -sh data/* /var/log/*`, `docker system df`, `docker image prune -f` |
| Certificate < 14 days | Renewal failing | `sudo certbot renew --dry-run`, check port 80 and `certbot.timer` |
| UFW not active | Someone disabled it (or reboot issue) | Treat as suspicious: `sudo ufw enable`, check `ausearch`, `last` |
| `ssrf_blocked` / `upload_rejected` events | Someone probing the converter | Identify the IP/user in the audit log; ban or disable the account |
| "login_failed" burst for one user | Credential stuffing | Lock the account, force password reset, tighten auth rate limit |

---

## 12. Update / rollback workflow

`/opt/converter/deploy.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
cd /opt/converter
git fetch origin main
git diff --stat HEAD origin/main      # review what's coming
git pull --ff-only origin main
docker compose build
docker compose up -d
docker image prune -f
docker compose ps
```

```bash
chmod +x deploy.sh && ./deploy.sh
```

**Rollback:**

```bash
git log --oneline -5
git checkout <previous_commit_hash>
docker compose build && docker compose up -d
```

Monthly maintenance: `sudo apt update && sudo apt upgrade`, rebuild images to pick up base-image patches
(`docker compose build --pull && docker compose up -d`), run `pip-audit` / `govulncheck`, review `fail2ban` and Nginx logs.

---

## 13. Verification & troubleshooting

**From your own computer:**

```bash
curl -I https://example.com/health          # 200, with HSTS and other headers
curl -I http://example.com                  # 301 to https
nmap -Pn SERVER_IP                          # only 22, 80, 443 open
curl -s https://example.com/docs -o /dev/null -w "%{http_code}\n"   # should be 404 in production
```
Test TLS at https://www.ssllabs.com/ssltest/ (aim for A/A+) and headers at https://securityheaders.com.

**On the server:** `sudo ufw status`, `sudo ss -tulpn` (nothing but sshd, nginx on public addresses),
`docker ps` (ports on `127.0.0.1` only).

| Problem | Fix |
|---|---|
| 502 Bad Gateway | `docker compose ps` / `logs api`. Container crashed or still starting |
| 413 Request Entity Too Large | Raise `client_max_body_size` in Nginx and `MAX_UPLOAD_MB` |
| 504 on large conversions | Increase `proxy_read_timeout` and gunicorn `--timeout` |
| `Permission denied` writing to `uploads/` | `sudo chown -R 1000:1000 data/uploads data/converted_files data/outputs data/models` |
| LibreOffice fails / hangs | Needs writable `HOME` (`/home/app`) and `/tmp`; use a unique profile per job; check RAM with `docker stats` |
| Container killed (exit 137) | Out of memory: raise `mem_limit`, lower worker count, limit concurrent conversions |
| `rembg` downloads model on every start | Make sure `./data/models:/home/app/.u2net` is mounted and writable |
| CORS error in browser | Add the exact origin (scheme + domain) to `ALLOWED_ORIGINS` |
| Wrong client IP in logs | Check `X-Forwarded-For` handling and gunicorn `--forwarded-allow-ips` |
| `read_only: true` breaks the app | Add the failing path to `tmpfs` or a volume, or disable it |
| Certificate renewal fails | `sudo certbot renew --dry-run`; make sure port 80 is open |
| Locked out of SSH | hPanel → Browser terminal |

---

## 14. Final security checklist

**Server**
- [ ] Root SSH login disabled, password login disabled, key-only for `deploy`
- [ ] UFW enabled (22/80/443) and Hostinger firewall attached
- [ ] fail2ban running, unattended-upgrades enabled
- [ ] Swap configured, Hostinger backups/snapshots on

**Network & TLS**
- [ ] DNS A records correct, certificate issued, `certbot renew --dry-run` passes
- [ ] HTTP redirects to HTTPS, HSTS header present
- [ ] `nmap` shows only 22/80/443; app and DB ports are loopback/internal only

**Application**
- [ ] `APP_ENV=production`, `DEBUG=false`, `/docs` and `/openapi.json` return 404
- [ ] Strong random `JWT_SECRET` (≥32 bytes) in both services; no default fallback in code
- [ ] JWT verified on all conversion, editor and download routes; ownership checks on files
- [ ] CORS limited to your domain; TrustedHost configured
- [ ] SSRF guard on URL/HTML fetching features
- [ ] Upload size, type (magic bytes), pixel and page limits enforced; server-generated filenames
- [ ] Timeouts on every subprocess; concurrency limited
- [ ] Rate limits on login, upload and contact endpoints

**Monitoring & alerting**
- [ ] Telegram (or other) alert channel tested with `notify.sh`
- [ ] Audit log middleware active; login, unauthorized-access, upload and download events recorded
- [ ] SSH-login alert (PAM) and `auditd` rules loaded
- [ ] fail2ban jails for sshd, nginx auth failures, 401/403 floods, rate-limit abuse and scanners
- [ ] `healthcheck.sh` cron running; `docker stop converter-auth` produced a PROBLEM then RECOVERED alert
- [ ] External uptime monitor + heartbeat configured
- [ ] Daily report arrives; logs rotated (Nginx 30 days, journal capped)

**Data & operations**
- [ ] `.env` files are mode 600 and not in Git; no secrets in Git history
- [ ] `uploads/`, `converted_files/`, `outputs/` untracked; automatic cleanup running
- [ ] Daily DB backup + off-server copy; restore tested once
- [ ] Uptime monitor and log checks in place
- [ ] `pip-audit` / `govulncheck` clean; monthly update routine scheduled

---

## 15. If you think you were hacked

1. **Snapshot the VPS** in hPanel (keep evidence), then block traffic: `sudo ufw default deny incoming && sudo ufw reload` or detach the firewall to "deny all".
2. Check `last -a`, `sudo lastb`, `sudo journalctl -u ssh`, `sudo ausearch -k root_commands -i`, `docker diff converter-api`, `docker ps -a`, `crontab -l` for every user, `/etc/cron.d/`, and unexpected processes (`top`). See the investigation cheat sheet in section 11.12.
3. **Rotate everything**: `JWT_SECRET` (this logs everyone out), DB password, SMTP password, SSH keys, Hostinger/hPanel password + 2FA, Git deploy keys.
4. Safest recovery: rebuild the VPS from a clean OS image, redeploy from Git, restore only the **database** from a known-good backup. Don't copy back executables or scripts from the old server.
5. Find and fix how they got in (logs, outdated dependency, missing auth on an endpoint) before going live again.

Also turn on **2FA** for your Hostinger account and your Git provider. Account takeover is the easiest attack and no server hardening prevents it.
