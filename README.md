# Ennex Master Backend

The master gateway for the Ennex app. Single entry point that protects and routes to up to 20 backend services.

## File Structure

```
ennex-master-backend/
├── main.py          # App entry point, security middleware, reverse proxy
├── config.py        # Loads 20 backend slots from environment variables
├── security.py      # Threat engine: rate limits, bans, JWT, XSS, SQLi detection
├── router.py        # Matches incoming paths to the correct backend slot
├── forwarder.py     # Forwards requests to backend slots with HMAC signing
├── admin.py         # Admin-only endpoints for monitoring and control
├── logger.py        # Three rotating log files: access, error, security
├── models.py        # Unified request/response data models
├── requirements.txt # Python dependencies
├── render.yaml      # Render.com deployment config
└── .env.example     # Environment variable template
```

## Deploy to Render

### Step 1 — Push to GitHub
```
git init
git add .
git commit -m "Ennex master backend"
git remote add origin https://github.com/YOUR_USERNAME/ennex-master-backend.git
git push -u origin main
```

### Step 2 — Connect to Render
1. Go to https://render.com
2. Click New → Web Service
3. Connect your GitHub repo
4. Render auto-detects render.yaml

### Step 3 — Set Environment Variables in Render Dashboard
Go to your service → Environment tab and set:
- `ALLOWED_ORIGIN` → your Ennex frontend URL
- `JWT_SECRET` → strong random string
- `ADMIN_JWT_SECRET` → different strong random string
- `HMAC_SHARED_SECRET` → another strong random string
- `BACKEND_1_KEY` through `BACKEND_20_KEY` → your backend API keys

### Step 4 — Add Backend Slots
For each backend service, set in Render environment:
```
BACKEND_1_NAME=auth
BACKEND_1_URL=https://your-service.onrender.com
BACKEND_1_KEY=your-secret-api-key
BACKEND_1_ROUTES=/api/auth/*
```

## Admin Endpoints
All require `Authorization: Bearer <admin-jwt>` with `role: admin` claim.

| Endpoint | Method | Description |
|---|---|---|
| /admin/slots/status | GET | View all 20 slots and health |
| /admin/slots/reload | POST | Reload slot config from env |
| /admin/security/banned-ips | GET | View all banned IPs |
| /admin/security/unban/{ip} | DELETE | Unban an IP |
| /admin/security/logs | GET | Last 100 security events |
| /admin/health | GET | Full system health report |

## Security Features
- JWT auth on every route
- Rate limiting: 100 req/min per IP, 50 req/min per user
- Auto-ban after 10 failed auth attempts in 60 seconds
- XSS, SQL injection, path traversal detection and auto-ban
- Port scanning detection (5+ unmatched routes in 10s = 1hr ban)
- Replay attack prevention (30 second timestamp window)
- HMAC signed requests to all backend slots
- Security headers on every response
