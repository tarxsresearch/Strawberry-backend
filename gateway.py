# ==============================================================================
# ENNEX MASTER GATEWAY - Single File Version
# Combines: config, models, logger, security, router, forwarder, admin, main
# Deploy on Render with: uvicorn gateway:app --host 0.0.0.0 --port $PORT
# ==============================================================================

import os
import re
import ssl
import hmac
import time
import uuid
import json
import logging
import hashlib
import httpx
import jwt

from typing import Any, Dict, List, Optional, Set, Tuple
from logging.handlers import RotatingFileHandler
from urllib.parse import urlparse

from fastapi import FastAPI, Request, Response, APIRouter, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()


# ------------------------------------------------------------------------------
# SECTION 1 - LOGGING
# ------------------------------------------------------------------------------

os.makedirs("logs", exist_ok=True)

LOG_FORMAT = "%(asctime)s [%(levelname)s] [TRACE:%(trace_id)s] %(message)s"

class TraceFilter(logging.Filter):
    def filter(self, record):
        if not hasattr(record, "trace_id"):
            record.trace_id = "SYSTEM"
        return True

def setup_logger(name: str, log_file: str, level=logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False
    if not logger.handlers:
        handler = RotatingFileHandler(
            os.path.join("logs", log_file),
            maxBytes=50 * 1024 * 1024,
            backupCount=10,
            encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter(LOG_FORMAT))
        logger.addHandler(handler)
        logger.addFilter(TraceFilter())
    return logger

access_logger   = setup_logger("access",   "access.log")
error_logger    = setup_logger("error",    "error.log",    logging.ERROR)
security_logger = setup_logger("security", "security.log", logging.WARNING)


# ------------------------------------------------------------------------------
# SECTION 2 - MODELS
# ------------------------------------------------------------------------------

class UnifiedResponse(BaseModel):
    success:  bool
    data:     Optional[Any] = None
    error:    Optional[str] = ""
    trace_id: str

class SlotStatus(BaseModel):
    slot_id: int
    name:    str
    url:     str
    routes:  list[str]
    online:  bool

class SystemHealthReport(BaseModel):
    status:          str
    active_slots:    int
    total_banned_ips: int


# ------------------------------------------------------------------------------
# SECTION 3 - CONFIG
# ------------------------------------------------------------------------------

class BackendSlot(BaseModel):
    name:             str
    url:              str
    key:              str
    routes:           List[str]
    compiled_routes:  List[re.Pattern] = []

    class Config:
        arbitrary_types_allowed = True

class Settings:
    PORT:              int   = int(os.getenv("PORT", 8000))
    ALLOWED_ORIGIN:    str   = os.getenv("ALLOWED_ORIGIN", "https://your-ennex-app.com")
    JWT_SECRET:        str   = os.getenv("JWT_SECRET", "super-secret-ennex-jwt-key-change-in-prod")
    ADMIN_JWT_SECRET:  str   = os.getenv("ADMIN_JWT_SECRET", "super-secret-ennex-admin-jwt-key-change-in-prod")
    HMAC_SHARED_SECRET: bytes = os.getenv("HMAC_SHARED_SECRET", "ennex-hmac-shared-gateway-token").encode("utf-8")

    # Up to 20 managed backend slots
    slots:        Dict[int, BackendSlot] = {}
    slot_health:  Dict[int, bool]        = {}

    def __init__(self):
        self.load_slots()

    def load_slots(self):
        new_slots  = {}
        new_health = {}
        for i in range(1, 21):
            name       = os.getenv(f"BACKEND_{i}_NAME")
            url        = os.getenv(f"BACKEND_{i}_URL")
            key        = os.getenv(f"BACKEND_{i}_KEY")
            routes_raw = os.getenv(f"BACKEND_{i}_ROUTES")

            if name and url and key and routes_raw:
                routes_list = [r.strip() for r in routes_raw.split(",") if r.strip()]
                compiled    = []
                for r in routes_list:
                    regex_str = "^" + re.escape(r).replace(r"\*", ".*") + "$"
                    compiled.append(re.compile(regex_str))

                new_slots[i] = BackendSlot(
                    name=name,
                    url=url.rstrip("/"),
                    key=key,
                    routes=routes_list,
                    compiled_routes=compiled
                )
                new_health[i] = False

        self.slots       = new_slots
        self.slot_health = new_health

settings = Settings()


# ------------------------------------------------------------------------------
# SECTION 4 - ROUTER
# ------------------------------------------------------------------------------

def match_route(path: str) -> Tuple[Optional[int], Optional[BackendSlot]]:
    for slot_id, slot in settings.slots.items():
        for pattern in slot.compiled_routes:
            if pattern.match(path):
                return slot_id, slot
    return None, None


# ------------------------------------------------------------------------------
# SECTION 5 - SECURITY / THREAT ENGINE
# ------------------------------------------------------------------------------

class ThreatEngine:
    def __init__(self):
        self.blacklist_file         = "banned_ips.json"
        self.banned_ips:            Dict[str, float]      = {}
        self.banned_devices:        Dict[str, float]      = {}  # fingerprint -> lift_timestamp
        self.suspended_accounts:    Dict[str, str]        = {}  # user_id -> reason
        self.devtools_strikes:      Dict[str, int]        = {}  # user_id -> strike count
        self.failed_auth_attempts:  Dict[str, list]       = {}
        self.unmatched_route_hits:  Dict[str, list]       = {}
        self.ip_request_windows:    Dict[str, list]       = {}
        self.jwt_request_windows:   Dict[str, list]       = {}
        self.fingerprints:          Dict[str, Set[str]]   = {}

        self.load_blacklist()

    def load_blacklist(self):
        if os.path.exists(self.blacklist_file):
            try:
                with open(self.blacklist_file, "r") as f:
                    data = json.load(f)
                    now  = time.time()
                    self.banned_ips = {ip: exp for ip, exp in data.get("ips", {}).items() if exp > now}
                    self.banned_devices = {fp: exp for fp, exp in data.get("devices", {}).items() if exp > now}
                    self.suspended_accounts = data.get("accounts", {})
            except Exception:
                self.banned_ips = {}

    def save_blacklist(self):
        try:
            with open(self.blacklist_file, "w") as f:
                json.dump({
                    "ips":      self.banned_ips,
                    "devices":  self.banned_devices,
                    "accounts": self.suspended_accounts
                }, f)
        except Exception:
            pass

    def ban_ip(self, ip: str, duration_seconds: int, reason: str, trace_id: str):
        self.banned_ips[ip] = time.time() + duration_seconds
        self.save_blacklist()
        security_logger.warning(
            f"IP BANNED: {ip} for {duration_seconds}s. Reason: {reason}",
            extra={"trace_id": trace_id}
        )

    def ban_device(self, fingerprint: str, reason: str, trace_id: str):
        self.banned_devices[fingerprint] = time.time() + (365 * 24 * 3600)  # 1 year
        self.save_blacklist()
        security_logger.warning(
            f"DEVICE BANNED: {fingerprint[:16]}... Reason: {reason}",
            extra={"trace_id": trace_id}
        )

    def suspend_account(self, user_id: str, reason: str, trace_id: str):
        self.suspended_accounts[user_id] = reason
        self.save_blacklist()
        security_logger.warning(
            f"ACCOUNT SUSPENDED: {user_id}. Reason: {reason}",
            extra={"trace_id": trace_id}
        )

    def unsuspend_account(self, user_id: str):
        if user_id in self.suspended_accounts:
            del self.suspended_accounts[user_id]
            self.save_blacklist()

    def is_banned(self, ip: str) -> bool:
        now = time.time()
        if ip in self.banned_ips:
            if now < self.banned_ips[ip]:
                return True
            del self.banned_ips[ip]
            self.save_blacklist()
        return False

    def is_device_banned(self, fingerprint: str) -> bool:
        now = time.time()
        if fingerprint in self.banned_devices:
            if now < self.banned_devices[fingerprint]:
                return True
            del self.banned_devices[fingerprint]
            self.save_blacklist()
        return False

    def is_account_suspended(self, user_id: str) -> bool:
        return user_id in self.suspended_accounts

    # DevTools detection - 3 strike system
    def report_devtools(self, user_id: str, ip: str, fingerprint: str, trace_id: str) -> dict:
        strikes = self.devtools_strikes.get(user_id, 0) + 1
        self.devtools_strikes[user_id] = strikes

        security_logger.warning(
            f"DEVTOOLS DETECTED: user={user_id} ip={ip} strike={strikes}",
            extra={"trace_id": trace_id}
        )

        if strikes == 1:
            return {"action": "warn", "message": "This action is not allowed.", "strike": 1}

        if strikes == 2:
            return {"action": "warn", "message": "Final warning. Next violation will suspend your account.", "strike": 2}

        # Strike 3 - suspend account, ban IP and device permanently
        self.suspend_account(user_id, "DevTools detected (3 strikes)", trace_id)
        self.ban_ip(ip, 365 * 24 * 3600, "DevTools ban - associated IP", trace_id)
        if fingerprint:
            self.ban_device(fingerprint, "DevTools ban - device fingerprint", trace_id)

        return {
            "action":  "suspended",
            "message": "Your account has been suspended. Contact the developer to restore access.",
            "strike":  3
        }

    def check_replay_attack(self, request: Request, trace_id: str):
        ts_header = request.headers.get("X-Timestamp")
        if not ts_header:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
        try:
            if abs(time.time() - float(ts_header)) > 30.0:
                security_logger.warning("Replay attack detected.", extra={"trace_id": trace_id})
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    def verify_jwt(self, request: Request, trace_id: str) -> dict:
        path = request.url.path

        # Skip JWT check for public auth paths
        if any(p in path for p in ["/api/auth/login", "/api/auth/register", "/api/auth/token", "/api/security/report-devtools"]):
            return {"sub": "anonymous_auth"}

        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            security_logger.warning("Missing Authorization header.", extra={"trace_id": trace_id})
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])

            # Block suspended accounts on every request
            user_id = payload.get("sub", "")
            if self.is_account_suspended(user_id):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Account suspended. Contact developer to restore access."
                )
            return payload
        except jwt.PyJWTError:
            self.track_failed_auth(request.client.host, trace_id)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    def track_failed_auth(self, ip: str, trace_id: str):
        now      = time.time()
        attempts = [t for t in self.failed_auth_attempts.get(ip, []) if now - t < 60]
        attempts.append(now)
        self.failed_auth_attempts[ip] = attempts
        if len(attempts) >= 10:
            self.ban_ip(ip, 1800, "Brute force auth attempts detected.", trace_id)

    def track_unmatched_route(self, ip: str, trace_id: str):
        now  = time.time()
        hits = [t for t in self.unmatched_route_hits.get(ip, []) if now - t < 10]
        hits.append(now)
        self.unmatched_route_hits[ip] = hits
        if len(hits) >= 5:
            self.ban_ip(ip, 3600, "Port scanning detected.", trace_id)

    def enforce_rate_limits(self, ip: str, token: Optional[str], trace_id: str):
        now = time.time()

        # 100 requests per minute per IP
        ip_window = [t for t in self.ip_request_windows.get(ip, []) if now - t < 60]
        ip_window.append(now)
        self.ip_request_windows[ip] = ip_window
        if len(ip_window) > 100:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS)

        # 50 requests per minute per JWT token
        if token:
            jwt_window = [t for t in self.jwt_request_windows.get(token, []) if now - t < 60]
            jwt_window.append(now)
            self.jwt_request_windows[token] = jwt_window
            if len(jwt_window) > 50:
                raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS)

    def fingerprint_request(self, user_id: str, ip: str, trace_id: str):
        if user_id == "anonymous_auth":
            return
        if user_id not in self.fingerprints:
            self.fingerprints[user_id] = set()
        self.fingerprints[user_id].add(ip)
        if len(self.fingerprints[user_id]) > 5:
            security_logger.warning(
                f"Suspicious: Account '{user_id}' seen across {len(self.fingerprints[user_id])} IPs.",
                extra={"trace_id": trace_id}
            )

    def inspect_payload(self, text: str, ip: str, trace_id: str):
        if re.search(r"(<script|javascript:|onerror=|onload=|eval\()", text, re.IGNORECASE):
            self.ban_ip(ip, 86400, "XSS injection pattern detected.", trace_id)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

        if re.search(r"(\bUNION\b.*\bSELECT\b|' OR '1'='1|--|/\*|\bDROP DATABASE\b)", text, re.IGNORECASE):
            self.ban_ip(ip, 86400, "SQL injection pattern detected.", trace_id)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

        if re.search(r"(\.\.\/\.\.\/|\betc/passwd\b|/win\.ini)", text, re.IGNORECASE):
            self.ban_ip(ip, 86400, "Directory traversal detected.", trace_id)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    def sanitize_string(self, value: str) -> str:
        return re.sub(r"[<>\'\"\\;]", "", value)

threat_engine = ThreatEngine()


# ------------------------------------------------------------------------------
# SECTION 6 - FORWARDER
# ------------------------------------------------------------------------------

http_client = httpx.AsyncClient(
    timeout=10.0,
    limits=httpx.Limits(max_connections=500, max_keepalive_connections=100)
)

def generate_hmac_signature(trace_id: str, timestamp: str, body: bytes) -> str:
    message = f"{trace_id}|{timestamp}".encode("utf-8") + body
    return hmac.HMAC(settings.HMAC_SHARED_SECRET, message, hashlib.sha256).hexdigest()

async def forward_request(request: Request, slot_url: str, slot_key: str, trace_id: str) -> Response:
    path       = request.url.path
    query      = request.url.query
    target_url = f"{slot_url}{path}"
    if query:
        target_url += f"?{query}"

    headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "authorization")}

    # Inject gateway identity headers - backend verifies these
    timestamp = str(time.time())
    headers["X-Ennex-Backend-Key"]        = slot_key
    headers["X-Ennex-Trace-ID"]           = trace_id
    headers["X-Ennex-Gateway-Timestamp"]  = timestamp

    body = await request.body()
    headers["X-Ennex-Signature"] = generate_hmac_signature(trace_id, timestamp, body)

    try:
        req = http_client.build_request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body
        )
        res = await http_client.send(req, stream=True)
        return StreamingResponse(
            res.aiter_raw(),
            status_code=res.status_code,
            headers=dict(res.headers),
            background=httpx.BackgroundTasks([res.aclose])
        )
    except httpx.TimeoutException:
        return Response(
            content=UnifiedResponse(
                success=False,
                error="Gateway timeout communicating with upstream service.",
                trace_id=trace_id
            ).model_dump_json(),
            status_code=503,
            media_type="application/json"
        )
    except Exception:
        return Response(
            content=UnifiedResponse(
                success=False,
                error="Service unavailable.",
                trace_id=trace_id
            ).model_dump_json(),
            status_code=503,
            media_type="application/json"
        )


# ------------------------------------------------------------------------------
# SECTION 7 - ADMIN ROUTER
# ------------------------------------------------------------------------------

admin_router = APIRouter(prefix="/admin")

def verify_admin_jwt(request: Request) -> str:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, settings.ADMIN_JWT_SECRET, algorithms=["HS256"])
        if payload.get("role") != "admin":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
        return payload.get("sub", "admin")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

@admin_router.get("/slots/status", response_model=UnifiedResponse)
async def get_slots_status(request: Request, admin_user: str = Depends(verify_admin_jwt)):
    data = [
        SlotStatus(
            slot_id=slot_id,
            name=slot.name,
            url=slot.url,
            routes=slot.routes,
            online=settings.slot_health.get(slot_id, False)
        ).model_dump()
        for slot_id, slot in settings.slots.items()
    ]
    return UnifiedResponse(success=True, data=data, trace_id=request.state.trace_id)

@admin_router.post("/slots/reload", response_model=UnifiedResponse)
async def reload_config(request: Request, admin_user: str = Depends(verify_admin_jwt)):
    settings.load_slots()
    await run_heartbeat_check()
    return UnifiedResponse(
        success=True,
        data={"message": "Slot configurations reloaded successfully."},
        trace_id=request.state.trace_id
    )

@admin_router.get("/security/banned-ips", response_model=UnifiedResponse)
async def get_banned_ips(request: Request, admin_user: str = Depends(verify_admin_jwt)):
    now = time.time()
    readable_bans = {
        ip: f"Remaining: {int(exp - now)}s"
        for ip, exp in threat_engine.banned_ips.items() if exp > now
    }
    return UnifiedResponse(success=True, data=readable_bans, trace_id=request.state.trace_id)

@admin_router.delete("/security/unban/{ip}", response_model=UnifiedResponse)
async def unban_ip(ip: str, request: Request, admin_user: str = Depends(verify_admin_jwt)):
    if ip in threat_engine.banned_ips:
        del threat_engine.banned_ips[ip]
        threat_engine.save_blacklist()
        return UnifiedResponse(
            success=True,
            data={"message": f"IP {ip} removed from blacklist."},
            trace_id=request.state.trace_id
        )
    return UnifiedResponse(
        success=False,
        error="Target IP is not currently banned.",
        trace_id=request.state.trace_id
    )

@admin_router.post("/security/unsuspend/{user_id}", response_model=UnifiedResponse)
async def unsuspend_account(user_id: str, request: Request, admin_user: str = Depends(verify_admin_jwt)):
    threat_engine.unsuspend_account(user_id)
    # Reset their devtools strike count too
    if user_id in threat_engine.devtools_strikes:
        del threat_engine.devtools_strikes[user_id]
    return UnifiedResponse(
        success=True,
        data={"message": f"Account {user_id} has been restored."},
        trace_id=request.state.trace_id
    )

@admin_router.get("/security/suspended-accounts", response_model=UnifiedResponse)
async def get_suspended_accounts(request: Request, admin_user: str = Depends(verify_admin_jwt)):
    return UnifiedResponse(
        success=True,
        data=threat_engine.suspended_accounts,
        trace_id=request.state.trace_id
    )

@admin_router.get("/security/banned-devices", response_model=UnifiedResponse)
async def get_banned_devices(request: Request, admin_user: str = Depends(verify_admin_jwt)):
    now = time.time()
    readable = {
        fp[:16] + "...": f"Remaining: {int(exp - now)}s"
        for fp, exp in threat_engine.banned_devices.items() if exp > now
    }
    return UnifiedResponse(success=True, data=readable, trace_id=request.state.trace_id)

@admin_router.get("/security/logs", response_model=UnifiedResponse)
async def get_security_logs(request: Request, admin_user: str = Depends(verify_admin_jwt)):
    try:
        log_path = os.path.join("logs", "security.log")
        if os.path.exists(log_path):
            with open(log_path, "r") as f:
                lines = f.readlines()[-100:]
            return UnifiedResponse(success=True, data=lines, trace_id=request.state.trace_id)
    except Exception:
        pass
    return UnifiedResponse(
        success=False,
        error="Unable to read security log file.",
        trace_id=request.state.trace_id
    )

@admin_router.get("/health", response_model=UnifiedResponse)
async def get_full_health(request: Request, admin_user: str = Depends(verify_admin_jwt)):
    active = sum(1 for s in settings.slot_health.values() if s)
    report = SystemHealthReport(
        status="HEALTHY" if active == len(settings.slots) else "DEGRADED",
        active_slots=active,
        total_banned_ips=len(threat_engine.banned_ips)
    )
    return UnifiedResponse(success=True, data=report.model_dump(), trace_id=request.state.trace_id)


# ------------------------------------------------------------------------------
# SECTION 8 - SECURITY REPORT ENDPOINT (called by frontend on DevTools detection)
# ------------------------------------------------------------------------------

class DevToolsReport(BaseModel):
    user_id:     str
    fingerprint: Optional[str] = ""
    strike:      Optional[int] = None

security_router = APIRouter(prefix="/api/security")

@security_router.post("/report-devtools", response_model=UnifiedResponse)
async def report_devtools(body: DevToolsReport, request: Request):
    ip          = request.client.host
    trace_id    = getattr(request.state, "trace_id", str(uuid.uuid4()))
    fingerprint = body.fingerprint or ""

    # Block if IP or device already banned
    if threat_engine.is_banned(ip):
        raise HTTPException(status_code=403, detail="Access denied.")
    if fingerprint and threat_engine.is_device_banned(fingerprint):
        raise HTTPException(status_code=403, detail="Access denied.")

    result = threat_engine.report_devtools(body.user_id, ip, fingerprint, trace_id)
    return UnifiedResponse(success=True, data=result, trace_id=trace_id)


# ------------------------------------------------------------------------------
# SECTION 9 - FASTAPI APP + MIDDLEWARE
# ------------------------------------------------------------------------------

app = FastAPI(
    title="Ennex Master Gateway",
    description="Single-file gateway managing all Ennex backend services.",
    version="3.0.0",
    docs_url=None,   # Disable public Swagger UI in production
    redoc_url=None
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.ALLOWED_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(admin_router)
app.include_router(security_router)


# ------------------------------------------------------------------------------
# SECTION 10 - REQUEST MIDDLEWARE (runs on every incoming request)
# ------------------------------------------------------------------------------

@app.middleware("http")
async def gateway_middleware(request: Request, call_next):
    trace_id          = str(uuid.uuid4())
    request.state.trace_id = trace_id
    ip                = request.client.host
    path              = request.url.path
    start             = time.time()

    # Block banned IPs immediately
    if threat_engine.is_banned(ip):
        return Response(
            content=UnifiedResponse(
                success=False,
                error="Access denied.",
                trace_id=trace_id
            ).model_dump_json(),
            status_code=403,
            media_type="application/json"
        )

    # Check device fingerprint ban
    fingerprint = request.headers.get("X-Device-Fingerprint", "")
    if fingerprint and threat_engine.is_device_banned(fingerprint):
        return Response(
            content=UnifiedResponse(
                success=False,
                error="Access denied.",
                trace_id=trace_id
            ).model_dump_json(),
            status_code=403,
            media_type="application/json"
        )

    # Skip security checks for admin and internal routes
    is_internal = path.startswith("/admin") or path.startswith("/health") or path.startswith("/api/security")

    auth_token = None
    jwt_payload = {"sub": "anonymous_auth"}

    if not is_internal:
        try:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                auth_token = auth_header.split(" ")[1]

            jwt_payload = threat_engine.verify_jwt(request, trace_id)
            user_id     = jwt_payload.get("sub", "anonymous_auth")

            # Block suspended accounts
            if threat_engine.is_account_suspended(user_id):
                return Response(
                    content=UnifiedResponse(
                        success=False,
                        error="Account suspended. Contact developer to restore access.",
                        trace_id=trace_id
                    ).model_dump_json(),
                    status_code=403,
                    media_type="application/json"
                )

            threat_engine.enforce_rate_limits(ip, auth_token, trace_id)
            threat_engine.fingerprint_request(user_id, ip, trace_id)

            # Inspect request body for injection attacks
            body_bytes = await request.body()
            try:
                body_text = body_bytes.decode("utf-8")
                if body_text:
                    threat_engine.inspect_payload(body_text, ip, trace_id)
            except UnicodeDecodeError:
                pass

        except HTTPException as e:
            return Response(
                content=UnifiedResponse(
                    success=False,
                    error=str(e.detail),
                    trace_id=trace_id
                ).model_dump_json(),
                status_code=e.status_code,
                media_type="application/json"
            )

    response = await call_next(request)

    # Log every request
    duration = round((time.time() - start) * 1000, 2)
    access_logger.info(
        f"{ip} {request.method} {path} -> {response.status_code} ({duration}ms)",
        extra={"trace_id": trace_id}
    )

    return response


# ------------------------------------------------------------------------------
# SECTION 11 - PROXY CATCHALL (routes all /api/* to correct backend slot)
# ------------------------------------------------------------------------------

@app.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
)
async def proxy_catchall(request: Request, full_path: str):
    trace_id = request.state.trace_id
    path     = request.url.path

    slot_id, slot = match_route(path)

    if not slot:
        threat_engine.track_unmatched_route(request.client.host, trace_id)
        return Response(
            content=UnifiedResponse(
                success=False,
                error="Route not found.",
                trace_id=trace_id
            ).model_dump_json(),
            status_code=404,
            media_type="application/json"
        )

    if not settings.slot_health.get(slot_id, False):
        return Response(
            content=UnifiedResponse(
                success=False,
                error=f"Service '{slot.name}' is currently offline.",
                trace_id=trace_id
            ).model_dump_json(),
            status_code=503,
            media_type="application/json"
        )

    return await forward_request(request, slot.url, slot.key, trace_id)


# ------------------------------------------------------------------------------
# SECTION 12 - HEALTH CHECK + HEARTBEAT
# ------------------------------------------------------------------------------

@app.get("/health")
async def health_check(request: Request):
    active = sum(1 for s in settings.slot_health.values() if s)
    return {
        "status":       "healthy",
        "version":      "3.0.0",
        "active_slots": active,
        "total_slots":  len(settings.slots)
    }

async def run_heartbeat_check():
    for slot_id, slot in settings.slots.items():
        try:
            res = await http_client.get(f"{slot.url}/health", timeout=5.0)
            settings.slot_health[slot_id] = res.status_code == 200
        except Exception:
            settings.slot_health[slot_id] = False


@app.on_event("startup")
async def startup_event():
    await run_heartbeat_check()
