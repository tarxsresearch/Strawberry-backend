import time
import uuid
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response, status, HTTPException
# FIX: Removed JSONMockResponse (doesn't exist). Using JSONResponse and Response correctly.
from fastapi.responses import JSONResponse, Response as FastApiResponse
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from security import threat_engine
from router import match_route
from forwarder import forward_request, http_client
from admin import admin_router
from logger import access_logger, error_logger, security_logger
from models import UnifiedResponse


async def run_heartbeat_check():
    """Validates connectivity to all slots without crashing on failure."""
    for slot_id, slot in list(settings.slots.items()):
        try:
            res = await http_client.get(f"{slot.url}/health", timeout=2.0)
            settings.slot_health[slot_id] = (res.status_code == 200)
        except Exception:
            settings.slot_health[slot_id] = False


async def background_heartbeat_worker():
    """Runs health checks on all backend slots every 15 seconds."""
    while True:
        await run_heartbeat_check()
        await asyncio.sleep(15)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    settings.load_slots()
    heartbeat_task = asyncio.create_task(background_heartbeat_worker())
    yield
    # Graceful shutdown
    heartbeat_task.cancel()
    await http_client.aclose()


app = FastAPI(
    title="Ennex Master Gateway",
    lifespan=lifespan,
    docs_url=None,   # Disable public docs in production
    redoc_url=None
)

# CORS — only allow the Ennex frontend origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.ALLOWED_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def primary_security_pipeline(request: Request, call_next):
    trace_id = str(uuid.uuid4())
    request.state.trace_id = trace_id
    ip = request.client.host
    start_time = time.time()
    response = None

    # 1. IP Blacklist check — drop banned IPs silently
    if threat_engine.is_banned(ip):
        return Response(status_code=status.HTTP_403_FORBIDDEN)

    # 2. Payload size limit — block oversized requests (max 10MB)
    content_length = request.headers.get("Content-Length")
    if content_length and int(content_length) > 10 * 1024 * 1024:
        security_logger.warning(
            f"Payload size limit exceeded by IP: {ip}",
            extra={"trace_id": trace_id}
        )
        return Response(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)

    # Run full security checks on all non-admin, non-health routes
    if not request.url.path.startswith("/admin") and request.url.path != "/health":
        try:
            # 3. Replay attack prevention
            threat_engine.check_replay_attack(request, trace_id)

            # 4. Deep payload inspection (XSS, SQLi, path traversal)
            threat_engine.inspect_payload(request.url.path, ip, trace_id)
            if request.url.query:
                threat_engine.inspect_payload(request.url.query, ip, trace_id)

            body_bytes = await request.body()
            if body_bytes:
                threat_engine.inspect_payload(body_bytes.decode("utf-8", errors="ignore"), ip, trace_id)

            # 5. JWT verification + rate limiting + fingerprinting
            jwt_payload = threat_engine.verify_jwt(request, trace_id)
            user_id = jwt_payload.get("sub")
            auth_header = request.headers.get("Authorization")

            threat_engine.enforce_rate_limits(ip, auth_header, trace_id)
            threat_engine.fingerprint_request(user_id, ip, trace_id)

        # FIX: HTTPException is now properly imported
        except HTTPException as ex:
            return Response(status_code=ex.status_code)

    # 6. Process the request
    try:
        response = await call_next(request)
    except Exception as exc:
        error_logger.error(
            f"Uncaught runtime exception: {str(exc)}",
            exc_info=True,
            extra={"trace_id": trace_id}
        )
        return FastApiResponse(
            content=UnifiedResponse(
                success=False,
                error="An unexpected internal error occurred.",
                trace_id=trace_id
            ).model_dump_json(),
            status_code=500,
            media_type="application/json"
        )
    finally:
        duration = int((time.time() - start_time) * 1000)
        status_code = response.status_code if response is not None else 500
        access_logger.info(
            f"IP: {ip} | {request.method} {request.url.path} | Status: {status_code} | Time: {duration}ms",
            extra={"trace_id": trace_id}
        )

    # 7. Inject security headers on every response
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none';"

    return response


# Mount admin routes
app.include_router(admin_router)


@app.get("/health")
async def health_check(request: Request):
    """Public health check endpoint — used by Render to verify the service is alive."""
    return UnifiedResponse(
        success=True,
        data={"status": "ONLINE"},
        trace_id=request.state.trace_id
    )


@app.api_route(
    "/{path_name:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
)
async def reverse_proxy_router(request: Request, path_name: str):
    """Dynamic reverse proxy — matches path to correct backend slot and forwards securely."""
    trace_id = request.state.trace_id
    ip = request.client.host
    path = f"/{path_name}"

    slot_id, slot = match_route(path)
    if not slot_id or not slot:
        # Track unmatched routes for port scanning detection
        threat_engine.track_unmatched_route(ip, trace_id)
        return FastApiResponse(
            content=UnifiedResponse(
                success=False,
                error="Route not found.",
                trace_id=trace_id
            ).model_dump_json(),
            status_code=404,
            media_type="application/json"
        )

    if not settings.slot_health.get(slot_id, False):
        return FastApiResponse(
            content=UnifiedResponse(
                success=False,
                error="Target service is currently offline.",
                trace_id=trace_id
            ).model_dump_json(),
            status_code=503,
            media_type="application/json"
        )

    return await forward_request(request, slot.url, slot.key, trace_id)
