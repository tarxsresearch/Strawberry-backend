import time
from fastapi import APIRouter, Depends, HTTPException, status, Request
import jwt
from config import settings
from security import threat_engine
from models import UnifiedResponse, SlotStatus, SystemHealthReport

admin_router = APIRouter(prefix="/admin")

def verify_admin_jwt(request: Request) -> str:
    """Strict isolated authorization for Admin Panel endpoints."""
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
    """View all 20 backend slots and their health status."""
    data = []
    for slot_id, slot in settings.slots.items():
        data.append(SlotStatus(
            slot_id=slot_id,
            name=slot.name,
            url=slot.url,
            routes=slot.routes,
            online=settings.slot_health.get(slot_id, False)
        ).model_dump())
    return UnifiedResponse(success=True, data=data, trace_id=request.state.trace_id)

@admin_router.post("/slots/reload", response_model=UnifiedResponse)
async def reload_config(request: Request, admin_user: str = Depends(verify_admin_jwt)):
    """Reload all 20 slot configs from environment variables without restarting."""
    settings.load_slots()
    from main import run_heartbeat_check
    await run_heartbeat_check()
    return UnifiedResponse(
        success=True,
        data={"message": "Slot configurations reloaded successfully."},
        trace_id=request.state.trace_id
    )

@admin_router.get("/security/banned-ips", response_model=UnifiedResponse)
async def get_banned_ips(request: Request, admin_user: str = Depends(verify_admin_jwt)):
    """View all currently banned IPs and their remaining ban time."""
    now = time.time()
    readable_bans = {
        ip: f"Remaining: {int(exp - now)}s"
        for ip, exp in threat_engine.banned_ips.items() if exp > now
    }
    return UnifiedResponse(success=True, data=readable_bans, trace_id=request.state.trace_id)

@admin_router.delete("/security/unban/{ip}", response_model=UnifiedResponse)
async def unban_ip(ip: str, request: Request, admin_user: str = Depends(verify_admin_jwt)):
    """Manually unban a specific IP address."""
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

@admin_router.get("/security/logs", response_model=UnifiedResponse)
async def get_security_logs(request: Request, admin_user: str = Depends(verify_admin_jwt)):
    """Read last 100 security log entries."""
    lines = []
    try:
        import os
        log_path = os.path.join("logs", "security.log")
        if os.path.exists(log_path):
            with open(log_path, "r") as f:
                lines = f.readlines()[-100:]
    except Exception:
        return UnifiedResponse(
            success=False,
            error="Unable to read security log file.",
            trace_id=request.state.trace_id
        )
    return UnifiedResponse(success=True, data=lines, trace_id=request.state.trace_id)

@admin_router.get("/health", response_model=UnifiedResponse)
async def get_full_health(request: Request, admin_user: str = Depends(verify_admin_jwt)):
    """Full system health report including all slots and banned IPs."""
    active = sum(1 for s in settings.slot_health.values() if s)
    report = SystemHealthReport(
        status="HEALTHY" if active == len(settings.slots) else "DEGRADED",
        active_slots=active,
        total_banned_ips=len(threat_engine.banned_ips)
    )
    return UnifiedResponse(success=True, data=report.model_dump(), trace_id=request.state.trace_id)
