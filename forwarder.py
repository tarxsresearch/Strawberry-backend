import hmac
import hashlib
import time
import httpx
from fastapi import Request, Response
from fastapi.responses import StreamingResponse
from config import settings
from models import UnifiedResponse

# Keep HTTPX connection pooling tuned for low latency
http_client = httpx.AsyncClient(
    timeout=10.0,
    limits=httpx.Limits(max_connections=500, max_keepalive_connections=100)
)

def generate_hmac_signature(trace_id: str, timestamp: str, body: bytes) -> str:
    """Signs downstream API messages to guarantee origin authenticity."""
    message = f"{trace_id}|{timestamp}".encode("utf-8") + body
    # FIX: use hmac.HMAC correctly (not hmac.new which doesn't exist)
    return hmac.HMAC(settings.HMAC_SHARED_SECRET, message, hashlib.sha256).hexdigest()

async def forward_request(request: Request, slot_url: str, slot_key: str, trace_id: str) -> Response:
    """
    Streams requests down to targeted microservices safely.
    Handles payloads as streams to enforce low RAM footprint.
    """
    path = request.url.path
    query = request.url.query
    target_url = f"{slot_url}{path}"
    if query:
        target_url += f"?{query}"

    # Extract clean request context, strip original auth headers
    headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "authorization")}

    # Inject API validation tokens securely — frontend never sees these
    headers["X-Ennex-Backend-Key"] = slot_key
    headers["X-Ennex-Trace-ID"] = trace_id

    timestamp = str(time.time())
    headers["X-Ennex-Gateway-Timestamp"] = timestamp

    body = await request.body()
    # Compute downstream proof of gateway authority
    headers["X-Ennex-Signature"] = generate_hmac_signature(trace_id, timestamp, body)

    try:
        req = http_client.build_request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body
        )
        res = await http_client.send(req, stream=True)

        # Stream the downstream response back to the client
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
