from typing import Any, Optional
from pydantic import BaseModel

class UnifiedResponse(BaseModel):
    """Enforces identical data contracts across every API transaction."""
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = ""
    trace_id: str

class SlotStatus(BaseModel):
    slot_id: int
    name: str
    url: str
    routes: list[str]
    online: bool

class SystemHealthReport(BaseModel):
    status: str
    active_slots: int
    total_banned_ips: int
