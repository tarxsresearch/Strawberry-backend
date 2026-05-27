from typing import Any, Optional, List
from pydantic import BaseModel

class UnifiedResponse(BaseModel):
    success: bool
    data: Any = None
    error: Optional[str] = ""
    trace_id: str

class SlotStatus(BaseModel):
    slot_id: int
    name: str
    url: str
    routes: List[str]
    online: bool

class SystemHealthReport(BaseModel):
    status: str
    active_slots: int
    total_banned_ips: int