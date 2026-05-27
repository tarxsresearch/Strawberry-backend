from typing import Tuple, Optional
from config import settings, BackendSlot

def match_route(path: str) -> Tuple[Optional[int], Optional[BackendSlot]]:
    """
    Evaluates incoming request paths against stored routing definitions.
    Returns the associated Slot ID and configuration upon a match.
    """
    for slot_id, slot in settings.slots.items():
        for pattern in slot.compiled_routes:
            if pattern.match(path):
                return slot_id, slot
    return None, None
