import os
import re
from typing import Dict, List
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

class BackendSlot(BaseModel):
    name: str
    url: str
    key: str
    routes: List[str]
    compiled_routes: List[re.Pattern] = []

    class Config:
        arbitrary_types_allowed = True

class Settings:
    PORT: int = int(os.getenv("PORT", 8000))
    ALLOWED_ORIGIN: str = os.getenv("ALLOWED_ORIGIN", "https://your-ennex-app.com")
    JWT_SECRET: str = os.getenv("JWT_SECRET", "super-secret-ennex-jwt-key-change-in-prod")
    ADMIN_JWT_SECRET: str = os.getenv("ADMIN_JWT_SECRET", "super-secret-ennex-admin-jwt-key-change-in-prod")
    HMAC_SHARED_SECRET: bytes = os.getenv("HMAC_SHARED_SECRET", "ennex-hmac-shared-gateway-token").encode("utf-8")

    # Storage for the 20 managed slots
    slots: Dict[int, BackendSlot] = {}
    # Track backend operational readiness in memory
    slot_health: Dict[int, bool] = {}

    def __init__(self):
        self.load_slots()

    def load_slots(self):
        """Discovers and validates all 20 environment configurations on startup/reload."""
        new_slots = {}
        new_health = {}
        for i in range(1, 21):
            name = os.getenv(f"BACKEND_{i}_NAME")
            url = os.getenv(f"BACKEND_{i}_URL")
            key = os.getenv(f"BACKEND_{i}_KEY")
            routes_raw = os.getenv(f"BACKEND_{i}_ROUTES")

            if name and url and key and routes_raw:
                # Standardize routes into clean, searchable arrays
                routes_list = [r.strip() for r in routes_raw.split(",") if r.strip()]
                compiled = []
                for r in routes_list:
                    # Transform wildcard syntax (/api/auth/*) into precise regular expressions
                    regex_str = "^" + re.escape(r).replace(r"\*", ".*") + "$"
                    compiled.append(re.compile(regex_str))

                new_slots[i] = BackendSlot(
                    name=name,
                    url=url.rstrip("/"),
                    key=key,
                    routes=routes_list,
                    compiled_routes=compiled
                )
                # Keep active slots set to offline until verified via health check
                new_health[i] = False

        self.slots = new_slots
        self.slot_health = new_health

settings = Settings()
