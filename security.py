import time
import re
import os
import json
import hmac
import hashlib
from typing import Dict, Set, Optional
from fastapi import Request, HTTPException, status
import jwt
from config import settings
from logger import security_logger

class ThreatEngine:
    def __init__(self):
        self.blacklist_file = "banned_ips.json"
        self.banned_ips: Dict[str, float] = {}           # IP -> lift_timestamp
        self.failed_auth_attempts: Dict[str, list] = {}  # IP -> list of timestamps
        self.unmatched_route_hits: Dict[str, list] = {}  # IP -> list of timestamps
        self.ip_request_windows: Dict[str, list] = {}    # IP -> list of timestamps
        self.jwt_request_windows: Dict[str, list] = {}   # Token -> list of timestamps
        self.fingerprints: Dict[str, Set[str]] = {}      # User ID -> Set of IPs seen

        self.load_blacklist()

    def load_blacklist(self):
        if os.path.exists(self.blacklist_file):
            try:
                with open(self.blacklist_file, "r") as f:
                    data = json.load(f)
                    now = time.time()
                    # Filter out expired bans on startup
                    self.banned_ips = {ip: exp for ip, exp in data.items() if exp > now}
            except Exception:
                self.banned_ips = {}

    def save_blacklist(self):
        try:
            with open(self.blacklist_file, "w") as f:
                json.dump(self.banned_ips, f)
        except Exception:
            pass

    def ban_ip(self, ip: str, duration_seconds: int, reason: str, trace_id: str):
        lift_time = time.time() + duration_seconds
        self.banned_ips[ip] = lift_time
        self.save_blacklist()
        security_logger.warning(
            f"IP BANNED: {ip} for {duration_seconds}s. Reason: {reason}",
            extra={"trace_id": trace_id}
        )

    def is_banned(self, ip: str) -> bool:
        now = time.time()
        if ip in self.banned_ips:
            if now < self.banned_ips[ip]:
                return True
            else:
                del self.banned_ips[ip]
                self.save_blacklist()
        return False

    def check_replay_attack(self, request: Request, trace_id: str):
        ts_header = request.headers.get("X-Timestamp")
        if not ts_header:
            security_logger.warning(
                "Rejected request due to missing X-Timestamp header.",
                extra={"trace_id": trace_id}
            )
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
        try:
            req_ts = float(ts_header)
            if abs(time.time() - req_ts) > 30.0:
                security_logger.warning(
                    "Replay attack signature detected. Delta exceeded threshold.",
                    extra={"trace_id": trace_id}
                )
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    def verify_jwt(self, request: Request, trace_id: str) -> dict:
        # Exempt initial authentication paths from strict JWT checks
        path = request.url.path
        if "/api/auth/login" in path or "/api/auth/register" in path or "/api/auth/token" in path:
            return {"sub": "anonymous_auth"}

        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            security_logger.warning(
                "Missing or malformed Authorization header.",
                extra={"trace_id": trace_id}
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
            return payload
        except jwt.PyJWTError:
            # Route failed validation to brute force mitigation track
            self.track_failed_auth(request.client.host, trace_id)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    def track_failed_auth(self, ip: str, trace_id: str):
        now = time.time()
        attempts = self.failed_auth_attempts.get(ip, [])
        attempts = [t for t in attempts if now - t < 60]
        attempts.append(now)
        self.failed_auth_attempts[ip] = attempts

        if len(attempts) >= 10:
            self.ban_ip(ip, 1800, "Brute force auth attempts threshold breached.", trace_id)

    def track_unmatched_route(self, ip: str, trace_id: str):
        now = time.time()
        hits = self.unmatched_route_hits.get(ip, [])
        hits = [t for t in hits if now - t < 10]
        hits.append(now)
        self.unmatched_route_hits[ip] = hits

        if len(hits) >= 5:
            self.ban_ip(ip, 3600, "Port scanning heuristics detected.", trace_id)

    def enforce_rate_limits(self, ip: str, token: Optional[str], trace_id: str):
        now = time.time()

        # IP Rate Limiting: 100 requests per minute
        ip_window = self.ip_request_windows.get(ip, [])
        ip_window = [t for t in ip_window if now - t < 60]
        ip_window.append(now)
        self.ip_request_windows[ip] = ip_window
        if len(ip_window) > 100:
            security_logger.warning(f"IP rate limit breached by {ip}", extra={"trace_id": trace_id})
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS)

        # User JWT Rate Limiting: 50 requests per minute
        if token:
            jwt_window = self.jwt_request_windows.get(token, [])
            jwt_window = [t for t in jwt_window if now - t < 60]
            jwt_window.append(now)
            self.jwt_request_windows[token] = jwt_window
            if len(jwt_window) > 50:
                security_logger.warning(
                    "User JWT rate limit breached.",
                    extra={"trace_id": trace_id}
                )
                raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS)

    def fingerprint_request(self, user_id: str, ip: str, trace_id: str):
        """Identifies credential stuffing and proxy hopping bypass methods."""
        if user_id == "anonymous_auth":
            return
        if user_id not in self.fingerprints:
            self.fingerprints[user_id] = set()
        self.fingerprints[user_id].add(ip)
        if len(self.fingerprints[user_id]) > 5:
            security_logger.warning(
                f"Suspicious behavioral signature: Account '{user_id}' split across "
                f"{len(self.fingerprints[user_id])} networks.",
                extra={"trace_id": trace_id}
            )

    def inspect_payload(self, text: str, ip: str, trace_id: str):
        """Active Deep Packet Inspection Layer executing strict regex pattern verification."""
        # Detect XSS signatures
        if re.search(r"(<script|javascript:|onerror=|onload=|eval\()", text, re.IGNORECASE):
            self.ban_ip(ip, 86400, "Malicious XSS injection pattern detected.", trace_id)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

        # Detect SQL injection syntax
        if re.search(r"(\bUNION\b.*\bSELECT\b|' OR '1'='1|--|/\*|\bDROP DATABASE\b)", text, re.IGNORECASE):
            self.ban_ip(ip, 86400, "SQL Injection structural fingerprint detected.", trace_id)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

        # Detect path traversal sequences
        if re.search(r"(\.\./\.\./|\betc/passwd\b|/win\.ini)", text, re.IGNORECASE):
            self.ban_ip(ip, 86400, "Directory Traversal scan detected.", trace_id)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    def sanitize_string(self, value: str) -> str:
        """Removes dangerous characters from structured logging parameters."""
        return re.sub(r"[<>\'\"\\;]", "", value)

threat_engine = ThreatEngine()
