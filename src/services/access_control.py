"""Time-bounded OTP grants and physician glass-break sessions."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import secrets
import threading
import time
from typing import Callable


@dataclass
class AccessGrant:
    token: str
    subject_key: str
    physician_id: str
    issued_at: float
    expires_at: float
    kind: str


class AccessController:
    """In-process grant store. Persist grants in PostgreSQL when the API is deployed."""

    def __init__(self, secret: str, physician_ids: set[str], clock: Callable[[], float] | None = None):
        self._secret = secret.encode("utf-8")
        self._physicians = set(physician_ids)
        self._now = clock or time.time
        self._grants: dict[str, AccessGrant] = {}
        self._lock = threading.Lock()

    def issue_otp(self, subject_key: str, physician_id: str, ttl_seconds: int) -> AccessGrant:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        issued = float(self._now())
        raw = secrets.token_hex(16)
        token = hmac.new(self._secret, f"{subject_key}|{physician_id}|{raw}".encode("utf-8"), hashlib.sha256).hexdigest()
        grant = AccessGrant(token, subject_key, physician_id, issued, issued + ttl_seconds, "OTP")
        with self._lock:
            self._grants[token] = grant
        return grant

    def validate_otp(self, token: str, subject_key: str) -> bool:
        with self._lock:
            grant = self._grants.get(token)
        if grant is None or grant.kind != "OTP":
            return False
        if grant.subject_key != subject_key:
            return False
        if self._now() >= grant.expires_at:
            return False
        return True

    def glass_break(self, physician_id: str, subject_key: str, reason: str) -> AccessGrant:
        if physician_id not in self._physicians:
            raise PermissionError("physician id is not a master physician id")
        if not reason.strip():
            raise ValueError("reason is required")
        issued = float(self._now())
        token = hmac.new(self._secret, f"glass|{physician_id}|{subject_key}|{issued}|{reason}".encode("utf-8"), hashlib.sha256).hexdigest()
        grant = AccessGrant(token, subject_key, physician_id, issued, issued + 3600, "GLASS_BREAK")
        with self._lock:
            self._grants[token] = grant
        return grant

    def reset(self) -> None:
        with self._lock:
            self._grants.clear()
