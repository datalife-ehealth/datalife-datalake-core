"""Patient OTP grants and physician glass-break."""

import threading
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from core.config import get_settings
from services.access_control import AccessController
from services.crypto import seal

router = APIRouter(prefix="/api/v1/access", tags=["access"])
_settings = get_settings()
_controller = AccessController(_settings.audit_secret, _settings.physician_ids())
_audit: list[dict[str, Any]] = []
_audit_lock = threading.Lock()


class OtpRequest(BaseModel):
    subject_key: str
    physician_id: str
    ttl_seconds: int = Field(default=900, gt=0, le=86400)


class OtpCheck(BaseModel):
    token: str
    subject_key: str


class GlassBreakRequest(BaseModel):
    physician_id: str
    subject_key: str
    reason: str


def controller() -> AccessController:
    return _controller


def audit_log() -> list[dict[str, Any]]:
    with _audit_lock:
        return list(_audit)


def reset_access_store() -> None:
    """Reset shared audit log and grant store for test isolation."""
    with _audit_lock:
        _audit.clear()
    _controller.reset()


def _append(event: dict[str, Any]) -> None:
    with _audit_lock:
        previous = _audit[-1]["block_hash"] if _audit else "0" * 64
        block = seal([event], previous, len(_audit)) | {"event": event}
        _audit.append(block)


@router.post("/otp")
def issue_otp(payload: OtpRequest) -> dict[str, Any]:
    grant = _controller.issue_otp(payload.subject_key, payload.physician_id, payload.ttl_seconds)
    event = {"type": "OTP_ISSUED", "subject_key": grant.subject_key, "physician_id": grant.physician_id, "expires_at": grant.expires_at}
    _append(event)
    return {"token": grant.token, "expires_at": grant.expires_at, "kind": grant.kind}


@router.post("/otp/validate")
def validate_otp(payload: OtpCheck) -> dict[str, bool]:
    return {"valid": _controller.validate_otp(payload.token, payload.subject_key)}


@router.post("/glass-break")
def glass_break(payload: GlassBreakRequest) -> dict[str, Any]:
    try:
        grant = _controller.glass_break(payload.physician_id, payload.subject_key, payload.reason)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    event = {
        "type": "GLASS_BREAK",
        "subject_key": grant.subject_key,
        "physician_id": grant.physician_id,
        "reason": payload.reason,
        "state": "UNCONFIRMED",
    }
    _append(event)
    return {"token": grant.token, "kind": grant.kind, "state": "UNCONFIRMED"}
