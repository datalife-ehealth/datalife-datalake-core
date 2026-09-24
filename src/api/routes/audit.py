"""Merkle integrity endpoint."""

from fastapi import APIRouter

from api.routes.access import audit_log
from services.crypto import verify_chain

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get("/verify")
def verify() -> dict[str, object]:
    blocks = audit_log()
    return {"ok": verify_chain(blocks), "height": len(blocks)}
