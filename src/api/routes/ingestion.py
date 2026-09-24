"""Multi-modal ingestion of clinical payloads. Personal identifiers are rejected."""

from __future__ import annotations

import hashlib
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/ingest", tags=["ingestion"])

_FORBIDDEN = {"name", "full_name", "cpf", "phone", "email", "emergency_contact"}
_STORE: list[dict[str, Any]] = []


class IngestRequest(BaseModel):
    subject_key: str = Field(min_length=4, max_length=64)
    kind: str = Field(pattern="^(json|xml|dicom)$")
    media_type: str = "application/octet-stream"
    body: str = Field(min_length=1)


def reset_store() -> None:
    _STORE.clear()


@router.post("")
def ingest(payload: IngestRequest) -> dict[str, Any]:
    lowered = payload.body.lower()
    if any(field in lowered for field in ("<cpf>", "patientname")):
        raise HTTPException(status_code=422, detail="personal identifiers are not accepted by the lake tier")
    digest = hashlib.sha256(payload.body.encode("utf-8")).hexdigest()
    record = {
        "subject_key": payload.subject_key,
        "kind": payload.kind,
        "media_type": payload.media_type,
        "payload_sha256": digest,
        "object_key": digest[:32],
    }
    _STORE.append(record)
    return record


@router.get("")
def list_documents(subject_key: str) -> dict[str, Any]:
    rows = [row for row in _STORE if row["subject_key"] == subject_key]
    return {"documents": rows, "count": len(rows)}
