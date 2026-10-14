"""Multi-modal ingestion of clinical payloads. Personal identifiers are rejected."""

from __future__ import annotations

import hashlib
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from core.config import get_settings
from services.parsing import ParseError, parse_payload

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
    # Parse the body under configured bounds first. parse_payload fails closed on
    # malformed, oversized, non-UTF-8, over-nested, or kind/media-type-mismatched
    # input. Running it before the PII scan below means the size and encoding checks
    # happen ahead of any whole-string work such as .lower(), so an oversized or
    # non-UTF-8 payload is rejected without first being copied. The reason is a stable
    # category string and is safe to surface without reflecting the payload.
    settings = get_settings()
    try:
        parse_payload(
            payload.kind,
            payload.media_type,
            payload.body,
            max_body_bytes=settings.ingest_max_body_bytes,
            max_depth=settings.ingest_max_depth,
            max_nodes=settings.ingest_max_nodes,
            max_dicom_values=settings.ingest_max_dicom_values,
        )
    except ParseError as exc:
        raise HTTPException(status_code=422, detail=exc.reason) from exc

    # Retained structural rejection until the dedicated PII policy work lands. It runs
    # on the raw body and never echoes it back.
    lowered = payload.body.lower()
    if any(field in lowered for field in ("<cpf>", "patientname")):
        raise HTTPException(status_code=422, detail="personal identifiers are not accepted by the lake tier")

    # Digest is computed over the original UTF-8 body so parser normalization cannot
    # change the existing payload_sha256 contract.
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
