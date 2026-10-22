"""Multi-modal ingestion of clinical payloads. Personal identifiers are rejected."""

from __future__ import annotations

import hashlib
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from core.config import get_settings
from core.database import get_session, session_scope
from services import documents as documents_service
from services.parsing import ParseError, parse_payload
from services.pii import scan_payload

router = APIRouter(prefix="/api/v1/ingest", tags=["ingestion"])

# One stable rejection message. The policy returns a category and safe field path for
# diagnostics, but the response never reflects which value or payload fragment matched.
_PII_REJECTED = "personal identifiers are not accepted by the lake tier"


class IngestRequest(BaseModel):
    subject_key: str = Field(min_length=4, max_length=64)
    kind: str = Field(pattern="^(json|xml|dicom)$")
    media_type: str = "application/octet-stream"
    body: str = Field(min_length=1)


def reset_store() -> None:
    """Clear persisted document metadata. Used for test isolation."""
    with session_scope() as session:
        documents_service.delete_all(session)


@router.post("")
def ingest(payload: IngestRequest, session: Session = Depends(get_session)) -> dict[str, Any]:
    # Parse the body under configured bounds first. parse_payload fails closed on
    # malformed, oversized, non-UTF-8, over-nested, or kind/media-type-mismatched
    # input. Running it before the PII scan below means the size and encoding checks
    # happen ahead of any whole-string work such as .lower(), so an oversized or
    # non-UTF-8 payload is rejected without first being copied. The reason is a stable
    # category string and is safe to surface without reflecting the payload.
    settings = get_settings()
    try:
        result = parse_payload(
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

    # Contextual PII policy over the normalized structure (nested keys, XML
    # attributes/text, DICOM identity tags, and obvious identifier values). Runs
    # before hashing/storing so no identity data is ever persisted or echoed back.
    if scan_payload(result):
        raise HTTPException(status_code=422, detail=_PII_REJECTED)

    # Digest is computed over the original UTF-8 body so parser normalization cannot
    # change the existing payload_sha256 contract. Only metadata is persisted; the
    # raw body never reaches the database.
    digest = hashlib.sha256(payload.body.encode("utf-8")).hexdigest()
    try:
        record, _created = documents_service.insert_document(
            session,
            subject_key=payload.subject_key,
            kind=payload.kind,
            media_type=payload.media_type,
            payload_sha256=digest,
            object_key=digest[:32],
        )
    except IntegrityError as exc:
        # A concurrent insert won the (subject_key, object_key) race. Fail closed with
        # a conflict rather than overwriting; the session dependency rolls back.
        raise HTTPException(status_code=409, detail="document already exists") from exc
    return record


@router.get("")
def list_documents(subject_key: str, session: Session = Depends(get_session)) -> dict[str, Any]:
    rows = documents_service.list_by_subject(session, subject_key)
    return {"documents": rows, "count": len(rows)}
