"""Transactional repository for document metadata.

Persists only the metadata contract (opaque ``subject_key``, kind, media type,
payload SHA-256, content-addressed object key, optional project reference, and a
timestamp). The raw ingestion ``body`` is never stored. All functions operate on a
caller-provided :class:`~sqlalchemy.orm.Session` so the transaction boundary and
commit/rollback stay owned by the request or scope that opened the session.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from models.schema import Document

# Response projection. Mirrors the pre-persistence API shape so clients are unaffected.
_PROJECTION = ("subject_key", "kind", "media_type", "payload_sha256", "object_key")


def _to_dict(document: Document) -> dict[str, Any]:
    return {field: getattr(document, field) for field in _PROJECTION}


def get_by_subject_and_object(session: Session, subject_key: str, object_key: str) -> Document | None:
    """Return the document for an exact (subject_key, object_key) pair, if any."""
    statement = select(Document).where(
        Document.subject_key == subject_key, Document.object_key == object_key
    )
    return session.scalars(statement).first()


def insert_document(
    session: Session,
    *,
    subject_key: str,
    kind: str,
    media_type: str,
    payload_sha256: str,
    object_key: str,
    project_id: int | None = None,
) -> tuple[dict[str, Any], bool]:
    """Insert a document, idempotent per (subject_key, object_key).

    Re-ingesting identical content for the same subject returns the existing row
    rather than creating a duplicate or overwriting it. Returns ``(record, created)``
    where ``created`` is ``False`` for the idempotent hit. The insert is flushed so a
    unique-constraint violation surfaces inside the caller's transaction (and can be
    mapped to a conflict) instead of at a later, ambiguous point.
    """
    existing = get_by_subject_and_object(session, subject_key, object_key)
    if existing is not None:
        return _to_dict(existing), False

    document = Document(
        subject_key=subject_key,
        kind=kind,
        media_type=media_type,
        payload_sha256=payload_sha256,
        object_key=object_key,
        project_id=project_id,
    )
    session.add(document)
    session.flush()
    return _to_dict(document), True


def list_by_subject(session: Session, subject_key: str) -> list[dict[str, Any]]:
    """Return all documents for an exact subject_key, ordered by insertion."""
    statement = select(Document).where(Document.subject_key == subject_key).order_by(Document.id)
    return [_to_dict(document) for document in session.scalars(statement).all()]


def delete_all(session: Session) -> None:
    """Delete every document row. Intended for test isolation only."""
    session.execute(delete(Document))
