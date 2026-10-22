"""Persistence tests: document metadata is stored via SQLAlchemy, not an in-memory list.

All tests run against the temporary SQLite database configured in conftest. They
cover single-row inserts, subject-scoped queries, idempotent duplicates, the
per-subject uniqueness constraint, survival across engine recreation, clean rollback
on conflict, the metadata-only boundary, and the FastAPI session dependency override.
"""

from __future__ import annotations

import hashlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from core import database
from core.database import get_session, session_scope
from main import app
from models.schema import Base, Document
from services import documents as documents_service


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def _ingest(client: TestClient, subject_key: str, body: str, *, kind: str = "json", media_type: str = "application/json"):
    return client.post(
        "/api/v1/ingest",
        json={"subject_key": subject_key, "kind": kind, "media_type": media_type, "body": body},
    )


def _count(subject_key: str) -> int:
    with session_scope() as session:
        return len(documents_service.list_by_subject(session, subject_key))


def test_ingest_creates_exactly_one_document_row(client):
    body = '{"a": 1}'
    response = _ingest(client, "subj-aaaa", body)
    assert response.status_code == 200
    record = response.json()
    assert record["payload_sha256"] == hashlib.sha256(body.encode("utf-8")).hexdigest()
    assert _count("subj-aaaa") == 1


def test_get_filters_by_exact_subject_key_through_sqlalchemy(client):
    _ingest(client, "subj-aaaa", '{"a": 1}')
    _ingest(client, "subj-bbbb", '{"b": 2}')
    response = client.get("/api/v1/ingest", params={"subject_key": "subj-aaaa"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 1
    assert all(row["subject_key"] == "subj-aaaa" for row in payload["documents"])


def test_duplicate_ingest_is_idempotent_single_row(client):
    body = '{"same": "content"}'
    first = _ingest(client, "subj-dupe", body)
    second = _ingest(client, "subj-dupe", body)
    assert first.status_code == 200 and second.status_code == 200
    assert first.json() == second.json()
    assert _count("subj-dupe") == 1


def test_same_content_different_subject_creates_separate_rows(client):
    body = '{"shared": "content"}'
    assert _ingest(client, "subj-one0", body).status_code == 200
    assert _ingest(client, "subj-two0", body).status_code == 200
    # Same object_key (content address), but per-(subject, object) uniqueness allows both.
    assert _count("subj-one0") == 1
    assert _count("subj-two0") == 1


def test_metadata_survives_engine_disposal_and_recreation(tmp_path):
    url = f"sqlite:///{tmp_path / 'persist.sqlite'}"
    database.configure_engine(url)
    database.create_all()
    with session_scope() as session:
        documents_service.insert_document(
            session,
            subject_key="subj-keep",
            kind="json",
            media_type="application/json",
            payload_sha256="d" * 64,
            object_key="d" * 32,
        )
    database.dispose_engine()

    # Reconnect to the same file; the row must still be there.
    database.configure_engine(url)
    database.create_all()
    with session_scope() as session:
        rows = documents_service.list_by_subject(session, "subj-keep")
    assert len(rows) == 1
    assert rows[0]["payload_sha256"] == "d" * 64


def test_conflicting_insert_rolls_back_without_partial_row():
    with session_scope() as session:
        documents_service.insert_document(
            session,
            subject_key="subj-conf",
            kind="json",
            media_type="application/json",
            payload_sha256="a" * 64,
            object_key="a" * 32,
        )
    # A raw duplicate that bypasses the idempotent guard must fail and roll back.
    with pytest.raises(IntegrityError):
        with session_scope() as session:
            session.add(
                Document(
                    subject_key="subj-conf",
                    kind="json",
                    media_type="application/json",
                    payload_sha256="a" * 64,
                    object_key="a" * 32,
                )
            )
            session.flush()
    assert _count("subj-conf") == 1


def test_no_raw_body_or_identity_field_is_persisted(client):
    body = '{"observation": {"loinc": "2160-0", "value": 13.2}}'
    assert _ingest(client, "subj-body", body).status_code == 200
    columns = set(Document.__table__.columns.keys())
    assert "body" not in columns
    with session_scope() as session:
        document = session.scalars(select(Document).where(Document.subject_key == "subj-body")).first()
        assert document is not None
        for name in columns:
            value = getattr(document, name)
            if isinstance(value, str):
                assert body not in value


def test_failed_request_does_not_commit_a_row():
    # Drive get_session directly: raising inside the scope must roll back.
    generator = get_session()
    session = next(generator)
    session.add(
        Document(
            subject_key="subj-roll",
            kind="json",
            media_type="application/json",
            payload_sha256="e" * 64,
            object_key="e" * 32,
        )
    )
    with pytest.raises(RuntimeError):
        generator.throw(RuntimeError("boom"))
    assert _count("subj-roll") == 0


def test_fastapi_session_dependency_override(client):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSessionLocal = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    Base.metadata.create_all(engine)

    def override_session():
        session = TestingSessionLocal()
        try:
            yield session
            session.commit()
        finally:
            session.close()

    app.dependency_overrides[get_session] = override_session
    try:
        response = _ingest(client, "subj-ovrd", '{"a": 1}')
        assert response.status_code == 200
        # The row landed in the override database, and not in the default one.
        with TestingSessionLocal() as session:
            assert len(documents_service.list_by_subject(session, "subj-ovrd")) == 1
        assert _count("subj-ovrd") == 0
    finally:
        app.dependency_overrides.clear()
