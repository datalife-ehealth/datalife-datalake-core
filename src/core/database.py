"""Database engine and session wiring for document-metadata persistence.

The application defaults to PostgreSQL (see ``Settings.database_url``) but the engine
and sessions are built lazily and are injectable, so tests can point the process at a
temporary file-backed SQLite database without importing or contacting PostgreSQL.

Scope note: this module exists to persist *document metadata* only. It makes no claim
that raw clinical payloads, OTP grants, glass-break sessions, or Merkle audit blocks
are durable, and ``create_all`` is a development bootstrap, not a migration strategy.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from core.config import get_settings
from models.schema import Base

# Process-wide engine and session factory. Both are created lazily on first use and
# can be reconfigured (e.g. by tests) via configure_engine().
_engine: Engine | None = None
_SessionLocal: sessionmaker | None = None


def _build_engine(database_url: str) -> Engine:
    # SQLite needs check_same_thread disabled so a connection can be used across the
    # threads a TestClient / threaded server may employ.
    connect_args: dict[str, object] = {}
    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    return create_engine(database_url, future=True, connect_args=connect_args)


def configure_engine(database_url: str | None = None, *, engine: Engine | None = None) -> Engine:
    """(Re)configure the process engine and session factory.

    Pass ``database_url`` (or a prebuilt ``engine``) to override the configured
    default; this is the injection point tests use for a temporary SQLite database.
    Any previously configured engine is disposed first to avoid leaking connections.
    """
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    if engine is None:
        url = database_url or get_settings().database_url
        engine = _build_engine(url)
    _engine = engine
    _SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)
    return _engine


def get_engine() -> Engine:
    """Return the process engine, configuring it from settings on first use."""
    if _engine is None:
        configure_engine()
    assert _engine is not None
    return _engine


def _session_factory() -> sessionmaker:
    if _SessionLocal is None:
        configure_engine()
    assert _SessionLocal is not None
    return _SessionLocal


def create_all() -> None:
    """Create all tables for the existing SQLAlchemy metadata (dev bootstrap)."""
    Base.metadata.create_all(get_engine())


def dispose_engine() -> None:
    """Dispose the engine and drop the session factory (used for teardown/tests)."""
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope: commit on success, roll back on error, always close."""
    session = _session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_session() -> Iterator[Session]:
    """FastAPI dependency yielding a session.

    Commits when the endpoint returns normally and rolls back if it raises, then
    always closes the session. FastAPI propagates endpoint exceptions back into this
    generator, so the rollback path runs for failed requests.
    """
    session = _session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
