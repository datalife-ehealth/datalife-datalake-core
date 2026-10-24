"""Shared test fixtures.

Point the process at a temporary file-backed SQLite database for the whole session
(no PostgreSQL needed) and give every test a clean ``documents`` table so persistence
does not leak across tests.
"""

from __future__ import annotations

import pytest

from core import database
from core.database import session_scope
from services import documents as documents_service


@pytest.fixture(scope="session")
def sqlite_url(tmp_path_factory: pytest.TempPathFactory) -> str:
    return f"sqlite:///{tmp_path_factory.mktemp('db') / 'test.sqlite'}"


@pytest.fixture(autouse=True)
def database_isolation(sqlite_url: str):
    """Configure the SQLite engine, ensure tables exist, and start each test clean.

    Reconfiguring per test keeps isolation robust even if a test swaps the engine to
    its own database file, because the next test resets it here.
    """
    database.configure_engine(sqlite_url)
    database.create_all()
    with session_scope() as session:
        documents_service.delete_all(session)
    yield
    database.configure_engine(sqlite_url)
