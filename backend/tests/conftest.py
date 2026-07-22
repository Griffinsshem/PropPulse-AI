from __future__ import annotations

import os

import pytest
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.models.base import Base

load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))


@pytest.fixture(scope="session")
def engine():
    """One database engine shared across the whole test session.
    Uses a dedicated TEST_DATABASE_URL, separate from local dev — tests run against a
    real Postgres instance, not a mock, so we catch real SQL/type
    errors (e.g. a bad CITEXT usage) that an in-memory fake DB would
    hide."""
    database_url = os.environ["TEST_DATABASE_URL"]
    return create_engine(database_url)


@pytest.fixture(scope="session")
def tables(engine):
    """Creates all tables once per test session, drops them once
    the whole session finishes. Individual tests never see this —
    they only see the rollback-per-test fixture below.

    Base.metadata.create_all() only knows about SQLAlchemy models —
    it does NOT replay Alembic migrations, so any migration with a
    side effect outside of a table definition (like enabling a
    Postgres extension) must be reproduced here explicitly. citext
    is required by the users.email column."""
    with engine.begin() as connection:
        connection.execute(text("CREATE EXTENSION IF NOT EXISTS citext"))

    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)


@pytest.fixture
def db_session(engine, tables):
    """Wraps each individual test in a transaction that is always
    rolled back afterward, regardless of whether the test passed or
    failed. This means tests never leave data behind and never see
    data left by another test — full isolation, without the cost of
    recreating tables for every single test."""
    connection = engine.connect()
    transaction = connection.begin()
    session_factory = sessionmaker(bind=connection)
    session: Session = session_factory()

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def app(tables):
    """Builds a real Flask app configured against the test database.
    Depends on the `tables` fixture (not `db_session`) since routes
    build their own sessions per-request via db_session() — using
    the rollback-per-test db_session fixture here would conflict
    with that, since the app needs its own live connection to
    actually commit data that a subsequent request can then see."""
    from app import create_app
    from app.core.config import TestConfig

    flask_app = create_app(TestConfig)
    flask_app.config.update(TESTING=True)
    yield flask_app


@pytest.fixture
def client(app, engine):
    """Flask's test client: lets tests make real HTTP requests
    (client.post('/api/v1/auth/register', json={...})) against the
    app without actually running a server.

    Integration tests commit real data via their own request-scoped
    sessions (see app fixture), so they can't rely on db_session's
    rollback-based isolation. Cleanup is scoped to ONLY tests that
    request this `client` fixture, rather than being a global
    autouse fixture — that earlier design caused lock contention
    with db_session's still-open connection in unrelated unit
    tests, hanging the whole suite. Scoping cleanup to client's own
    teardown avoids that ordering ambiguity entirely."""
    test_client = app.test_client()
    yield test_client

    with engine.begin() as connection:
        table_names = [
            "audit_logs",
            "refresh_tokens",
            "email_verification_tokens",
            "password_reset_tokens",
            "oauth_identities",
            "users",
            "role_permissions",
            "permissions",
            "roles",
        ]
        for table_name in table_names:
            connection.execute(text(f"TRUNCATE TABLE {table_name} CASCADE"))
