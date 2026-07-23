from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, scoped_session, sessionmaker

# A single engine per process, created once when the app starts.
# The actual engine is bound to a specific DATABASE_URL inside
# init_engine(), called from create_app() — this module only
# declares the shape, it doesn't connect to anything at import time.
_session_factory: sessionmaker[Session] | None = None
db_session: scoped_session[Session] | None = None


def init_engine(database_url: str) -> None:
    """Creates the engine and session factory for this process,
    bound to the given database URL. Called once from create_app().
    Using scoped_session ties each session to the current thread/
    request context, so concurrent requests never accidentally
    share or interleave database state."""
    global _session_factory, db_session
    engine = create_engine(database_url, pool_pre_ping=True)
    _session_factory = sessionmaker(bind=engine)
    db_session = scoped_session(_session_factory)
