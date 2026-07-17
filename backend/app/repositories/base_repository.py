from __future__ import annotations

from sqlalchemy.orm import Session


class BaseRepository:
    """Shared base for all repositories. Holds the injected database
    session; subclasses add table-specific query methods.

    The session is injected (Dependency Injection), never created
    internally — this is what lets tests substitute a test-scoped
    session, and what lets a service coordinate multiple repositories
    sharing one transaction."""

    def __init__(self, session: Session) -> None:
        self._session = session
