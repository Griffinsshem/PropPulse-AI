from __future__ import annotations

import uuid

from app.models.audit_log import AuditLog
from app.repositories.base_repository import BaseRepository


class AuditLogRepository(BaseRepository):
    """Owns writes to the audit_logs table. Deliberately exposes
    ONLY a single 'record' method — no update, no delete. This is
    the code-level enforcement of the append-only rule described in
    AuditLog's docstring: there is no method here that could violate
    it, so bypassing it would require writing raw SQL outside this
    class entirely, which code review must catch."""

    def record(
        self,
        *,
        user_id: uuid.UUID | None,
        event_type: str,
        description: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        metadata: dict | None = None,
    ) -> AuditLog:
        entry = AuditLog(
            user_id=user_id,
            event_type=event_type,
            description=description,
            ip_address=ip_address,
            user_agent=user_agent,
            event_metadata=metadata,
        )
        self._session.add(entry)
        self._session.flush()
        return entry

    def __repr__(self) -> str:
        return "<AuditLogRepository>"
