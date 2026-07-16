from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import TimestampedModel


class AuditLog(TimestampedModel):
    """A permanent, append-only record of security-relevant events
    (login attempts, password resets, role changes, permission
    denials). Application code must only ever INSERT into this
    table — never UPDATE or DELETE. This rule is enforced by
    convention and code review, not by the database itself.

    user_id uses ON DELETE SET NULL (unlike every other user-linked
    table, which uses CASCADE): if a user account is later hard-
    deleted, we still want to retain the historical security record
    of what happened, just without the specific user link."""

    __tablename__ = "audit_logs"

    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    event_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String, nullable=True)
    event_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} event_type={self.event_type!r} user_id={self.user_id}>"
