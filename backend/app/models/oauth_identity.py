from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import TimestampedModel


class OAuthIdentity(TimestampedModel):
    """Links a user to an external identity provider (e.g. Google,
    Microsoft). One user may link multiple providers.

    Schema-only for now: no routes or services populate this table
    yet. Reserved ahead of time so the OAuth fast-follow feature is a
    pure code addition, not a schema migration against a live,
    populated users table."""

    __tablename__ = "oauth_identities"
    __table_args__ = (
        UniqueConstraint("provider", "provider_user_id", name="uq_oauth_provider_identity"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(String(20), nullable=False)
    provider_user_id: Mapped[str] = mapped_column(String(255), nullable=False)

    def __repr__(self) -> str:
        return f"<OAuthIdentity id={self.id} provider={self.provider!r} user_id={self.user_id}>"
