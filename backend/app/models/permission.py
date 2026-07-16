from __future__ import annotations

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import TimestampedModel


class Permission(TimestampedModel):
    """A single granular capability (e.g. 'users:deactivate',
    'property:publish') that can be attached to one or more roles."""

    __tablename__ = "permissions"

    code: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<Permission id={self.id} code={self.code!r}>"
