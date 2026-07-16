from __future__ import annotations

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import TimestampedModel


class Role(TimestampedModel):
    """A named role (e.g. Buyer, Agent, Admin) that groups permissions
    and is assigned to exactly one user per account."""

    __tablename__ = "roles"

    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<Role id={self.id} name={self.name!r}>"
