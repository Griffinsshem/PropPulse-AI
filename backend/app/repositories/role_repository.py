from __future__ import annotations

import uuid

from sqlalchemy import select

from app.models.role import Role
from app.repositories.base_repository import BaseRepository


class RoleRepository(BaseRepository):
    """Owns queries against the roles table. Small and rarely
    changing compared to other repositories, but kept consistent
    with the rest of the architecture rather than special-cased —
    every table gets exactly one place responsible for its queries,
    regardless of how static that table's data is."""

    def get_by_name(self, name: str) -> Role | None:
        stmt = select(Role).where(Role.name == name)
        return self._session.scalar(stmt)

    def get_by_id(self, role_id: uuid.UUID) -> Role | None:
        return self._session.get(Role, role_id)

    def __repr__(self) -> str:
        return "<RoleRepository>"
