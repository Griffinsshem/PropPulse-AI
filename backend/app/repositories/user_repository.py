from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import func, select

from app.models.user import User
from app.repositories.base_repository import BaseRepository


class UserRepository(BaseRepository):
    """Owns all direct database queries against the users table.
    No other layer of the application is permitted to query User
    directly — every access goes through here, so we have exactly
    one place to review for correct, safe SQL."""

    def get_by_id(self, user_id: uuid.UUID) -> User | None:
        return self._session.get(User, user_id)

    def get_by_email(self, email: str) -> User | None:
        stmt = select(User).where(User.email == email, User.deleted_at.is_(None))
        return self._session.scalar(stmt)

    def create(self, *, email: str, password_hash: str, role_id: uuid.UUID) -> User:
        user = User(email=email, password_hash=password_hash, role_id=role_id)
        self._session.add(user)
        self._session.flush()  # assigns user.id without committing the transaction
        return user

    def increment_failed_attempts(self, user_id: uuid.UUID) -> None:
        user = self._session.get(User, user_id)
        if user is not None:
            user.failed_login_attempts += 1

    def reset_failed_attempts(self, user_id: uuid.UUID) -> None:
        user = self._session.get(User, user_id)
        if user is not None:
            user.failed_login_attempts = 0
            user.locked_until = None

    def lock_until(self, user_id: uuid.UUID, until: datetime) -> None:
        user = self._session.get(User, user_id)
        if user is not None:
            user.locked_until = until

    def set_email_verified(self, user_id: uuid.UUID) -> None:
        user = self._session.get(User, user_id)
        if user is not None:
            user.is_email_verified = True

    def set_active(self, user_id: uuid.UUID, is_active: bool) -> None:
        user = self._session.get(User, user_id)
        if user is not None:
            user.is_active = is_active

    def update_role(self, user_id: uuid.UUID, role_id: uuid.UUID) -> None:
        user = self._session.get(User, user_id)
        if user is not None:
            user.role_id = role_id

    def set_password_hash(self, user_id: uuid.UUID, password_hash: str) -> None:
        """Used by password reset confirmation. Only ever receives
        an already-hashed value (hash_password() output) — never
        the plaintext new password."""
        user = self._session.get(User, user_id)
        if user is not None:
            user.password_hash = password_hash

    def update_last_login(self, user_id: uuid.UUID, when: datetime) -> None:
        user = self._session.get(User, user_id)
        if user is not None:
            user.last_login_at = when

    def list_paginated(
        self,
        *,
        page: int,
        per_page: int,
        role_id: uuid.UUID | None = None,
        is_active: bool | None = None,
    ) -> tuple[list[User], int]:
        """Returns (results_for_this_page, total_matching_rows).

        Runs two queries deliberately: one COUNT for the total (used
        by the frontend to render "page X of Y"), one SELECT for the
        actual page of rows. Combining them into one query is not
        possible in standard SQL when using LIMIT/OFFSET."""
        filters = [User.deleted_at.is_(None)]
        if role_id is not None:
            filters.append(User.role_id == role_id)
        if is_active is not None:
            filters.append(User.is_active == is_active)

        count_stmt = select(func.count()).select_from(User).where(*filters)
        total = self._session.scalar(count_stmt) or 0

        list_stmt = (
            select(User)
            .where(*filters)
            .order_by(User.created_at.desc())
            .offset((page - 1) * per_page)
            .limit(per_page)
        )
        results = list(self._session.scalars(list_stmt))
        return results, total

    def soft_delete(self, user_id: uuid.UUID, when: datetime) -> None:
        user = self._session.get(User, user_id)
        if user is not None:
            user.deleted_at = when
