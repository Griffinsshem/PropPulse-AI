from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select

from app.models.refresh_token import RefreshToken
from app.repositories.base_repository import BaseRepository


class RefreshTokenRepository(BaseRepository):
    """Owns all direct database queries against the refresh_tokens
    table, including the family-based revocation logic that powers
    theft detection during token rotation."""

    def create(
        self,
        *,
        user_id: uuid.UUID,
        token_hash: str,
        family_id: uuid.UUID,
        expires_at: datetime,
        user_agent: str | None = None,
        ip_address: str | None = None,
    ) -> RefreshToken:
        token = RefreshToken(
            user_id=user_id,
            token_hash=token_hash,
            family_id=family_id,
            expires_at=expires_at,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        self._session.add(token)
        self._session.flush()
        return token

    def get_by_token_hash(self, token_hash: str) -> RefreshToken | None:
        stmt = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        return self._session.scalar(stmt)

    def revoke(self, token_id: uuid.UUID, when: datetime) -> None:
        token = self._session.get(RefreshToken, token_id)
        if token is not None:
            token.is_revoked = True
            token.revoked_at = when

    def revoke_family(self, family_id: uuid.UUID, when: datetime) -> None:
        """Revokes every token descended from one original login.
        Called when a reused (already-revoked) refresh token is
        presented — the theft-detection response designed in
        Section 6: log out every session in the family, not just
        block the one suspicious request."""
        stmt = select(RefreshToken).where(
            RefreshToken.family_id == family_id,
            RefreshToken.is_revoked.is_(False),
        )
        tokens = self._session.scalars(stmt)
        for token in tokens:
            token.is_revoked = True
            token.revoked_at = when

    def revoke_all_for_user(self, user_id: uuid.UUID, when: datetime) -> None:
        """Used by logout-all and by password-reset confirmation —
        revokes every active session for this user, across every
        family, not just one."""
        stmt = select(RefreshToken).where(
            RefreshToken.user_id == user_id,
            RefreshToken.is_revoked.is_(False),
        )
        tokens = self._session.scalars(stmt)
        for token in tokens:
            token.is_revoked = True
            token.revoked_at = when

    def __repr__(self) -> str:
        return "<RefreshTokenRepository>"
