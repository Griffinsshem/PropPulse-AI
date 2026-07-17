from __future__ import annotations

import uuid
from datetime import datetime
from typing import Generic, TypeVar

from sqlalchemy import select

from app.models.email_verification_token import EmailVerificationToken
from app.models.password_reset_token import PasswordResetToken
from app.repositories.base_repository import BaseRepository

TokenModel = TypeVar("TokenModel", EmailVerificationToken, PasswordResetToken)


class TokenRepository(BaseRepository, Generic[TokenModel]):
    """Shared data-access logic for single-use, expiring, hashed
    tokens. Parameterized over the specific model (EmailVerification
    Token or PasswordResetToken) so the two token *tables* stay
    separate (Separation of Concerns — their business rules may
    diverge later) while the *access pattern* is written once
    (DRY), instead of duplicating five near-identical methods."""

    def __init__(self, session, model: type[TokenModel]) -> None:
        super().__init__(session)
        self._model = model

    def create(
        self,
        *,
        user_id: uuid.UUID,
        token_hash: str,
        expires_at: datetime,
        ip_address: str | None = None,
    ) -> TokenModel:
        kwargs = {"user_id": user_id, "token_hash": token_hash, "expires_at": expires_at}
        if self._model is PasswordResetToken:
            kwargs["ip_address"] = ip_address
        token = self._model(**kwargs)
        self._session.add(token)
        self._session.flush()
        return token

    def get_valid_by_token_hash(self, token_hash: str, now: datetime) -> TokenModel | None:
        """Returns the token only if it exists, hasn't expired, and
        hasn't already been used. Callers should treat 'not found'
        and 'found but invalid' identically at the API layer (see
        Section 6 — generic 400 error, no detail on which case
        applies)."""
        stmt = select(self._model).where(
            self._model.token_hash == token_hash,
            self._model.expires_at > now,
            self._model.used_at.is_(None),
        )
        return self._session.scalar(stmt)

    def mark_used(self, token_id: uuid.UUID, when: datetime) -> None:
        token = self._session.get(self._model, token_id)
        if token is not None:
            token.used_at = when

    def __repr__(self) -> str:
        return f"<TokenRepository model={self._model.__name__}>"
