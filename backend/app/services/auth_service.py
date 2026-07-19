from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.notifications import EmailSender
from app.core.security import generate_secure_token, hash_password, hash_token
from app.models.email_verification_token import EmailVerificationToken
from app.models.user import User
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.role_repository import RoleRepository
from app.repositories.token_repository import TokenRepository
from app.repositories.user_repository import UserRepository

EMAIL_VERIFICATION_TOKEN_TTL_HOURS = 24


class EmailAlreadyRegisteredError(Exception):
    """Raised when registration is attempted with an email that
    already has an account. Deliberately distinct from a generic
    exception so the API layer can map it to the specific 409
    response designed in Section 6."""


class RoleNotFoundError(Exception):
    """Raised if the requested role name doesn't exist in the roles
    table. Should not happen in normal operation if the Pydantic
    schema's role validation is working — but the service checks
    independently rather than trusting that assumption blindly
    (defense in depth)."""


class AuthService:
    """Business logic for authentication and account lifecycle:
    registration, email verification, login, token refresh, and
    logout. Depends only on repositories and core utilities that
    are themselves already independently tested — this class
    focuses purely on orchestrating them into the behaviors defined
    in Section 2's functional requirements."""

    def __init__(
        self,
        session: Session,
        user_repo: UserRepository,
        role_repo: RoleRepository,
        audit_repo: AuditLogRepository,
        email_sender: EmailSender,
    ) -> None:
        self._session = session
        self._user_repo = user_repo
        self._role_repo = role_repo
        self._audit_repo = audit_repo
        self._email_sender = email_sender
        self._email_verification_repo = TokenRepository(session, EmailVerificationToken)

    def register(self, *, email: str, password: str, role_name: str) -> User:
        """Implements FR-1 and FR-2 (registration + verification
        token issuance). Raises EmailAlreadyRegisteredError if the
        email is already in use, or RoleNotFoundError if role_name
        doesn't match any row in the roles table."""
        role = self._role_repo.get_by_name(role_name)
        if role is None:
            raise RoleNotFoundError(f"No such role: {role_name!r}")

        existing_user = self._user_repo.get_by_email(email)
        if existing_user is not None:
            raise EmailAlreadyRegisteredError(f"Email already registered: {email!r}")

        password_hash = hash_password(password)
        user = self._user_repo.create(email=email, password_hash=password_hash, role_id=role.id)

        raw_verification_token = generate_secure_token()
        self._email_verification_repo.create(
            user_id=user.id,
            token_hash=hash_token(raw_verification_token),
            expires_at=datetime.now(timezone.utc)
            + timedelta(hours=EMAIL_VERIFICATION_TOKEN_TTL_HOURS),
        )

        self._audit_repo.record(
            user_id=user.id,
            event_type="user_registered",
            description=f"New account registered with role {role_name!r}",
        )

        self._session.commit()

        self._email_sender.send_verification_email(
            to_email=email, raw_token=raw_verification_token
        )

        return user
