from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.notifications import EmailSender
from app.core.security import (
    create_access_jwt,
    generate_secure_token,
    hash_password,
    hash_token,
    verify_password,
)
from app.models.email_verification_token import EmailVerificationToken
from app.models.user import User
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.repositories.role_repository import RoleRepository
from app.repositories.token_repository import TokenRepository
from app.repositories.user_repository import UserRepository

EMAIL_VERIFICATION_TOKEN_TTL_HOURS = 24
REFRESH_TOKEN_TTL_DAYS = 30
MAX_FAILED_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15


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


class InvalidCredentialsError(Exception):
    """Raised for ANY login failure that should be indistinguishable
    to the caller: wrong password, unknown email, unverified email,
    or a deactivated account. Deliberately generic — this is the
    STRIDE 'Information Disclosure / user enumeration' mitigation
    from Section 4: the API layer must map every one of these cases
    to the exact same 401 response with the exact same message."""


class AccountLockedError(Exception):
    """Raised when an account has exceeded MAX_FAILED_LOGIN_ATTEMPTS
    and is still within its lockout window. Deliberately a DISTINCT
    error from InvalidCredentialsError — per Section 6, this maps to
    a specific 423 response, since 'this account is temporarily
    locked' is only meaningful information to someone who already
    knows the account exists (they're the one who triggered it)."""

    def __init__(self, locked_until: datetime) -> None:
        self.locked_until = locked_until
        super().__init__(f"Account locked until {locked_until.isoformat()}")


class InvalidRefreshTokenError(Exception):
    """Raised when a presented refresh token is missing, expired, or
    invalid. Also raised (deliberately, with no different behavior
    visible to the caller) when a token is detected as REUSED after
    rotation — the theft-detection case. An attacker who replays a
    stolen, already-rotated token sees the exact same error as
    someone who just typed garbage; only the audit log and the
    silent full-family revocation reveal that something more
    serious happened."""


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
        refresh_token_repo: RefreshTokenRepository,
        audit_repo: AuditLogRepository,
        email_sender: EmailSender,
        jwt_secret_key: str,
    ) -> None:
        self._session = session
        self._user_repo = user_repo
        self._role_repo = role_repo
        self._refresh_token_repo = refresh_token_repo
        self._audit_repo = audit_repo
        self._email_sender = email_sender
        self._jwt_secret_key = jwt_secret_key
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

    def login(
        self,
        *,
        email: str,
        password: str,
        mfa_code: str | None = None,  # noqa: ARG002 - accepted now, verified in the MFA fast-follow
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[str, str, User]:
        """Implements FR-3. Returns (access_token, raw_refresh_token,
        user) on success. Raises AccountLockedError (423) if the
        account is currently locked, or InvalidCredentialsError (401)
        for every other failure case — wrong password, unknown
        email, unverified email, or deactivated account are all
        deliberately indistinguishable to the caller.

        TODO(mfa-fast-follow): mfa_code is accepted but not yet
        verified. Once MFA is implemented, a user with mfa_enabled
        must supply a valid TOTP code here or receive a distinct
        error requesting one.
        """
        now = datetime.now(timezone.utc)
        user = self._user_repo.get_by_email(email)

        if user is not None and user.locked_until is not None and user.locked_until > now:
            raise AccountLockedError(user.locked_until)

        password_is_correct = user is not None and verify_password(password, user.password_hash)
        account_is_usable = (
            user is not None and user.is_active and user.is_email_verified
        )

        if user is None or not password_is_correct or not account_is_usable:
            if user is not None:
                self._record_failed_login(user, now)
            self._audit_repo.record(
                user_id=user.id if user is not None else None,
                event_type="login_failure",
                ip_address=ip_address,
                user_agent=user_agent,
            )
            self._session.commit()
            raise InvalidCredentialsError("Invalid email or password.")

        self._user_repo.reset_failed_attempts(user.id)
        self._user_repo.update_last_login(user.id, now)

        role = self._role_repo.get_by_id(user.role_id)
        access_token = create_access_jwt(
            user_id=str(user.id), role=role.name if role is not None else "unknown",
            secret_key=self._jwt_secret_key,
        )
        raw_refresh_token = generate_secure_token()
        self._refresh_token_repo.create(
            user_id=user.id,
            token_hash=hash_token(raw_refresh_token),
            family_id=uuid.uuid4(),
            expires_at=now + timedelta(days=REFRESH_TOKEN_TTL_DAYS),
            user_agent=user_agent,
            ip_address=ip_address,
        )

        self._audit_repo.record(
            user_id=user.id,
            event_type="login_success",
            ip_address=ip_address,
            user_agent=user_agent,
        )

        self._session.commit()

        return access_token, raw_refresh_token, user

    def refresh(
        self,
        *,
        raw_refresh_token: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[str, str]:
        """Implements FR-4: rotates a refresh token on every use and
        detects theft via reuse of an already-revoked token. Returns
        (new_access_token, new_raw_refresh_token) on success.

        Raises InvalidRefreshTokenError for every failure case:
        token not found, expired, or reused-after-rotation. These
        are deliberately indistinguishable to the caller — only the
        internal handling differs (a reuse triggers full family
        revocation; a simple not-found does not, since there is no
        family to revoke)."""
        now = datetime.now(timezone.utc)
        token_hash = hash_token(raw_refresh_token)
        existing_token = self._refresh_token_repo.get_by_token_hash(token_hash)

        if existing_token is None or existing_token.expires_at <= now:
            raise InvalidRefreshTokenError("Invalid or expired refresh token.")

        if existing_token.is_revoked:
            # Theft signal: this exact token was already rotated away.
            # Revoke every token in the family, not just this one.
            self._refresh_token_repo.revoke_family(existing_token.family_id, now)
            self._audit_repo.record(
                user_id=existing_token.user_id,
                event_type="refresh_token_reuse_detected",
                description="A previously-rotated refresh token was reused; entire token family revoked.",
                ip_address=ip_address,
                user_agent=user_agent,
            )
            self._session.commit()
            raise InvalidRefreshTokenError("Invalid or expired refresh token.")

        user = self._user_repo.get_by_id(existing_token.user_id)
        if user is None or not user.is_active:
            raise InvalidRefreshTokenError("Invalid or expired refresh token.")

        # Normal rotation: revoke the presented token, issue a new one
        # sharing the SAME family_id so a future reuse can still be
        # detected as belonging to this login's lineage.
        self._refresh_token_repo.revoke(existing_token.id, now)

        role = self._role_repo.get_by_id(user.role_id)
        new_access_token = create_access_jwt(
            user_id=str(user.id),
            role=role.name if role is not None else "unknown",
            secret_key=self._jwt_secret_key,
        )
        new_raw_refresh_token = generate_secure_token()
        self._refresh_token_repo.create(
            user_id=user.id,
            token_hash=hash_token(new_raw_refresh_token),
            family_id=existing_token.family_id,
            expires_at=now + timedelta(days=REFRESH_TOKEN_TTL_DAYS),
            user_agent=user_agent,
            ip_address=ip_address,
        )

        self._audit_repo.record(
            user_id=user.id,
            event_type="token_refreshed",
            ip_address=ip_address,
            user_agent=user_agent,
        )

        self._session.commit()

        return new_access_token, new_raw_refresh_token

    def _record_failed_login(self, user: User, now: datetime) -> None:
        """Increments the failure counter and locks the account if
        the threshold is reached.

        NOTE: increment_failed_attempts() mutates `user` in place
        (SQLAlchemy's identity map means `user` here and the row
        loaded inside the repository method are the same object in
        this session) — so user.failed_login_attempts already
        reflects the incremented value immediately after this call.
        Do NOT add +1 again here; an earlier version of this method
        did exactly that and caused accounts to lock out one attempt
        early, which the test suite caught."""
        self._user_repo.increment_failed_attempts(user.id)
        if user.failed_login_attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
            self._user_repo.lock_until(user.id, now + timedelta(minutes=LOCKOUT_DURATION_MINUTES))
