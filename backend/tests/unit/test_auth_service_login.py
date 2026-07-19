from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from app.core.security import hash_password
from app.models.audit_log import AuditLog
from app.models.role import Role
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.repositories.role_repository import RoleRepository
from app.repositories.user_repository import UserRepository
from app.services.auth_service import (
    AccountLockedError,
    AuthService,
    InvalidCredentialsError,
    MAX_FAILED_LOGIN_ATTEMPTS,
)

TEST_JWT_SECRET = "test-secret-key-not-used-in-production-32b"


class SpyEmailSender:
    def send_verification_email(self, *, to_email: str, raw_token: str) -> None:
        pass

    def send_password_reset_email(self, *, to_email: str, raw_token: str) -> None:
        pass


@pytest.fixture
def buyer_role(db_session):
    role = Role(name=f"buyer-{uuid.uuid4()}")
    db_session.add(role)
    db_session.flush()
    return role


@pytest.fixture
def auth_service(db_session):
    return AuthService(
        session=db_session,
        user_repo=UserRepository(db_session),
        role_repo=RoleRepository(db_session),
        refresh_token_repo=RefreshTokenRepository(db_session),
        audit_repo=AuditLogRepository(db_session),
        email_sender=SpyEmailSender(),
        jwt_secret_key=TEST_JWT_SECRET,
    )


@pytest.fixture
def verified_user(db_session, buyer_role):
    """A user in the state login() should accept: active, verified,
    correct password known to the test."""
    user_repo = UserRepository(db_session)
    user = user_repo.create(
        email="verified.user@example.com",
        password_hash=hash_password("correct-password-123"),
        role_id=buyer_role.id,
    )
    user_repo.set_email_verified(user.id)
    db_session.flush()
    return user


class TestAuthServiceLoginSuccess:
    def test_login_with_correct_credentials_returns_tokens_and_user(
        self, db_session, auth_service, verified_user
    ):
        access_token, raw_refresh_token, user = auth_service.login(
            email="verified.user@example.com", password="correct-password-123"
        )

        assert isinstance(access_token, str) and len(access_token) > 0
        assert isinstance(raw_refresh_token, str) and len(raw_refresh_token) > 0
        assert user.id == verified_user.id

    def test_successful_login_resets_failed_attempts_and_updates_last_login(
        self, db_session, auth_service, verified_user
    ):
        user_repo = UserRepository(db_session)
        user_repo.increment_failed_attempts(verified_user.id)
        db_session.flush()

        auth_service.login(email="verified.user@example.com", password="correct-password-123")

        refreshed = user_repo.get_by_id(verified_user.id)
        assert refreshed.failed_login_attempts == 0
        assert refreshed.last_login_at is not None

    def test_successful_login_writes_a_login_success_audit_entry(
        self, db_session, auth_service, verified_user
    ):
        auth_service.login(email="verified.user@example.com", password="correct-password-123")

        entries = db_session.query(AuditLog).filter(AuditLog.user_id == verified_user.id).all()
        assert any(e.event_type == "login_success" for e in entries)


class TestAuthServiceLoginFailureCasesAreIndistinguishable:
    def test_wrong_password_raises_invalid_credentials(self, db_session, auth_service, verified_user):
        with pytest.raises(InvalidCredentialsError):
            auth_service.login(email="verified.user@example.com", password="wrong-password")

    def test_unknown_email_raises_the_same_invalid_credentials_error(self, db_session, auth_service):
        with pytest.raises(InvalidCredentialsError):
            auth_service.login(email="nobody.here@example.com", password="anything")

    def test_unverified_email_raises_invalid_credentials(self, db_session, auth_service, buyer_role):
        user_repo = UserRepository(db_session)
        user_repo.create(
            email="unverified@example.com",
            password_hash=hash_password("correct-password-123"),
            role_id=buyer_role.id,
        )
        db_session.flush()

        with pytest.raises(InvalidCredentialsError):
            auth_service.login(email="unverified@example.com", password="correct-password-123")

    def test_deactivated_account_raises_invalid_credentials(
        self, db_session, auth_service, verified_user
    ):
        user_repo = UserRepository(db_session)
        user_repo.set_active(verified_user.id, False)
        db_session.flush()

        with pytest.raises(InvalidCredentialsError):
            auth_service.login(email="verified.user@example.com", password="correct-password-123")


class TestAuthServiceLoginLockout:
    def test_account_locks_after_max_failed_attempts(self, db_session, auth_service, verified_user):
        for _ in range(MAX_FAILED_LOGIN_ATTEMPTS):
            with pytest.raises(InvalidCredentialsError):
                auth_service.login(email="verified.user@example.com", password="wrong-password")

        # The account is now locked — even the CORRECT password must be rejected,
        # and with a distinct error type, per Section 6's 423 design.
        with pytest.raises(AccountLockedError):
            auth_service.login(email="verified.user@example.com", password="correct-password-123")

    def test_locked_account_error_exposes_locked_until(self, db_session, auth_service, verified_user):
        for _ in range(MAX_FAILED_LOGIN_ATTEMPTS):
            with pytest.raises(InvalidCredentialsError):
                auth_service.login(email="verified.user@example.com", password="wrong-password")

        with pytest.raises(AccountLockedError) as exc_info:
            auth_service.login(email="verified.user@example.com", password="wrong-password")

        assert exc_info.value.locked_until > datetime.now(timezone.utc)

    def test_login_below_the_threshold_does_not_lock_the_account(
        self, db_session, auth_service, verified_user
    ):
        for _ in range(MAX_FAILED_LOGIN_ATTEMPTS - 1):
            with pytest.raises(InvalidCredentialsError):
                auth_service.login(email="verified.user@example.com", password="wrong-password")

        # One attempt below the threshold — correct password should still work.
        access_token, raw_refresh_token, user = auth_service.login(
            email="verified.user@example.com", password="correct-password-123"
        )
        assert user.id == verified_user.id
