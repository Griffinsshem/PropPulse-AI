from __future__ import annotations

import uuid

import pytest

from app.core.security import hash_password, hash_token
from app.models.audit_log import AuditLog
from app.models.role import Role
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.repositories.role_repository import RoleRepository
from app.repositories.user_repository import UserRepository
from app.services.auth_service import AuthService

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
def refresh_token_repo(db_session):
    return RefreshTokenRepository(db_session)


@pytest.fixture
def auth_service(db_session, refresh_token_repo):
    return AuthService(
        session=db_session,
        user_repo=UserRepository(db_session),
        role_repo=RoleRepository(db_session),
        refresh_token_repo=refresh_token_repo,
        audit_repo=AuditLogRepository(db_session),
        email_sender=SpyEmailSender(),
        jwt_secret_key=TEST_JWT_SECRET,
    )


@pytest.fixture
def logged_in_user_with_token(db_session, buyer_role, auth_service):
    user_repo = UserRepository(db_session)
    user = user_repo.create(
        email="logout.test@example.com",
        password_hash=hash_password("correct-password-123"),
        role_id=buyer_role.id,
    )
    user_repo.set_email_verified(user.id)
    db_session.flush()

    _, raw_refresh_token, _ = auth_service.login(
        email="logout.test@example.com", password="correct-password-123"
    )
    return user, raw_refresh_token


class TestAuthServiceLogout:
    def test_logout_revokes_the_presented_token(
        self, db_session, auth_service, refresh_token_repo, logged_in_user_with_token
    ):
        _, raw_refresh_token = logged_in_user_with_token

        auth_service.logout(raw_refresh_token=raw_refresh_token)

        token = refresh_token_repo.get_by_token_hash(hash_token(raw_refresh_token))
        assert token.is_revoked is True

    def test_logout_with_unknown_token_does_not_raise(self, db_session, auth_service):
        """Confirms the idempotent-by-design behavior: logging out
        with a token that was never issued should be a silent
        no-op, not an error."""
        auth_service.logout(raw_refresh_token="never-issued-token")  # should not raise

    def test_logout_writes_an_audit_entry(self, db_session, auth_service, logged_in_user_with_token):
        user, raw_refresh_token = logged_in_user_with_token

        auth_service.logout(raw_refresh_token=raw_refresh_token)

        entries = db_session.query(AuditLog).filter(AuditLog.user_id == user.id).all()
        assert any(e.event_type == "logout" for e in entries)

    def test_logout_with_unknown_token_writes_no_audit_entry(self, db_session, auth_service):
        """Since there's no known user tied to a bogus token, there
        is nothing meaningful to log against — confirms logout()
        doesn't attempt to record an entry with a garbage reference."""
        initial_count = db_session.query(AuditLog).count()

        auth_service.logout(raw_refresh_token="never-issued-token")

        assert db_session.query(AuditLog).count() == initial_count


class TestAuthServiceLogoutAll:
    def test_logout_all_revokes_every_token_across_multiple_families(
        self, db_session, auth_service, refresh_token_repo, buyer_role
    ):
        """Simulates a user logged in on two different devices
        (two separate families from two separate login() calls),
        then confirms logout_all revokes both."""
        user_repo = UserRepository(db_session)
        user = user_repo.create(
            email="multi.device@example.com",
            password_hash=hash_password("correct-password-123"),
            role_id=buyer_role.id,
        )
        user_repo.set_email_verified(user.id)
        db_session.flush()

        _, raw_token_device_1, _ = auth_service.login(
            email="multi.device@example.com", password="correct-password-123"
        )
        _, raw_token_device_2, _ = auth_service.login(
            email="multi.device@example.com", password="correct-password-123"
        )

        auth_service.logout_all(user_id=user.id)

        token_1 = refresh_token_repo.get_by_token_hash(hash_token(raw_token_device_1))
        token_2 = refresh_token_repo.get_by_token_hash(hash_token(raw_token_device_2))
        assert token_1.is_revoked is True
        assert token_2.is_revoked is True

    def test_logout_all_does_not_affect_a_different_users_tokens(
        self, db_session, auth_service, refresh_token_repo, buyer_role
    ):
        user_repo = UserRepository(db_session)
        user_a = user_repo.create(
            email="user.a@example.com",
            password_hash=hash_password("pw"),
            role_id=buyer_role.id,
        )
        user_repo.set_email_verified(user_a.id)
        user_b = user_repo.create(
            email="user.b@example.com",
            password_hash=hash_password("pw"),
            role_id=buyer_role.id,
        )
        user_repo.set_email_verified(user_b.id)
        db_session.flush()

        _, raw_token_a, _ = auth_service.login(email="user.a@example.com", password="pw")
        _, raw_token_b, _ = auth_service.login(email="user.b@example.com", password="pw")

        auth_service.logout_all(user_id=user_a.id)

        token_a = refresh_token_repo.get_by_token_hash(hash_token(raw_token_a))
        token_b = refresh_token_repo.get_by_token_hash(hash_token(raw_token_b))
        assert token_a.is_revoked is True
        assert token_b.is_revoked is False

    def test_logout_all_writes_a_logout_all_audit_entry(
        self, db_session, auth_service, logged_in_user_with_token
    ):
        user, _ = logged_in_user_with_token

        auth_service.logout_all(user_id=user.id)

        entries = db_session.query(AuditLog).filter(AuditLog.user_id == user.id).all()
        assert any(e.event_type == "logout_all" for e in entries)
