from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.core.security import generate_secure_token, hash_password, hash_token
from app.models.audit_log import AuditLog
from app.models.email_verification_token import EmailVerificationToken
from app.models.role import Role
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.repositories.role_repository import RoleRepository
from app.repositories.token_repository import TokenRepository
from app.repositories.user_repository import UserRepository
from app.services.auth_service import AuthService, InvalidVerificationTokenError

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
def email_verification_repo(db_session):
    return TokenRepository(db_session, EmailVerificationToken)


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
def unverified_user_with_token(db_session, buyer_role, email_verification_repo):
    """A freshly-registered-style user: NOT yet email-verified,
    with a real, valid verification token issued directly against
    the repository (bypassing register() itself, since we only want
    to test verify_email() here, not re-test registration)."""
    user_repo = UserRepository(db_session)
    user = user_repo.create(
        email="verify.this@example.com",
        password_hash=hash_password("pw"),
        role_id=buyer_role.id,
    )
    db_session.flush()

    raw_token = generate_secure_token()
    email_verification_repo.create(
        user_id=user.id,
        token_hash=hash_token(raw_token),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    db_session.flush()
    return user, raw_token


class TestAuthServiceVerifyEmail:
    def test_verify_email_with_a_valid_token_marks_user_verified(
        self, db_session, auth_service, unverified_user_with_token
    ):
        user, raw_token = unverified_user_with_token

        auth_service.verify_email(raw_token=raw_token)

        user_repo = UserRepository(db_session)
        refreshed = user_repo.get_by_id(user.id)
        assert refreshed.is_email_verified is True

    def test_verify_email_marks_the_token_as_used(
        self, db_session, auth_service, email_verification_repo, unverified_user_with_token
    ):
        _, raw_token = unverified_user_with_token

        auth_service.verify_email(raw_token=raw_token)

        now = datetime.now(timezone.utc)
        # get_valid_by_token_hash excludes used tokens, so this must now be None.
        found = email_verification_repo.get_valid_by_token_hash(hash_token(raw_token), now=now)
        assert found is None

    def test_verify_email_writes_an_audit_entry(
        self, db_session, auth_service, unverified_user_with_token
    ):
        user, raw_token = unverified_user_with_token

        auth_service.verify_email(raw_token=raw_token)

        entries = db_session.query(AuditLog).filter(AuditLog.user_id == user.id).all()
        assert any(e.event_type == "email_verified" for e in entries)

    def test_verify_email_rejects_an_unknown_token(self, db_session, auth_service):
        with pytest.raises(InvalidVerificationTokenError):
            auth_service.verify_email(raw_token="this-token-was-never-issued")

    def test_verify_email_rejects_an_expired_token(
        self, db_session, auth_service, buyer_role, email_verification_repo
    ):
        user_repo = UserRepository(db_session)
        user = user_repo.create(
            email="expired.verify@example.com",
            password_hash=hash_password("pw"),
            role_id=buyer_role.id,
        )
        db_session.flush()

        raw_token = generate_secure_token()
        email_verification_repo.create(
            user_id=user.id,
            token_hash=hash_token(raw_token),
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),  # already expired
        )
        db_session.flush()

        with pytest.raises(InvalidVerificationTokenError):
            auth_service.verify_email(raw_token=raw_token)

    def test_verify_email_rejects_reusing_an_already_used_token(
        self, db_session, auth_service, unverified_user_with_token
    ):
        """Simulates clicking the same verification link twice —
        the second attempt must fail, not silently re-verify."""
        _, raw_token = unverified_user_with_token

        auth_service.verify_email(raw_token=raw_token)  # first use succeeds

        with pytest.raises(InvalidVerificationTokenError):
            auth_service.verify_email(raw_token=raw_token)  # second use must fail
