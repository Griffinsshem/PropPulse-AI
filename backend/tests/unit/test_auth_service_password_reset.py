from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.core.security import generate_secure_token, hash_password, hash_token, verify_password
from app.models.audit_log import AuditLog
from app.models.password_reset_token import PasswordResetToken
from app.models.role import Role
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.repositories.role_repository import RoleRepository
from app.repositories.token_repository import TokenRepository
from app.repositories.user_repository import UserRepository
from app.services.auth_service import AuthService, InvalidResetTokenError

TEST_JWT_SECRET = "test-secret-key-not-used-in-production-32b"


class SpyEmailSender:
    def __init__(self) -> None:
        self.reset_emails_sent: list[dict] = []

    def send_verification_email(self, *, to_email: str, raw_token: str) -> None:
        pass

    def send_password_reset_email(self, *, to_email: str, raw_token: str) -> None:
        self.reset_emails_sent.append({"to_email": to_email, "raw_token": raw_token})


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
def password_reset_repo(db_session):
    return TokenRepository(db_session, PasswordResetToken)


@pytest.fixture
def spy_email_sender():
    return SpyEmailSender()


@pytest.fixture
def auth_service(db_session, refresh_token_repo, spy_email_sender):
    return AuthService(
        session=db_session,
        user_repo=UserRepository(db_session),
        role_repo=RoleRepository(db_session),
        refresh_token_repo=refresh_token_repo,
        audit_repo=AuditLogRepository(db_session),
        email_sender=spy_email_sender,
        jwt_secret_key=TEST_JWT_SECRET,
    )


@pytest.fixture
def existing_user(db_session, buyer_role):
    user_repo = UserRepository(db_session)
    user = user_repo.create(
        email="reset.me@example.com",
        password_hash=hash_password("old-password-123"),
        role_id=buyer_role.id,
    )
    user_repo.set_email_verified(user.id)
    db_session.flush()
    return user


class TestRequestPasswordReset:
    def test_request_for_existing_email_creates_a_token_and_sends_email(
        self, db_session, auth_service, spy_email_sender, existing_user, password_reset_repo
    ):
        auth_service.request_password_reset(email="reset.me@example.com")

        assert len(spy_email_sender.reset_emails_sent) == 1
        sent = spy_email_sender.reset_emails_sent[0]
        assert sent["to_email"] == "reset.me@example.com"

        now = datetime.now(timezone.utc)
        found = password_reset_repo.get_valid_by_token_hash(hash_token(sent["raw_token"]), now=now)
        assert found is not None
        assert found.user_id == existing_user.id

    def test_request_for_existing_email_writes_an_audit_entry(
        self, db_session, auth_service, existing_user
    ):
        auth_service.request_password_reset(email="reset.me@example.com")

        entries = db_session.query(AuditLog).filter(AuditLog.user_id == existing_user.id).all()
        assert any(e.event_type == "password_reset_requested" for e in entries)

    def test_request_for_unknown_email_does_not_raise_and_sends_no_email(
        self, db_session, auth_service, spy_email_sender
    ):
        """Core enumeration-safety property: calling this with an
        email that has no account must behave identically from the
        outside — no exception, and per our design, no email sent
        since there's no real token to deliver."""
        auth_service.request_password_reset(email="nobody.here@example.com")  # must not raise

        assert len(spy_email_sender.reset_emails_sent) == 0

    def test_request_for_unknown_email_writes_no_audit_entry(self, db_session, auth_service):
        initial_count = db_session.query(AuditLog).count()

        auth_service.request_password_reset(email="nobody.here@example.com")

        assert db_session.query(AuditLog).count() == initial_count


class TestConfirmPasswordReset:
    def test_confirm_with_valid_token_updates_the_password(
        self, db_session, auth_service, existing_user, password_reset_repo
    ):
        raw_token = generate_secure_token()
        password_reset_repo.create(
            user_id=existing_user.id,
            token_hash=hash_token(raw_token),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        )
        db_session.flush()

        auth_service.confirm_password_reset(raw_token=raw_token, new_password="brand-new-password-456")

        user_repo = UserRepository(db_session)
        refreshed = user_repo.get_by_id(existing_user.id)
        assert verify_password("brand-new-password-456", refreshed.password_hash) is True
        assert verify_password("old-password-123", refreshed.password_hash) is False

    def test_confirm_revokes_all_existing_refresh_tokens(
        self, db_session, auth_service, refresh_token_repo, password_reset_repo, existing_user
    ):
        """The key security property: an attacker's existing
        session must not survive a password reset intended to
        recover a compromised account."""
        raw_session_token = "an-existing-active-session-token"
        refresh_token_repo.create(
            user_id=existing_user.id,
            token_hash=hash_token(raw_session_token),
            family_id=uuid.uuid4(),
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        db_session.flush()

        raw_reset_token = generate_secure_token()
        password_reset_repo.create(
            user_id=existing_user.id,
            token_hash=hash_token(raw_reset_token),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        )
        db_session.flush()

        auth_service.confirm_password_reset(raw_token=raw_reset_token, new_password="new-password-789")

        existing_session = refresh_token_repo.get_by_token_hash(hash_token(raw_session_token))
        assert existing_session.is_revoked is True

    def test_confirm_marks_the_reset_token_as_used(
        self, db_session, auth_service, password_reset_repo, existing_user
    ):
        raw_token = generate_secure_token()
        password_reset_repo.create(
            user_id=existing_user.id,
            token_hash=hash_token(raw_token),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        )
        db_session.flush()

        auth_service.confirm_password_reset(raw_token=raw_token, new_password="new-password-789")

        now = datetime.now(timezone.utc)
        found = password_reset_repo.get_valid_by_token_hash(hash_token(raw_token), now=now)
        assert found is None

    def test_confirm_writes_an_audit_entry(
        self, db_session, auth_service, password_reset_repo, existing_user
    ):
        raw_token = generate_secure_token()
        password_reset_repo.create(
            user_id=existing_user.id,
            token_hash=hash_token(raw_token),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        )
        db_session.flush()

        auth_service.confirm_password_reset(raw_token=raw_token, new_password="new-password-789")

        entries = db_session.query(AuditLog).filter(AuditLog.user_id == existing_user.id).all()
        assert any(e.event_type == "password_reset_completed" for e in entries)

    def test_confirm_rejects_an_unknown_token(self, db_session, auth_service):
        with pytest.raises(InvalidResetTokenError):
            auth_service.confirm_password_reset(
                raw_token="never-issued", new_password="new-password-789"
            )

    def test_confirm_rejects_an_expired_token(
        self, db_session, auth_service, password_reset_repo, existing_user
    ):
        raw_token = generate_secure_token()
        password_reset_repo.create(
            user_id=existing_user.id,
            token_hash=hash_token(raw_token),
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        )
        db_session.flush()

        with pytest.raises(InvalidResetTokenError):
            auth_service.confirm_password_reset(raw_token=raw_token, new_password="new-password-789")

    def test_confirm_rejects_reusing_an_already_used_token(
        self, db_session, auth_service, password_reset_repo, existing_user
    ):
        raw_token = generate_secure_token()
        password_reset_repo.create(
            user_id=existing_user.id,
            token_hash=hash_token(raw_token),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        )
        db_session.flush()

        auth_service.confirm_password_reset(raw_token=raw_token, new_password="first-reset-pw")

        with pytest.raises(InvalidResetTokenError):
            auth_service.confirm_password_reset(raw_token=raw_token, new_password="second-reset-pw")
