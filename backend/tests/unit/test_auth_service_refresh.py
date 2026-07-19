from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.core.security import hash_password, hash_token
from app.models.audit_log import AuditLog
from app.models.role import Role
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.repositories.role_repository import RoleRepository
from app.repositories.user_repository import UserRepository
from app.services.auth_service import AuthService, InvalidRefreshTokenError

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
    """Registers, verifies, and logs in a user, returning both the
    user and the raw refresh token issued at login — the starting
    point every refresh() test needs."""
    user_repo = UserRepository(db_session)
    user = user_repo.create(
        email="refresh.test@example.com",
        password_hash=hash_password("correct-password-123"),
        role_id=buyer_role.id,
    )
    user_repo.set_email_verified(user.id)
    db_session.flush()

    _, raw_refresh_token, _ = auth_service.login(
        email="refresh.test@example.com", password="correct-password-123"
    )
    return user, raw_refresh_token


class TestAuthServiceRefreshHappyPath:
    def test_refresh_returns_a_new_access_and_refresh_token(
        self, db_session, auth_service, logged_in_user_with_token
    ):
        _, raw_refresh_token = logged_in_user_with_token

        new_access_token, new_raw_refresh_token = auth_service.refresh(
            raw_refresh_token=raw_refresh_token
        )

        assert isinstance(new_access_token, str) and len(new_access_token) > 0
        assert isinstance(new_raw_refresh_token, str) and len(new_raw_refresh_token) > 0
        assert new_raw_refresh_token != raw_refresh_token

    def test_refresh_revokes_the_old_token(
        self, db_session, auth_service, refresh_token_repo, logged_in_user_with_token
    ):
        _, raw_refresh_token = logged_in_user_with_token

        auth_service.refresh(raw_refresh_token=raw_refresh_token)

        old_token = refresh_token_repo.get_by_token_hash(hash_token(raw_refresh_token))
        assert old_token.is_revoked is True

    def test_refresh_preserves_family_id_across_rotation(
        self, db_session, auth_service, refresh_token_repo, logged_in_user_with_token
    ):
        """This is the property that makes theft detection work at
        all: rotated tokens must stay linked to their original
        login's family, or a later reuse could never be traced back
        to 'which sessions need to be revoked.'"""
        _, raw_refresh_token = logged_in_user_with_token
        old_token = refresh_token_repo.get_by_token_hash(hash_token(raw_refresh_token))
        original_family_id = old_token.family_id

        _, new_raw_refresh_token = auth_service.refresh(raw_refresh_token=raw_refresh_token)

        new_token = refresh_token_repo.get_by_token_hash(hash_token(new_raw_refresh_token))
        assert new_token.family_id == original_family_id

    def test_refresh_writes_a_token_refreshed_audit_entry(
        self, db_session, auth_service, logged_in_user_with_token
    ):
        user, raw_refresh_token = logged_in_user_with_token

        auth_service.refresh(raw_refresh_token=raw_refresh_token)

        entries = db_session.query(AuditLog).filter(AuditLog.user_id == user.id).all()
        assert any(e.event_type == "token_refreshed" for e in entries)


class TestAuthServiceRefreshRejectsInvalidTokens:
    def test_refresh_rejects_a_completely_unknown_token(self, db_session, auth_service):
        with pytest.raises(InvalidRefreshTokenError):
            auth_service.refresh(raw_refresh_token="this-token-was-never-issued")

    def test_refresh_rejects_an_expired_token(
        self, db_session, auth_service, refresh_token_repo, buyer_role
    ):
        user_repo = UserRepository(db_session)
        user = user_repo.create(
            email="expired.token.user@example.com",
            password_hash=hash_password("pw"),
            role_id=buyer_role.id,
        )
        db_session.flush()

        raw_token = "an-already-expired-raw-token"
        refresh_token_repo.create(
            user_id=user.id,
            token_hash=hash_token(raw_token),
            family_id=uuid.uuid4(),
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),  # already expired
        )
        db_session.flush()

        with pytest.raises(InvalidRefreshTokenError):
            auth_service.refresh(raw_refresh_token=raw_token)


class TestAuthServiceRefreshTheftDetection:
    def test_reusing_an_already_rotated_token_raises_and_revokes_the_whole_family(
        self, db_session, auth_service, refresh_token_repo, logged_in_user_with_token
    ):
        """The core theft-detection test: rotate once (token A ->
        token B, both in the same family), then try to reuse token A
        (simulating an attacker who stole it before rotation). This
        must be rejected AND must revoke token B as well, even
        though token B was never directly involved in the attack."""
        user, raw_token_a = logged_in_user_with_token

        _, raw_token_b = auth_service.refresh(raw_refresh_token=raw_token_a)

        # Attacker (or a confused client) replays the OLD token A.
        with pytest.raises(InvalidRefreshTokenError):
            auth_service.refresh(raw_refresh_token=raw_token_a)

        # Token B, though never directly reused, must now ALSO be revoked,
        # since it belongs to the same compromised family.
        token_b = refresh_token_repo.get_by_token_hash(hash_token(raw_token_b))
        assert token_b.is_revoked is True

    def test_theft_detection_writes_a_distinct_audit_event(
        self, db_session, auth_service, logged_in_user_with_token
    ):
        user, raw_token_a = logged_in_user_with_token
        auth_service.refresh(raw_refresh_token=raw_token_a)

        with pytest.raises(InvalidRefreshTokenError):
            auth_service.refresh(raw_refresh_token=raw_token_a)

        entries = db_session.query(AuditLog).filter(AuditLog.user_id == user.id).all()
        assert any(e.event_type == "refresh_token_reuse_detected" for e in entries)

    def test_theft_detection_does_not_affect_a_different_users_tokens(
        self, db_session, auth_service, refresh_token_repo, buyer_role, logged_in_user_with_token
    ):
        """Confirms family-scoped revocation doesn't accidentally
        spill over to an unrelated user's active session."""
        _, raw_token_a = logged_in_user_with_token

        other_user_repo = UserRepository(db_session)
        other_user = other_user_repo.create(
            email="unrelated.user@example.com",
            password_hash=hash_password("pw"),
            role_id=buyer_role.id,
        )
        other_user_repo.set_email_verified(other_user.id)
        db_session.flush()

        _, other_raw_token, _ = auth_service.login(
            email="unrelated.user@example.com", password="pw"
        )

        # Trigger theft detection on the FIRST user's family.
        auth_service.refresh(raw_refresh_token=raw_token_a)
        with pytest.raises(InvalidRefreshTokenError):
            auth_service.refresh(raw_refresh_token=raw_token_a)

        # The unrelated user's token must remain completely unaffected.
        other_token = refresh_token_repo.get_by_token_hash(hash_token(other_raw_token))
        assert other_token.is_revoked is False
