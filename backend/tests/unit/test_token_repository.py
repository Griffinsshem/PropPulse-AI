from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.models.email_verification_token import EmailVerificationToken
from app.models.password_reset_token import PasswordResetToken
from app.models.role import Role
from app.repositories.token_repository import TokenRepository
from app.repositories.user_repository import UserRepository


@pytest.fixture
def sample_user(db_session):
    role = Role(name=f"test-role-{uuid.uuid4()}")
    db_session.add(role)
    db_session.flush()

    user_repo = UserRepository(db_session)
    user = user_repo.create(email="token.test@example.com", password_hash="h", role_id=role.id)
    db_session.flush()
    return user


# Parameterizing over both model types proves the SAME repository
# class genuinely works correctly for both tables, rather than us
# just asserting it does in a docstring.
@pytest.mark.parametrize("model", [EmailVerificationToken, PasswordResetToken])
class TestTokenRepositoryAcrossBothModels:
    def test_create_persists_a_token(self, db_session, sample_user, model):
        repo = TokenRepository(db_session, model)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        token = repo.create(
            user_id=sample_user.id,
            token_hash="some-hash-value",
            expires_at=expires_at,
        )

        assert token.id is not None
        assert token.used_at is None

    def test_get_valid_by_token_hash_finds_unexpired_unused_token(
        self, db_session, sample_user, model
    ):
        repo = TokenRepository(db_session, model)
        now = datetime.now(timezone.utc)
        repo.create(user_id=sample_user.id, token_hash="valid-hash", expires_at=now + timedelta(hours=1))
        db_session.flush()

        found = repo.get_valid_by_token_hash("valid-hash", now=now)

        assert found is not None
        assert found.token_hash == "valid-hash"

    def test_get_valid_by_token_hash_rejects_expired_token(self, db_session, sample_user, model):
        repo = TokenRepository(db_session, model)
        now = datetime.now(timezone.utc)
        repo.create(
            user_id=sample_user.id,
            token_hash="expired-hash",
            expires_at=now - timedelta(minutes=1),  # already in the past
        )
        db_session.flush()

        found = repo.get_valid_by_token_hash("expired-hash", now=now)

        assert found is None

    def test_get_valid_by_token_hash_rejects_already_used_token(
        self, db_session, sample_user, model
    ):
        repo = TokenRepository(db_session, model)
        now = datetime.now(timezone.utc)
        token = repo.create(
            user_id=sample_user.id, token_hash="used-hash", expires_at=now + timedelta(hours=1)
        )
        db_session.flush()
        repo.mark_used(token.id, when=now)
        db_session.flush()

        found = repo.get_valid_by_token_hash("used-hash", now=now)

        assert found is None

    def test_mark_used_sets_used_at_timestamp(self, db_session, sample_user, model):
        repo = TokenRepository(db_session, model)
        now = datetime.now(timezone.utc)
        token = repo.create(
            user_id=sample_user.id, token_hash="mark-me", expires_at=now + timedelta(hours=1)
        )
        db_session.flush()

        repo.mark_used(token.id, when=now)
        db_session.flush()

        refreshed = db_session.get(model, token.id)
        assert refreshed.used_at is not None


class TestTokenRepositoryPasswordResetSpecifics:
    def test_password_reset_token_stores_ip_address(self, db_session, sample_user):
        repo = TokenRepository(db_session, PasswordResetToken)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        token = repo.create(
            user_id=sample_user.id,
            token_hash="ip-tracked-hash",
            expires_at=expires_at,
            ip_address="198.51.100.7",
        )

        assert token.ip_address == "198.51.100.7"
