from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.models.role import Role
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.repositories.user_repository import UserRepository


@pytest.fixture
def sample_user(db_session):
    role = Role(name=f"test-role-{uuid.uuid4()}")
    db_session.add(role)
    db_session.flush()

    user_repo = UserRepository(db_session)
    user = user_repo.create(email="token.owner@example.com", password_hash="h", role_id=role.id)
    db_session.flush()
    return user


class TestRefreshTokenRepositoryCreateAndFetch:
    def test_create_persists_token_with_family_id(self, db_session, sample_user):
        repo = RefreshTokenRepository(db_session)
        family_id = uuid.uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)

        token = repo.create(
            user_id=sample_user.id,
            token_hash="hashed-token-value",
            family_id=family_id,
            expires_at=expires_at,
        )

        assert token.id is not None
        assert token.family_id == family_id
        assert token.is_revoked is False

    def test_get_by_token_hash_finds_the_right_token(self, db_session, sample_user):
        repo = RefreshTokenRepository(db_session)
        repo.create(
            user_id=sample_user.id,
            token_hash="unique-hash-abc",
            family_id=uuid.uuid4(),
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )

        found = repo.get_by_token_hash("unique-hash-abc")

        assert found is not None
        assert found.token_hash == "unique-hash-abc"

    def test_get_by_token_hash_returns_none_for_unknown_hash(self, db_session):
        repo = RefreshTokenRepository(db_session)

        found = repo.get_by_token_hash("does-not-exist")

        assert found is None


class TestRefreshTokenRepositoryRevocation:
    def test_revoke_marks_single_token_revoked(self, db_session, sample_user):
        repo = RefreshTokenRepository(db_session)
        token = repo.create(
            user_id=sample_user.id,
            token_hash="hash-1",
            family_id=uuid.uuid4(),
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )
        db_session.flush()

        repo.revoke(token.id, when=datetime.now(timezone.utc))
        db_session.flush()

        refreshed = repo.get_by_token_hash("hash-1")
        assert refreshed.is_revoked is True
        assert refreshed.revoked_at is not None

    def test_revoke_family_revokes_all_tokens_sharing_family_id_but_not_others(
        self, db_session, sample_user
    ):
        """This is the theft-detection mechanism from Section 5/6:
        revoking a family must not touch tokens from a different
        family, even for the same user."""
        repo = RefreshTokenRepository(db_session)
        family_a = uuid.uuid4()
        family_b = uuid.uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)

        repo.create(user_id=sample_user.id, token_hash="a1", family_id=family_a, expires_at=expires_at)
        repo.create(user_id=sample_user.id, token_hash="a2", family_id=family_a, expires_at=expires_at)
        repo.create(user_id=sample_user.id, token_hash="b1", family_id=family_b, expires_at=expires_at)
        db_session.flush()

        repo.revoke_family(family_a, when=datetime.now(timezone.utc))
        db_session.flush()

        assert repo.get_by_token_hash("a1").is_revoked is True
        assert repo.get_by_token_hash("a2").is_revoked is True
        assert repo.get_by_token_hash("b1").is_revoked is False

    def test_revoke_all_for_user_revokes_across_every_family(self, db_session, sample_user):
        repo = RefreshTokenRepository(db_session)
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)

        repo.create(user_id=sample_user.id, token_hash="x1", family_id=uuid.uuid4(), expires_at=expires_at)
        repo.create(user_id=sample_user.id, token_hash="x2", family_id=uuid.uuid4(), expires_at=expires_at)
        db_session.flush()

        repo.revoke_all_for_user(sample_user.id, when=datetime.now(timezone.utc))
        db_session.flush()

        assert repo.get_by_token_hash("x1").is_revoked is True
        assert repo.get_by_token_hash("x2").is_revoked is True
