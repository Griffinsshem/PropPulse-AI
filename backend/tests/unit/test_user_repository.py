from __future__ import annotations

import uuid

import pytest

from app.models.role import Role
from app.repositories.user_repository import UserRepository


@pytest.fixture
def sample_role(db_session):
    """Creates a real Role row each test can attach users to.
    Rolled back automatically by the db_session fixture, so this
    never leaks between tests."""
    role = Role(name=f"test-role-{uuid.uuid4()}", description="for tests")
    db_session.add(role)
    db_session.flush()
    return role


class TestUserRepositoryCreateAndFetch:
    def test_create_persists_a_user_with_expected_defaults(self, db_session, sample_role):
        repo = UserRepository(db_session)

        user = repo.create(
            email="new.user@example.com",
            password_hash="argon2-hash-placeholder",
            role_id=sample_role.id,
        )

        assert user.id is not None
        assert user.email == "new.user@example.com"
        assert user.is_email_verified is False
        assert user.is_active is True
        assert user.failed_login_attempts == 0

    def test_get_by_email_is_case_insensitive(self, db_session, sample_role):
        repo = UserRepository(db_session)
        repo.create(
            email="CaseTest@Example.com",
            password_hash="hash",
            role_id=sample_role.id,
        )

        found = repo.get_by_email("casetest@example.com")

        assert found is not None
        assert found.email == "CaseTest@Example.com"

    def test_get_by_email_returns_none_for_unknown_email(self, db_session):
        repo = UserRepository(db_session)

        found = repo.get_by_email("does-not-exist@example.com")

        assert found is None

    def test_get_by_email_excludes_soft_deleted_users(self, db_session, sample_role):
        repo = UserRepository(db_session)
        user = repo.create(
            email="deleted.user@example.com",
            password_hash="hash",
            role_id=sample_role.id,
        )
        db_session.flush()
        repo.soft_delete(user.id, when=user.created_at)
        db_session.flush()

        found = repo.get_by_email("deleted.user@example.com")

        assert found is None


class TestUserRepositoryFailedLoginTracking:
    def test_increment_failed_attempts_increases_count(self, db_session, sample_role):
        repo = UserRepository(db_session)
        user = repo.create(email="a@example.com", password_hash="h", role_id=sample_role.id)
        db_session.flush()

        repo.increment_failed_attempts(user.id)
        repo.increment_failed_attempts(user.id)
        db_session.flush()

        refreshed = repo.get_by_id(user.id)
        assert refreshed.failed_login_attempts == 2

    def test_reset_failed_attempts_clears_count_and_lock(self, db_session, sample_role):
        repo = UserRepository(db_session)
        user = repo.create(email="b@example.com", password_hash="h", role_id=sample_role.id)
        db_session.flush()
        repo.increment_failed_attempts(user.id)
        db_session.flush()

        repo.reset_failed_attempts(user.id)
        db_session.flush()

        refreshed = repo.get_by_id(user.id)
        assert refreshed.failed_login_attempts == 0
        assert refreshed.locked_until is None


class TestUserRepositoryPagination:
    def test_list_paginated_returns_correct_total_across_multiple_pages(
        self, db_session, sample_role
    ):
        """This is the test that specifically catches the bug we
        found and fixed earlier: total must reflect ALL matching
        rows, not just the count on the current page."""
        repo = UserRepository(db_session)
        for i in range(5):
            repo.create(
                email=f"page.user{i}@example.com",
                password_hash="h",
                role_id=sample_role.id,
            )
        db_session.flush()

        page_1_results, total = repo.list_paginated(page=1, per_page=2)

        assert len(page_1_results) == 2
        assert total == 5

    def test_list_paginated_filters_by_role_id(self, db_session, sample_role):
        repo = UserRepository(db_session)
        other_role = Role(name=f"other-role-{uuid.uuid4()}")
        db_session.add(other_role)
        db_session.flush()

        repo.create(email="in.role@example.com", password_hash="h", role_id=sample_role.id)
        repo.create(email="other.role@example.com", password_hash="h", role_id=other_role.id)
        db_session.flush()

        results, total = repo.list_paginated(page=1, per_page=10, role_id=sample_role.id)

        assert total == 1
        assert results[0].email == "in.role@example.com"
