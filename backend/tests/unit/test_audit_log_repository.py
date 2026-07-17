from __future__ import annotations

import uuid

import pytest

from app.models.role import Role
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.user_repository import UserRepository


@pytest.fixture
def sample_user(db_session):
    role = Role(name=f"test-role-{uuid.uuid4()}")
    db_session.add(role)
    db_session.flush()

    user_repo = UserRepository(db_session)
    user = user_repo.create(email="audited.user@example.com", password_hash="h", role_id=role.id)
    db_session.flush()
    return user


class TestAuditLogRepository:
    def test_record_persists_an_entry_with_expected_fields(self, db_session, sample_user):
        repo = AuditLogRepository(db_session)

        entry = repo.record(
            user_id=sample_user.id,
            event_type="login_success",
            ip_address="203.0.113.10",
            metadata={"method": "password"},
        )

        assert entry.id is not None
        assert entry.event_type == "login_success"
        assert entry.event_metadata == {"method": "password"}

    def test_record_allows_null_user_id_for_anonymous_events(self, db_session):
        """Covers the ON DELETE SET NULL design from Section 5 —
        the repository must accept a null user_id, since that's
        exactly the state a log entry ends up in after its user is
        hard-deleted."""
        repo = AuditLogRepository(db_session)

        entry = repo.record(user_id=None, event_type="login_failure")

        assert entry.id is not None
        assert entry.user_id is None

    def test_audit_log_repository_exposes_no_update_or_delete_methods(self):
        """Structural test confirming the append-only rule: this
        repository must never grow an update/delete method by
        accident in a future edit."""
        public_methods = [m for m in dir(AuditLogRepository) if not m.startswith("_")]
        assert public_methods == ["record"]
