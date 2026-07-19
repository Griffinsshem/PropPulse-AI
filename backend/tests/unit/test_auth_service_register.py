from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from app.core.security import hash_token
from app.models.email_verification_token import EmailVerificationToken
from app.models.role import Role
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.role_repository import RoleRepository
from app.repositories.user_repository import UserRepository
from app.services.auth_service import (
    AuthService,
    EmailAlreadyRegisteredError,
    RoleNotFoundError,
)


class SpyEmailSender:
    """A test double that records every call instead of sending a
    real email, so tests can assert on exactly what would have been
    sent — including the raw (unhashed) token, which only exists
    transiently and is never persisted anywhere."""

    def __init__(self) -> None:
        self.verification_emails_sent: list[dict] = []
        self.reset_emails_sent: list[dict] = []

    def send_verification_email(self, *, to_email: str, raw_token: str) -> None:
        self.verification_emails_sent.append({"to_email": to_email, "raw_token": raw_token})

    def send_password_reset_email(self, *, to_email: str, raw_token: str) -> None:
        self.reset_emails_sent.append({"to_email": to_email, "raw_token": raw_token})


@pytest.fixture
def buyer_role(db_session):
    role = Role(name=f"buyer-{uuid.uuid4()}")
    db_session.add(role)
    db_session.flush()
    return role


@pytest.fixture
def auth_service(db_session):
    """Builds a real AuthService wired to real repositories against
    the real (rolled-back) test database, but with a SpyEmailSender
    instead of a real email provider — this is the Adapter Pattern
    payoff described in Section 7: swapping one dependency without
    touching AuthService itself."""
    service = AuthService(
        session=db_session,
        user_repo=UserRepository(db_session),
        role_repo=RoleRepository(db_session),
        audit_repo=AuditLogRepository(db_session),
        email_sender=SpyEmailSender(),
    )
    return service


class TestAuthServiceRegister:
    def test_register_creates_a_user_with_hashed_password(self, db_session, auth_service, buyer_role):
        user = auth_service.register(
            email="new.buyer@example.com", password="a-real-password-123", role_name=buyer_role.name
        )

        assert user.id is not None
        assert user.email == "new.buyer@example.com"
        assert user.password_hash != "a-real-password-123"  # never stored in plain text
        assert user.is_email_verified is False

    def test_register_raises_for_unknown_role(self, db_session, auth_service):
        with pytest.raises(RoleNotFoundError):
            auth_service.register(
                email="someone@example.com", password="a-real-password-123", role_name="not-a-real-role"
            )

    def test_register_raises_for_duplicate_email(self, db_session, auth_service, buyer_role):
        auth_service.register(
            email="duplicate@example.com", password="a-real-password-123", role_name=buyer_role.name
        )

        with pytest.raises(EmailAlreadyRegisteredError):
            auth_service.register(
                email="duplicate@example.com", password="another-password-456", role_name=buyer_role.name
            )

    def test_register_creates_a_valid_email_verification_token(
        self, db_session, auth_service, buyer_role
    ):
        user = auth_service.register(
            email="verify.me@example.com", password="a-real-password-123", role_name=buyer_role.name
        )


        # Confirm exactly one verification token exists for this user,
        # and it is currently valid (not expired, not used).
        stored_tokens = (
            db_session.query(EmailVerificationToken)
            .filter(EmailVerificationToken.user_id == user.id)
            .all()
        )
        assert len(stored_tokens) == 1
        assert stored_tokens[0].used_at is None
        assert stored_tokens[0].expires_at > datetime.now(timezone.utc)

    def test_register_sends_a_verification_email_with_a_token_that_matches_the_stored_hash(
        self, db_session, auth_service, buyer_role
    ):
        """This is the most important test in this file: it proves
        the raw token emailed to the user actually corresponds to
        what we stored (hashed) in the database — i.e. the user
        will actually be able to verify their email with the link
        they receive."""
        spy = auth_service._email_sender  # test-only introspection of the injected dependency
        user = auth_service.register(
            email="check.token@example.com", password="a-real-password-123", role_name=buyer_role.name
        )

        assert len(spy.verification_emails_sent) == 1
        sent = spy.verification_emails_sent[0]
        assert sent["to_email"] == "check.token@example.com"

        stored_token = (
            db_session.query(EmailVerificationToken)
            .filter(EmailVerificationToken.user_id == user.id)
            .one()
        )
        assert stored_token.token_hash == hash_token(sent["raw_token"])

    def test_register_writes_an_audit_log_entry(self, db_session, auth_service, buyer_role):
        from app.models.audit_log import AuditLog

        user = auth_service.register(
            email="audited.registration@example.com",
            password="a-real-password-123",
            role_name=buyer_role.name,
        )

        entries = db_session.query(AuditLog).filter(AuditLog.user_id == user.id).all()

        assert len(entries) == 1
        assert entries[0].event_type == "user_registered"
