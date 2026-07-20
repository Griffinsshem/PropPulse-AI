from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from app.schemas.auth_schemas import RegisterRequest, RegisterResponse


class TestRegisterRequestValidation:
    def test_accepts_a_well_formed_request(self):
        req = RegisterRequest(
            email="buyer@example.com", password="a-valid-password-123", role="buyer"
        )
        assert req.email == "buyer@example.com"
        assert req.role == "buyer"

    def test_strips_whitespace_from_email(self):
        req = RegisterRequest(
            email="  buyer@example.com  ", password="a-valid-password-123", role="buyer"
        )
        assert req.email == "buyer@example.com"

    def test_rejects_a_malformed_email(self):
        with pytest.raises(ValidationError):
            RegisterRequest(email="not-an-email", password="a-valid-password-123", role="buyer")

    def test_rejects_a_password_that_is_too_short(self):
        with pytest.raises(ValidationError):
            RegisterRequest(email="buyer@example.com", password="short1", role="buyer")

    def test_rejects_a_password_with_no_digit(self):
        with pytest.raises(ValidationError):
            RegisterRequest(
                email="buyer@example.com", password="all-letters-no-numbers", role="buyer"
            )

    def test_rejects_a_password_with_no_letter(self):
        with pytest.raises(ValidationError):
            RegisterRequest(email="buyer@example.com", password="123456789012", role="buyer")

    def test_rejects_an_unrecognized_role(self):
        with pytest.raises(ValidationError):
            RegisterRequest(email="buyer@example.com", password="a-valid-password-123", role="wizard")

    def test_rejects_privileged_roles_that_must_be_admin_assigned(self):
        """This is the schema-layer half of FR-1: admin, super_admin,
        bank, and government_analyst must never be self-selectable,
        even if someone crafts a request by hand rather than using
        a form that only shows the allowed options."""
        for privileged_role in ["admin", "super_admin", "bank", "government_analyst"]:
            with pytest.raises(ValidationError):
                RegisterRequest(
                    email="buyer@example.com",
                    password="a-valid-password-123",
                    role=privileged_role,
                )


class TestRegisterResponseNeverLeaksSensitiveFields:
    def test_response_only_exposes_the_declared_fields(self):
        """Simulates building a response from a real User-like object
        that has MANY more attributes (including password_hash) than
        the response schema declares. Confirms only the safe subset
        makes it through, regardless of what the source object has."""

        class FakeUserWithSensitiveFields:
            def __init__(self) -> None:
                self.id = uuid.uuid4()
                self.email = "buyer@example.com"
                self.is_email_verified = False
                self.password_hash = "argon2id$this-must-never-leak"
                self.failed_login_attempts = 0
                self.locked_until = None

        fake_user = FakeUserWithSensitiveFields()
        response = RegisterResponse.model_validate(fake_user)
        dumped = response.model_dump()

        assert "password_hash" not in dumped
        assert "failed_login_attempts" not in dumped
        assert "locked_until" not in dumped
        assert dumped == {
            "id": fake_user.id,
            "email": "buyer@example.com",
            "is_email_verified": False,
        }
