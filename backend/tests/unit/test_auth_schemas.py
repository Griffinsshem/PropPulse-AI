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


class TestVerifyEmailRequest:
    def test_accepts_a_nonempty_token(self):
        from app.schemas.auth_schemas import VerifyEmailRequest

        req = VerifyEmailRequest(token="some-raw-token")
        assert req.token == "some-raw-token"

    def test_rejects_an_empty_token(self):
        from app.schemas.auth_schemas import VerifyEmailRequest

        with pytest.raises(ValidationError):
            VerifyEmailRequest(token="")


class TestLoginRequest:
    def test_accepts_a_well_formed_request_without_mfa_code(self):
        from app.schemas.auth_schemas import LoginRequest

        req = LoginRequest(email="user@example.com", password="anything")
        assert req.mfa_code is None

    def test_accepts_an_optional_mfa_code(self):
        from app.schemas.auth_schemas import LoginRequest

        req = LoginRequest(email="user@example.com", password="anything", mfa_code="123456")
        assert req.mfa_code == "123456"

    def test_rejects_a_malformed_email(self):
        from app.schemas.auth_schemas import LoginRequest

        with pytest.raises(ValidationError):
            LoginRequest(email="not-an-email", password="anything")

    def test_does_not_enforce_password_strength_on_login(self):
        """Deliberately different from RegisterRequest: login should
        accept whatever password the user actually has, even a
        short/weak one from an old account, since the strength rule
        only makes sense when a NEW password is being set."""
        from app.schemas.auth_schemas import LoginRequest

        req = LoginRequest(email="user@example.com", password="short")
        assert req.password == "short"


class TestLoginResponseAndRefreshResponse:
    def test_login_response_builds_correctly_with_nested_user(self):
        from app.schemas.auth_schemas import LoginResponse, LoginUser

        response = LoginResponse(
            access_token="a-jwt-token",
            expires_in=900,
            user=LoginUser(id=uuid.uuid4(), email="user@example.com", role="buyer"),
        )
        dumped = response.model_dump()
        assert dumped["user"]["role"] == "buyer"
        assert "password_hash" not in dumped["user"]

    def test_login_user_only_exposes_declared_fields_from_a_richer_object(self):
        """Same proof-by-construction as RegisterResponse's test:
        build from an object with sensitive extra attributes and
        confirm they don't leak through."""
        from app.schemas.auth_schemas import LoginUser

        class FakeUser:
            def __init__(self) -> None:
                self.id = uuid.uuid4()
                self.email = "user@example.com"
                self.role = "buyer"
                self.password_hash = "must-never-leak"

        dumped = LoginUser.model_validate(FakeUser()).model_dump()
        assert "password_hash" not in dumped

    def test_refresh_response_has_no_refresh_token_field(self):
        """Structural proof that RefreshResponse cannot carry a
        refresh token in the JSON body, even by accident — the
        refresh token must only ever travel via the httpOnly cookie
        set directly by the route, per Section 6."""
        from app.schemas.auth_schemas import RefreshResponse

        fields = RefreshResponse.model_fields.keys()
        assert "refresh_token" not in fields
        assert set(fields) == {"access_token", "expires_in"}


class TestPasswordResetSchemas:
    def test_password_reset_request_accepts_a_valid_email(self):
        from app.schemas.auth_schemas import PasswordResetRequestRequest

        req = PasswordResetRequestRequest(email="user@example.com")
        assert req.email == "user@example.com"

    def test_password_reset_request_rejects_a_malformed_email(self):
        from app.schemas.auth_schemas import PasswordResetRequestRequest

        with pytest.raises(ValidationError):
            PasswordResetRequestRequest(email="not-an-email")

    def test_password_reset_confirm_accepts_a_valid_request(self):
        from app.schemas.auth_schemas import PasswordResetConfirmRequest

        req = PasswordResetConfirmRequest(token="a-raw-token", new_password="a-valid-password-123")
        assert req.new_password == "a-valid-password-123"

    def test_password_reset_confirm_enforces_the_same_strength_rule_as_registration(self):
        """Proves the SHARED validator is genuinely wired up here,
        not just present in the file unused — a weak new_password
        must be rejected exactly like a weak RegisterRequest
        password would be."""
        from app.schemas.auth_schemas import PasswordResetConfirmRequest

        with pytest.raises(ValidationError):
            PasswordResetConfirmRequest(token="a-raw-token", new_password="alllettersnonumbers")


class TestMessageResponse:
    def test_message_response_holds_a_simple_string(self):
        from app.schemas.auth_schemas import MessageResponse

        response = MessageResponse(message="If an account with that email exists, a reset link has been sent.")
        assert "message" in response.model_dump()
