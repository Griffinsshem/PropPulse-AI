from __future__ import annotations

import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


def _validate_password_strength(value: str) -> str:
    """Shared password strength rule used by every schema that
    accepts a new password (registration, password reset
    confirmation). Factored out to avoid duplicating the same
    check in two places, which would risk them silently drifting
    apart over time."""
    has_letter = any(char.isalpha() for char in value)
    has_number = any(char.isdigit() for char in value)
    if not (has_letter and has_number):
        raise ValueError("Password must contain at least one letter and one number.")
    return value

# Roles a user may self-select at registration. Deliberately EXCLUDES
# admin, super_admin, bank, and government_analyst — per FR-1, those
# require an existing Admin to assign. This is the schema-layer half
# of that rule; AuthService.register() also checks independently
# that the role exists at all (defense in depth, not redundancy).
SelfRegistrableRole = Literal[
    "buyer",
    "seller",
    "agent",
    "developer",
    "property_manager",
    "investor",
    "tenant",
]


class RegisterRequest(BaseModel):
    """Validates the incoming JSON body for POST /api/v1/auth/register."""

    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    role: SelfRegistrableRole

    @field_validator("password")
    @classmethod
    def password_must_be_strong(cls, value: str) -> str:
        return _validate_password_strength(value)


class RegisterResponse(BaseModel):
    """What we send back after successful registration. Deliberately
    excludes password_hash and any other sensitive field — this
    class defines the ONLY fields that can ever leave the API for
    this endpoint, regardless of what the User model itself has."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    is_email_verified: bool



class VerifyEmailRequest(BaseModel):
    """Validates POST /api/v1/auth/verify-email."""

    token: str = Field(min_length=1)


class LoginRequest(BaseModel):
    """Validates POST /api/v1/auth/login. mfa_code is optional and,
    per Section 6/7, currently unused by AuthService.login() until
    the MFA fast-follow feature ships."""

    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
    mfa_code: str | None = None


class LoginUser(BaseModel):
    """The minimal user shape embedded in LoginResponse. Deliberately
    separate from RegisterResponse even though the fields overlap
    right now — the two endpoints have no reason to be coupled to
    the same response shape just because they currently look
    similar; if login's user summary needs to grow differently from
    registration's later, this avoids an awkward shared-then-diverged
    class."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    role: str


class LoginResponse(BaseModel):
    """What we send back after successful login. access_token is the
    only token in this body — the refresh token is delivered via an
    httpOnly cookie set by the route, never in JSON, per Section 6's
    security design."""

    access_token: str
    expires_in: int
    user: LoginUser


class RefreshResponse(BaseModel):
    """What we send back after a successful token refresh. No
    corresponding request schema exists — the refresh token comes
    from the httpOnly cookie, never a JSON body, per Section 6."""

    access_token: str
    expires_in: int


class PasswordResetRequestRequest(BaseModel):
    """Validates POST /api/v1/auth/password-reset/request."""

    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr


class PasswordResetConfirmRequest(BaseModel):
    """Validates POST /api/v1/auth/password-reset/confirm. Reuses
    the same password strength rule as RegisterRequest via the
    shared _validate_password_strength function."""

    token: str = Field(min_length=1)
    new_password: str = Field(min_length=12, max_length=128)

    @field_validator("new_password")
    @classmethod
    def new_password_must_be_strong(cls, value: str) -> str:
        return _validate_password_strength(value)


class MessageResponse(BaseModel):
    """A generic, minimal response used for endpoints that only need
    to confirm an action happened, without returning any specific
    data — e.g. password-reset-request's deliberately vague
    'if this email exists, a reset link was sent' response."""

    message: str
