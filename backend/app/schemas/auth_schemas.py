from __future__ import annotations

import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

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
    def password_must_contain_letter_and_number(cls, value: str) -> str:
        has_letter = any(char.isalpha() for char in value)
        has_number = any(char.isdigit() for char in value)
        if not (has_letter and has_number):
            raise ValueError("Password must contain at least one letter and one number.")
        return value


class RegisterResponse(BaseModel):
    """What we send back after successful registration. Deliberately
    excludes password_hash and any other sensitive field — this
    class defines the ONLY fields that can ever leave the API for
    this endpoint, regardless of what the User model itself has."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    is_email_verified: bool
