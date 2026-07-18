from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# --- Password hashing (Argon2id) -------------------------------------------
#
# argon2-cffi's PasswordHasher defaults to the Argon2id variant with
# OWASP-recommended cost parameters. We deliberately do not override
# these defaults here — tuning memory/time cost incorrectly is a
# well-known way to accidentally weaken password storage, and the
# library's defaults track current best practice better than a
# one-off guess would.
_password_hasher = PasswordHasher()


def hash_password(plain_password: str) -> str:
    """Hashes a plaintext password for storage. The returned string
    includes the algorithm, cost parameters, and salt all together —
    nothing extra needs to be stored alongside it."""
    return _password_hasher.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Returns True if plain_password matches hashed_password.
    Never raises on a wrong password — a mismatch is a normal,
    expected outcome, not an error condition."""
    try:
        return _password_hasher.verify(hashed_password, plain_password)
    except VerifyMismatchError:
        return False


# --- Secure token generation and hashing -----------------------------------


def generate_secure_token() -> str:
    """Generates a cryptographically secure, URL-safe random token
    for use as a refresh token, email verification token, or
    password reset token. Uses `secrets`, never `random` — `random`
    is not safe for anything security-sensitive because its output
    is statistically predictable, not cryptographically random."""
    return secrets.token_urlsafe(32)


def hash_token(raw_token: str) -> str:
    """Hashes a raw token for storage/comparison. Unlike passwords,
    tokens are already long, high-entropy, unguessable random
    strings — there's no brute-force risk to defend against, so a
    fast, deterministic hash (SHA-256) is the right tool here rather
    than the deliberately slow Argon2id used for passwords."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


# --- JWT access tokens ------------------------------------------------------

_JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_TTL_SECONDS = 900  # 15 minutes, per Section 6 API contract


def create_access_jwt(*, user_id: str, role: str, secret_key: str) -> str:
    """Creates a short-lived JWT access token. Payload is
    deliberately minimal (user_id, role, type, exp, iat only) —
    JWTs are base64-encoded, NOT encrypted, so anything placed here
    is readable by anyone who intercepts the token. Never add email,
    permissions, or other PII to this payload."""
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": user_id,
        "role": role,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(seconds=ACCESS_TOKEN_TTL_SECONDS),
    }
    return jwt.encode(payload, secret_key, algorithm=_JWT_ALGORITHM)


def decode_access_jwt(token: str, *, secret_key: str) -> dict[str, Any]:
    """Decodes and verifies a JWT access token. Raises
    jwt.InvalidTokenError (or a subclass, e.g. jwt.ExpiredSignatureError)
    if the token is malformed, has an invalid signature, or has
    expired. Callers (the @require_auth decorator) are responsible
    for catching this and returning 401."""
    payload = jwt.decode(token, secret_key, algorithms=[_JWT_ALGORITHM])
    if payload.get("type") != "access":
        raise jwt.InvalidTokenError("Token is not an access token")
    return payload
