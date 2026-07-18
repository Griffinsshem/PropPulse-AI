from __future__ import annotations


import jwt as pyjwt
import pytest

from app.core.security import (
    create_access_jwt,
    decode_access_jwt,
    generate_secure_token,
    hash_password,
    hash_token,
    verify_password,
)

TEST_SECRET_KEY = "test-secret-key-not-used-in-production-32b"


class TestPasswordHashing:
    def test_hash_password_does_not_return_the_plain_password(self):
        hashed = hash_password("correct-horse-battery-staple")
        assert hashed != "correct-horse-battery-staple"

    def test_hashing_the_same_password_twice_produces_different_hashes(self):
        """This proves salting is actually happening. If this test
        ever failed, it would mean every user with the same password
        gets an identical hash — a serious vulnerability, since an
        attacker could precompute a table of hashes for common
        passwords and instantly identify matches across all users."""
        hash_one = hash_password("same-password-123")
        hash_two = hash_password("same-password-123")

        assert hash_one != hash_two

    def test_verify_password_accepts_the_correct_password(self):
        hashed = hash_password("my-real-password")
        assert verify_password("my-real-password", hashed) is True

    def test_verify_password_rejects_a_wrong_password(self):
        hashed = hash_password("my-real-password")
        assert verify_password("a-guessed-password", hashed) is False

    def test_verify_password_never_raises_on_mismatch(self):
        """Confirms verify_password absorbs VerifyMismatchError
        internally rather than requiring every caller to handle it."""
        hashed = hash_password("my-real-password")
        try:
            result = verify_password("wrong", hashed)
        except Exception as exc:  # noqa: BLE001 - intentionally broad for this assertion
            pytest.fail(f"verify_password raised unexpectedly: {exc}")
        assert result is False


class TestSecureTokenGeneration:
    def test_generate_secure_token_returns_a_nonempty_string(self):
        token = generate_secure_token()
        assert isinstance(token, str)
        assert len(token) > 0

    def test_generate_secure_token_returns_unique_values(self):
        tokens = {generate_secure_token() for _ in range(100)}
        assert len(tokens) == 100  # no collisions across 100 generations

    def test_hash_token_is_deterministic(self):
        """Unlike password hashing, token hashing must be
        deterministic — we need to hash an incoming raw token and
        compare it against what's stored, so the same input must
        always produce the same output."""
        raw = "some-raw-token-value"
        assert hash_token(raw) == hash_token(raw)

    def test_hash_token_differs_for_different_inputs(self):
        assert hash_token("token-a") != hash_token("token-b")


class TestAccessJwt:
    def test_create_and_decode_round_trip_recovers_the_payload(self):
        token = create_access_jwt(user_id="user-123", role="buyer", secret_key=TEST_SECRET_KEY)

        decoded = decode_access_jwt(token, secret_key=TEST_SECRET_KEY)

        assert decoded["sub"] == "user-123"
        assert decoded["role"] == "buyer"
        assert decoded["type"] == "access"

    def test_decode_rejects_a_token_signed_with_a_different_secret(self):
        """This is the core security property of the whole scheme:
        without knowing SECRET_KEY, an attacker cannot forge a valid
        token, even if they know the exact payload shape."""
        token = create_access_jwt(user_id="user-123", role="buyer", secret_key=TEST_SECRET_KEY)

        with pytest.raises(pyjwt.InvalidSignatureError):
            decode_access_jwt(token, secret_key="a-completely-different-secret-32bytes")

    def test_decode_rejects_a_tampered_token(self):
        """Simulates an attacker flipping a bit in the token body
        (e.g. trying to change their role to 'admin'). Any
        modification must invalidate the signature."""
        token = create_access_jwt(user_id="user-123", role="buyer", secret_key=TEST_SECRET_KEY)
        tampered = token[:-1] + ("A" if token[-1] != "A" else "B")

        with pytest.raises(pyjwt.InvalidTokenError):
            decode_access_jwt(tampered, secret_key=TEST_SECRET_KEY)

    def test_decode_rejects_an_expired_token(self):
        """We can't easily wait 15 real minutes in a test, so we
        construct an already-expired token directly using the same
        signing mechanism, rather than mocking datetime.now()."""
        from datetime import datetime, timedelta, timezone

        expired_payload = {
            "sub": "user-123",
            "role": "buyer",
            "type": "access",
            "iat": datetime.now(timezone.utc) - timedelta(hours=1),
            "exp": datetime.now(timezone.utc) - timedelta(minutes=1),
        }
        expired_token = pyjwt.encode(expired_payload, TEST_SECRET_KEY, algorithm="HS256")

        with pytest.raises(pyjwt.ExpiredSignatureError):
            decode_access_jwt(expired_token, secret_key=TEST_SECRET_KEY)

    def test_decode_rejects_a_token_of_the_wrong_type(self):
        """Guards against the 'confused deputy' scenario described
        in security.py's docstring: a token signed for a different
        purpose, using the same secret, must not be accepted here."""
        from datetime import datetime, timedelta, timezone

        wrong_type_payload = {
            "sub": "user-123",
            "role": "buyer",
            "type": "email_change_confirmation",
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
        }
        wrong_type_token = pyjwt.encode(wrong_type_payload, TEST_SECRET_KEY, algorithm="HS256")

        with pytest.raises(pyjwt.InvalidTokenError):
            decode_access_jwt(wrong_type_token, secret_key=TEST_SECRET_KEY)
