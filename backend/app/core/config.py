from __future__ import annotations

import os

from dotenv import load_dotenv

_REPO_ROOT_ENV = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env")
load_dotenv(_REPO_ROOT_ENV)


class Config:
    """Base configuration, loaded from environment variables. Every
    setting the application needs lives here, in ONE place — no
    other module should call os.environ.get() directly for app
    config, so there's a single, reviewable source of truth."""

    SECRET_KEY: str = os.environ["SECRET_KEY"]
    DATABASE_URL: str = os.environ["DATABASE_URL"]
    REDIS_URL: str = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    FLASK_ENV: str = os.environ.get("FLASK_ENV", "production")

    # Cookie security flags for the refresh token cookie (Section 6).
    # Secure=True requires HTTPS, which is why it's off in local dev
    # (plain HTTP) but MUST be True anywhere else.
    REFRESH_COOKIE_SECURE: bool = FLASK_ENV != "development"
    REFRESH_COOKIE_SAMESITE: str = "Strict"
    REFRESH_COOKIE_NAME: str = "refresh_token"


class TestConfig(Config):
    """Overrides for the test suite: points at the dedicated test
    database, never the real dev database."""

    DATABASE_URL: str = os.environ["TEST_DATABASE_URL"]
    FLASK_ENV: str = "testing"
