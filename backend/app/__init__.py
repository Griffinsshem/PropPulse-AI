from __future__ import annotations

from flask import Flask, jsonify

from app.core.config import Config
from app.extensions.database import init_engine
from app.services.auth_service import (
    AccountLockedError,
    EmailAlreadyRegisteredError,
    InvalidCredentialsError,
    InvalidRefreshTokenError,
    InvalidResetTokenError,
    InvalidVerificationTokenError,
    RoleNotFoundError,
)


def create_app(config_class: type[Config] = Config) -> Flask:
    """Application factory: builds a fresh Flask app each time it's
    called, rather than relying on one global instance. This is
    what lets the test suite spin up an app configured against the
    test database without ever touching the real one, and without
    tests sharing state through a shared global app object."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    init_engine(config_class.DATABASE_URL)

    _register_error_handlers(app)
    _register_blueprints(app)

    return app


def _register_blueprints(app: Flask) -> None:
    from app.api.auth import auth_bp

    app.register_blueprint(auth_bp)


def _register_error_handlers(app: Flask) -> None:
    """Maps every AuthService exception to the exact HTTP status
    code and generic message specified in Section 6's API contract.
    This is the ONE place that translation happens — routes never
    need to catch these exceptions themselves, keeping routes thin
    per Section 7's architecture."""

    @app.errorhandler(EmailAlreadyRegisteredError)
    def _handle_email_already_registered(exc: EmailAlreadyRegisteredError):
        return jsonify(error={"code": "EMAIL_ALREADY_REGISTERED", "message": str(exc)}), 409

    @app.errorhandler(RoleNotFoundError)
    def _handle_role_not_found(exc: RoleNotFoundError):
        return jsonify(error={"code": "INVALID_ROLE", "message": "Invalid role specified."}), 422

    @app.errorhandler(InvalidCredentialsError)
    def _handle_invalid_credentials(exc: InvalidCredentialsError):
        return jsonify(error={"code": "INVALID_CREDENTIALS", "message": str(exc)}), 401

    @app.errorhandler(AccountLockedError)
    def _handle_account_locked(exc: AccountLockedError):
        return (
            jsonify(
                error={
                    "code": "ACCOUNT_LOCKED",
                    "message": f"Account is locked until {exc.locked_until.isoformat()}.",
                }
            ),
            423,
        )

    @app.errorhandler(InvalidRefreshTokenError)
    def _handle_invalid_refresh_token(exc: InvalidRefreshTokenError):
        return jsonify(error={"code": "INVALID_REFRESH_TOKEN", "message": str(exc)}), 401

    @app.errorhandler(InvalidVerificationTokenError)
    def _handle_invalid_verification_token(exc: InvalidVerificationTokenError):
        return jsonify(error={"code": "INVALID_VERIFICATION_TOKEN", "message": str(exc)}), 400

    @app.errorhandler(InvalidResetTokenError)
    def _handle_invalid_reset_token(exc: InvalidResetTokenError):
        return jsonify(error={"code": "INVALID_RESET_TOKEN", "message": str(exc)}), 400
