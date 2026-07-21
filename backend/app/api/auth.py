from __future__ import annotations

from flask import Blueprint, g, jsonify, request

from app.core.decorators import rate_limit, require_auth
from app.core.security import ACCESS_TOKEN_TTL_SECONDS
from app.extensions.database import db_session
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.repositories.role_repository import RoleRepository
from app.repositories.user_repository import UserRepository
from app.schemas.auth_schemas import (
    LoginRequest,
    LoginResponse,
    LoginUser,
    MessageResponse,
    PasswordResetConfirmRequest,
    PasswordResetRequestRequest,
    RegisterRequest,
    RegisterResponse,
    RefreshResponse,
    VerifyEmailRequest,
)
from app.services.auth_service import AuthService

auth_bp = Blueprint("auth", __name__, url_prefix="/api/v1/auth")


def _build_auth_service() -> AuthService:
    """Constructs a fully-wired AuthService for the current request.
    Kept as a small factory function rather than a module-level
    singleton, since the underlying session (db_session, a
    scoped_session) is itself request-scoped — building the service
    fresh per-request keeps that scoping correct without any extra
    bookkeeping. The real email sender is not wired up yet
    (Section 7's deferred notifications feature); NullEmailSender
    stands in until then."""
    from app.core.notifications import NullEmailSender
    from flask import current_app

    session = db_session()
    return AuthService(
        session=session,
        user_repo=UserRepository(session),
        role_repo=RoleRepository(session),
        refresh_token_repo=RefreshTokenRepository(session),
        audit_repo=AuditLogRepository(session),
        email_sender=NullEmailSender(),
        jwt_secret_key=current_app.config["SECRET_KEY"],
    )


@auth_bp.route("/register", methods=["POST"])
@rate_limit("5/hour", key="ip")
def register():
    data = RegisterRequest.model_validate(request.get_json(force=True))
    service = _build_auth_service()
    user = service.register(email=data.email, password=data.password, role_name=data.role)
    response = RegisterResponse.model_validate(user)
    return jsonify(data=response.model_dump(mode="json")), 201


@auth_bp.route("/verify-email", methods=["POST"])
@rate_limit("10/hour", key="ip")
def verify_email():
    data = VerifyEmailRequest.model_validate(request.get_json(force=True))
    service = _build_auth_service()
    service.verify_email(raw_token=data.token)
    return jsonify(data={"email_verified": True}), 200


@auth_bp.route("/login", methods=["POST"])
@rate_limit("5/15minutes", key="ip+email")
def login():
    data = LoginRequest.model_validate(request.get_json(force=True))
    service = _build_auth_service()
    access_token, raw_refresh_token, user = service.login(
        email=data.email,
        password=data.password,
        mfa_code=data.mfa_code,
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent"),
    )

    role_repo = RoleRepository(db_session())
    role = role_repo.get_by_id(user.role_id)
    response = LoginResponse(
        access_token=access_token,
        expires_in=ACCESS_TOKEN_TTL_SECONDS,
        user=LoginUser(id=user.id, email=user.email, role=role.name if role else "unknown"),
    )

    resp = jsonify(data=response.model_dump(mode="json"))
    _set_refresh_cookie(resp, raw_refresh_token)
    return resp, 200


@auth_bp.route("/refresh", methods=["POST"])
@rate_limit("20/15minutes", key="user")
def refresh():
    from flask import current_app

    raw_refresh_token = request.cookies.get(current_app.config["REFRESH_COOKIE_NAME"], "")
    service = _build_auth_service()
    new_access_token, new_raw_refresh_token = service.refresh(
        raw_refresh_token=raw_refresh_token,
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent"),
    )

    response = RefreshResponse(access_token=new_access_token, expires_in=ACCESS_TOKEN_TTL_SECONDS)
    resp = jsonify(data=response.model_dump(mode="json"))
    _set_refresh_cookie(resp, new_raw_refresh_token)
    return resp, 200


@auth_bp.route("/logout", methods=["POST"])
def logout():
    from flask import current_app

    raw_refresh_token = request.cookies.get(current_app.config["REFRESH_COOKIE_NAME"], "")
    service = _build_auth_service()
    service.logout(
        raw_refresh_token=raw_refresh_token,
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent"),
    )

    resp = jsonify()
    resp.delete_cookie(current_app.config["REFRESH_COOKIE_NAME"])
    return resp, 204


@auth_bp.route("/logout-all", methods=["POST"])
@require_auth
def logout_all():
    service = _build_auth_service()
    service.logout_all(
        user_id=g.current_user_id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent"),
    )
    return jsonify(), 204


@auth_bp.route("/password-reset/request", methods=["POST"])
@rate_limit("3/hour", key="email")
def request_password_reset():
    data = PasswordResetRequestRequest.model_validate(request.get_json(force=True))
    service = _build_auth_service()
    service.request_password_reset(email=data.email, ip_address=request.remote_addr)
    response = MessageResponse(
        message="If an account with that email exists, a reset link has been sent."
    )
    return jsonify(data=response.model_dump()), 200


@auth_bp.route("/password-reset/confirm", methods=["POST"])
@rate_limit("5/hour", key="ip")
def confirm_password_reset():
    data = PasswordResetConfirmRequest.model_validate(request.get_json(force=True))
    service = _build_auth_service()
    service.confirm_password_reset(
        raw_token=data.token, new_password=data.new_password, ip_address=request.remote_addr
    )
    response = MessageResponse(message="Your password has been reset successfully.")
    return jsonify(data=response.model_dump()), 200


def _set_refresh_cookie(response, raw_refresh_token: str) -> None:
    """Sets the refresh token as an httpOnly, Secure, SameSite=Strict
    cookie — per Section 6, this token must NEVER appear in a JSON
    response body, only here."""
    from flask import current_app

    response.set_cookie(
        current_app.config["REFRESH_COOKIE_NAME"],
        raw_refresh_token,
        httponly=True,
        secure=current_app.config["REFRESH_COOKIE_SECURE"],
        samesite=current_app.config["REFRESH_COOKIE_SAMESITE"],
        max_age=60 * 60 * 24 * 30,  # 30 days, matching REFRESH_TOKEN_TTL_DAYS
    )
