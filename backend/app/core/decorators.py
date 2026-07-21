from __future__ import annotations

from functools import wraps
from typing import Callable

import jwt
from flask import current_app, g, jsonify, request

from app.core.security import decode_access_jwt


def require_auth(view_func: Callable) -> Callable:
    """Requires a valid access token in the Authorization header
    (Bearer scheme). On success, sets g.current_user_id and
    g.current_user_role for the route to use. On failure, returns
    401 without ever calling the wrapped route — this is what makes
    it structurally impossible to forget authentication on a route
    that uses this decorator (Section 7)."""

    @wraps(view_func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return (
                jsonify(error={"code": "MISSING_TOKEN", "message": "Authentication required."}),
                401,
            )

        token = auth_header.removeprefix("Bearer ").strip()
        try:
            payload = decode_access_jwt(token, secret_key=current_app.config["SECRET_KEY"])
        except jwt.InvalidTokenError:
            return (
                jsonify(error={"code": "INVALID_TOKEN", "message": "Invalid or expired token."}),
                401,
            )

        g.current_user_id = payload["sub"]
        g.current_user_role = payload["role"]
        return view_func(*args, **kwargs)

    return wrapper


def rate_limit(limit: str, *, key: str = "ip") -> Callable:
    """Placeholder for Redis-backed rate limiting (Section 6/7).
    Currently a no-op — every route that needs rate limiting is
    already decorated with this NOW, so wiring up real enforcement
    later is a one-line change inside this function, not a
    route-by-route retrofit. Deliberately deferred: rate limiting
    needs a Redis extension we haven't wired up yet, and isn't
    required to prove the routes themselves work correctly."""

    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            return view_func(*args, **kwargs)

        return wrapper

    return decorator
