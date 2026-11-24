"""Purpose-separated browser proofs; the key lives only in the auth store."""

import hashlib
import hmac
import secrets
import time

from fastapi import Request, Response

from .auth_models import AuthError

SESSION_COOKIE = "c2hunter_session"
PRELOGIN_COOKIE = "c2hunter_preauth"


def proof(key: bytes, purpose: str, token: str) -> str:
    return hmac.new(key, (purpose + "\0" + token).encode(), hashlib.sha256).hexdigest()


def prelogin(key: bytes) -> tuple[str, str]:
    value = f"{int(time.time())}.{secrets.token_hex(32)}"
    cookie = value + "." + proof(key, "prelogin-cookie", value)
    return cookie, proof(key, "prelogin-csrf", cookie)


def verify_prelogin(key: bytes, cookie: str, csrf: str) -> None:
    try:
        timestamp, nonce, signature = cookie.split(".")
        age = time.time() - int(timestamp)
        valid = (
            0 <= age <= 600
            and len(nonce) == 64
            and hmac.compare_digest(
                signature, proof(key, "prelogin-cookie", timestamp + "." + nonce)
            )
            and hmac.compare_digest(csrf, proof(key, "prelogin-csrf", cookie))
        )
    except (ValueError, TypeError, UnicodeError):
        valid = False
    if not valid:
        raise AuthError("CSRF_INVALID", 403)


def cookie_value(request: Request, name: str) -> str | None:
    values = []
    for header in request.headers.getlist("cookie"):
        for part in header.split(";"):
            key, separator, value = part.strip().partition("=")
            if key == name and separator:
                values.append(value)
    if len(values) > 1 or (values and len(values[0]) > 512):
        raise AuthError("AUTH_REQUIRED", 401)
    return values[0] if values else None


def set_cookie(response: Response, name: str, value: str, *, secure: bool, age: int) -> None:
    response.set_cookie(
        name, value, max_age=age, httponly=True, secure=secure, samesite="lax", path="/"
    )
