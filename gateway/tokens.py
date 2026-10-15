#!/usr/bin/env python3
"""Scoped access tokens for the MCP auth gateway.

Tokens are HMAC-SHA256 signed, in the form ``header.payload.signature``
(base64url, no padding). The payload binds the token to one user, one
server, and a fixed scope set, with a short expiry:

    {"v": 1, "sub": "<user>", "srv": "<server_id>",
     "scp": ["tools:read", ...], "iat": 169..., "exp": 169..., "jti": "<hex>"}

There is no token database: validation is pure cryptography, so any
gateway node holding the secret can validate. Revocation is by expiry
(short TTLs); see notes/threat-model.md.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time


class TokenError(Exception):
    """Raised when a token fails validation. ``reason`` is machine-readable."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(detail or reason)
        self.reason = reason


def new_secret() -> str:
    """Generate a fresh 256-bit gateway secret (hex)."""
    return secrets.token_hex(32)


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(data + pad)
    except Exception as exc:
        raise TokenError("malformed", "token is not valid base64url") from exc


def _sign(secret: str, signing_input: str) -> str:
    mac = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256)
    return _b64e(mac.digest())


def mint_token(secret: str, sub: str, server: str, scopes, ttl_seconds: int = 900,
               now: float | None = None) -> str:
    """Mint a scoped token bound to (user, server). ttl defaults to 15 minutes."""
    if not secret:
        raise ValueError("secret must not be empty")
    if not sub or not server:
        raise ValueError("sub and server must not be empty")
    now_i = int(now if now is not None else time.time())
    payload = {
        "v": 1,
        "sub": sub,
        "srv": server,
        "scp": sorted(set(scopes)),
        "iat": now_i,
        "exp": now_i + int(ttl_seconds),
        "jti": secrets.token_hex(8),
    }
    header = _b64e(json.dumps({"alg": "HS256", "typ": "MGW"}).encode())
    body = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = header + "." + body
    return signing_input + "." + _sign(secret, signing_input)


def validate_token(secret: str, token: str, now: float | None = None) -> dict:
    """Validate a token. Returns the payload dict, or raises TokenError."""
    if not token or not isinstance(token, str):
        raise TokenError("malformed", "empty token")
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenError("malformed", "token must have 3 dot-separated parts")
    header_b64, body_b64, sig = parts
    try:
        header = json.loads(_b64d(header_b64))
    except TokenError:
        raise
    except Exception as exc:
        raise TokenError("malformed", "bad token header") from exc
    if header.get("alg") != "HS256":
        raise TokenError("malformed", "unsupported alg")
    expected = _sign(secret, header_b64 + "." + body_b64)
    if not hmac.compare_digest(expected, sig):
        raise TokenError("bad_signature", "signature mismatch")
    try:
        payload = json.loads(_b64d(body_b64))
    except TokenError:
        raise
    except Exception as exc:
        raise TokenError("malformed", "bad token payload") from exc
    if not isinstance(payload, dict) or payload.get("v") != 1:
        raise TokenError("malformed", "bad payload version")
    now_i = int(now if now is not None else time.time())
    if payload.get("exp", 0) <= now_i:
        raise TokenError("expired", "token has expired")
    for field in ("sub", "srv", "scp", "iat"):
        if field not in payload:
            raise TokenError("malformed", "missing field: %s" % field)
    return payload
