#!/usr/bin/env python3
"""User authentication providers (pluggable).

The gateway never sees passwords. A provider implements the OAuth
authorization-code flow:

  1. ``authorization_url(state, redirect_uri)`` — where to send the user.
  2. ``exchange_code(code, redirect_uri)`` — trade the code for the user
     identity; returns ``{"id": ..., "login": ..., "name": ...}``.

v0.1 ships ``GitHubAuthProvider`` (real, stdlib urllib) and
``DemoAuthProvider`` (insecure stub for the demo and tests — it trusts
any username you hand it; never enable it in production).
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request


class AuthError(Exception):
    pass


class AuthProvider:
    name = "base"

    def authorization_url(self, state: str, redirect_uri: str) -> str:
        raise NotImplementedError

    def exchange_code(self, code: str, redirect_uri: str) -> dict:
        raise NotImplementedError


class GitHubAuthProvider(AuthProvider):
    """GitHub OAuth. Create an OAuth App at
    https://github.com/settings/developers -> "New OAuth App"; set the
    Authorization callback URL to https://<gateway-host>/auth/callback.
    See notes/oauth-setup.md for the full walkthrough."""

    name = "github"
    AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
    TOKEN_URL = "https://github.com/login/oauth/access_token"
    USER_URL = "https://api.github.com/user"

    def __init__(self, client_id: str, client_secret: str):
        if not client_id or not client_secret:
            raise ValueError("GitHub client_id and client_secret are required")
        self.client_id = client_id
        self.client_secret = client_secret

    def authorization_url(self, state: str, redirect_uri: str) -> str:
        q = urllib.parse.urlencode({
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": "read:user user:email",
            "state": state,
        })
        return self.AUTHORIZE_URL + "?" + q

    def _post(self, url: str, data: dict) -> dict:
        body = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(
            url, data=body,
            headers={"Accept": "application/json",
                     "Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            raise AuthError("token exchange failed: %s" % exc) from exc

    def _get(self, url: str, token: str) -> dict:
        req = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "User-Agent": "mcp-auth-gateway",
        })
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            raise AuthError("user lookup failed: %s" % exc) from exc

    def exchange_code(self, code: str, redirect_uri: str) -> dict:
        tok = self._post(self.TOKEN_URL, {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
        })
        access = tok.get("access_token")
        if not access:
            raise AuthError("no access_token in response: %s"
                            % tok.get("error_description", tok.get("error", "?")))
        me = self._get(self.USER_URL, access)
        login = me.get("login")
        if not login:
            raise AuthError("GitHub user lookup returned no login")
        return {"id": str(me.get("id", "")), "login": login,
                "name": me.get("name") or login}


class DemoAuthProvider(AuthProvider):
    """INSECURE stub: trusts any username. Demo and tests only."""

    name = "demo"

    def authorization_url(self, state: str, redirect_uri: str) -> str:
        return redirect_uri + "?code=demo&state=" + urllib.parse.quote(state)

    def exchange_code(self, code: str, redirect_uri: str) -> dict:
        raise AuthError("DemoAuthProvider does not do real exchanges; "
                        "use login_as() instead")

    def login_as(self, username: str) -> dict:
        if not username or not username.strip():
            raise AuthError("username must not be empty")
        username = username.strip()
        return {"id": "demo-" + username, "login": username, "name": username}
