#!/usr/bin/env python3
"""HTTP reverse proxy: Bearer-token auth + scope enforcement in front of
any stdio MCP server.

Endpoints:
  GET  /auth/login?provider=<name>   -> 302 to the OAuth provider
  GET  /auth/callback?code=..&state=.. -> exchange, set signed session
                                          cookie, JSON with allowed servers
  POST /token  {"server": "<id>"}     -> mint a scoped token for the
                                       logged-in session (policy-driven)
  POST /mcp/<server_id>               -> proxy one JSON-RPC message to the
                                       upstream stdio server. Requires
                                       ``Authorization: Bearer <token>``.

Upstream servers are spawned lazily (one persistent process per server)
and restarted if they die. Totals/state stay server-side; the gateway
never interprets tool arguments.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import select
import subprocess
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import tokens
from .policy import Policy, PolicyError
from .scopes import has_scope, required_scope


# ---------------------------------------------------------------------------
# upstream stdio process pool
# ---------------------------------------------------------------------------

class UpstreamError(Exception):
    pass


class UpstreamPool:
    """One persistent stdio subprocess per server_id, started lazily."""

    def __init__(self, read_timeout: float = 30.0):
        self._procs: dict[str, subprocess.Popen] = {}
        self._lock = threading.Lock()
        self._read_timeout = read_timeout

    def _spawn(self, server_id: str, command: list) -> subprocess.Popen:
        try:
            return subprocess.Popen(
                command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, bufsize=1)
        except OSError as exc:
            raise UpstreamError("cannot start %s: %s" % (server_id, exc)) from exc

    def call(self, server_id: str, command: list, message: dict) -> dict:
        with self._lock:
            proc = self._procs.get(server_id)
            if proc is None or proc.poll() is not None:
                proc = self._spawn(server_id, command)
                self._procs[server_id] = proc
        line = json.dumps(message) + "\n"
        try:
            proc.stdin.write(line)
            proc.stdin.flush()
        except (BrokenPipeError, OSError):
            with self._lock:
                self._procs.pop(server_id, None)
            raise UpstreamError("upstream %s died on write" % server_id)
        rlist, _, _ = select.select([proc.stdout], [], [], self._read_timeout)
        if not rlist:
            raise UpstreamError("upstream %s timed out" % server_id)
        out = proc.stdout.readline()
        if not out:
            with self._lock:
                self._procs.pop(server_id, None)
            raise UpstreamError("upstream %s closed stdout" % server_id)
        try:
            return json.loads(out)
        except json.JSONDecodeError as exc:
            raise UpstreamError("upstream %s returned bad JSON" % server_id) from exc

    def shutdown(self):
        with self._lock:
            for proc in self._procs.values():
                try:
                    proc.kill()
                except OSError:
                    pass
            self._procs.clear()


# ---------------------------------------------------------------------------
# gateway
# ---------------------------------------------------------------------------

class Gateway:
    def __init__(self, policy: Policy, secret: str, providers: dict,
                 session_ttl: int = 86400, token_ttl: int = 900,
                 base_url: str = ""):
        if not secret:
            raise ValueError("secret must not be empty")
        self.policy = policy
        self.secret = secret
        self.providers = providers
        self.session_ttl = session_ttl
        self.token_ttl = token_ttl
        self.base_url = base_url.rstrip("/")
        self.pool = UpstreamPool()
        self._states: dict[str, float] = {}
        self._states_lock = threading.Lock()

    # -- sessions (stateless signed cookies) -------------------------------

    def _sign(self, value: str) -> str:
        mac = hmac.new(self.secret.encode(), value.encode(), hashlib.sha256)
        return base64.urlsafe_b64encode(mac.digest()).rstrip(b"=").decode()

    def make_session(self, user: dict) -> str:
        payload = {"sub": user["login"], "uid": user.get("id", ""),
                   "exp": int(time.time()) + self.session_ttl}
        body = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=").decode()
        return body + "." + self._sign(body)

    def read_session(self, cookie_value: str | None) -> dict | None:
        if not cookie_value:
            return None
        parts = cookie_value.split(".")
        if len(parts) != 2:
            return None
        body, sig = parts
        if not hmac.compare_digest(self._sign(body), sig):
            return None
        try:
            pad = "=" * (-len(body) % 4)
            payload = json.loads(base64.urlsafe_b64decode(body + pad))
        except Exception:
            return None
        if payload.get("exp", 0) <= int(time.time()):
            return None
        return payload

    # -- oauth state ---------------------------------------------------------

    def new_state(self) -> str:
        state = secrets.token_urlsafe(24)
        with self._states_lock:
            self._states[state] = time.time() + 600
            # prune expired
            expired = [s for s, e in self._states.items() if e <= time.time()]
            for s in expired:
                del self._states[s]
        return state

    def consume_state(self, state: str) -> bool:
        with self._states_lock:
            exp = self._states.pop(state, None)
        return exp is not None and exp > time.time()

    # -- token minting -------------------------------------------------------

    def mint_for(self, user_login: str, server_id: str) -> tuple[str, list]:
        scopes = self.policy.resolve_scopes(user_login, server_id)
        if not scopes:
            raise PolicyError("no access for %s on %s" % (user_login, server_id))
        token = tokens.mint_token(self.secret, user_login, server_id, scopes,
                                  ttl_seconds=self.token_ttl)
        return token, scopes


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    gateway: Gateway  # set by serve()

    def log_message(self, fmt, *args):  # quieter logs
        pass

    # -- helpers -------------------------------------------------------------

    def _send_json(self, status: int, obj: dict, headers: dict | None = None):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length <= 0 or length > 1_000_000:
            return None
        try:
            return json.loads(self.rfile.read(length))
        except Exception:
            return None

    def _session(self) -> dict | None:
        cookie = self.headers.get("Cookie", "")
        value = None
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("mgw_session="):
                value = part[len("mgw_session="):]
                break
        return self.gateway.read_session(value)

    def _bearer(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[len("Bearer "):].strip()
        return None

    # -- routes ---------------------------------------------------------------

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path, qs = parsed.path, urllib.parse.parse_qs(parsed.query)
        gw = self.gateway

        if path == "/auth/login":
            provider = qs.get("provider", [""])[0]
            prov = gw.providers.get(provider)
            if prov is None:
                return self._send_json(400, {"error": "unknown provider"})
            state = gw.new_state()
            redirect_uri = gw.base_url + "/auth/callback" if gw.base_url else None
            url = prov.authorization_url(state, redirect_uri or "")
            self.send_response(302)
            self.send_header("Location", url)
            self.end_headers()
            return

        if path == "/auth/callback":
            code = qs.get("code", [""])[0]
            state = qs.get("state", [""])[0]
            if not code or not gw.consume_state(state):
                return self._send_json(400, {"error": "bad code or state"})
            # find which provider by trying each is overkill in v0.1:
            # use the single configured provider, or ?provider= hint
            provider = qs.get("provider", [""])[0] or next(iter(gw.providers), "")
            prov = gw.providers.get(provider)
            if prov is None:
                return self._send_json(400, {"error": "unknown provider"})
            redirect_uri = gw.base_url + "/auth/callback" if gw.base_url else ""
            try:
                user = prov.exchange_code(code, redirect_uri)
            except Exception as exc:
                return self._send_json(502, {"error": "auth exchange failed",
                                            "detail": str(exc)})
            session = gw.make_session(user)
            allowed = gw.policy.allowed_servers(user["login"])
            return self._send_json(200, {"login": user["login"],
                                         "servers": allowed},
                                   {"Set-Cookie": "mgw_session=%s; HttpOnly; "
                                                  "SameSite=Lax; Path=/" % session})

        if path == "/health":
            return self._send_json(200, {"ok": True})

        return self._send_json(404, {"error": "not found"})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        gw = self.gateway

        if path == "/token":
            sess = self._session()
            if sess is None:
                return self._send_json(401, {"error": "login required"})
            body = self._read_json_body()
            server_id = (body or {}).get("server")
            if not server_id:
                return self._send_json(400, {"error": "missing server"})
            try:
                token, scopes = gw.mint_for(sess["sub"], server_id)
            except PolicyError as exc:
                return self._send_json(403, {"error": "forbidden", "detail": str(exc)})
            return self._send_json(200, {"token": token, "scopes": scopes,
                                         "expires_in": gw.token_ttl})

        if path.startswith("/mcp/"):
            server_id = path[len("/mcp/"):]
            if "/" in server_id or not server_id:
                return self._send_json(404, {"error": "not found"})
            raw_token = self._bearer()
            if not raw_token:
                return self._send_json(
                    401, {"error": "missing bearer token",
                          "hint": "POST /token with a login session first"})
            try:
                claims = tokens.validate_token(gw.secret, raw_token)
            except tokens.TokenError as exc:
                return self._send_json(
                    401, {"error": "invalid token", "reason": exc.reason})
            if claims["srv"] != server_id:
                return self._send_json(
                    403, {"error": "token is for a different server"})
            body = self._read_json_body()
            if not isinstance(body, dict) or "method" not in body:
                return self._send_json(400, {"error": "expected a JSON-RPC message"})
            method = body["method"]
            if not has_scope(claims["scp"], method):
                return self._send_json(
                    403, {"error": "scope denied",
                          "detail": "method %r needs scope %r" % (method, required_scope(method)),
                          "hint": "ask your admin for a grant, then mint a new token"})
            try:
                command = gw.policy.server_command(server_id)
            except PolicyError as exc:
                return self._send_json(404, {"error": str(exc)})
            try:
                resp = gw.pool.call(server_id, command, body)
            except UpstreamError as exc:
                return self._send_json(502, {"error": "upstream failed",
                                             "detail": str(exc)})
            return self._send_json(200, resp)

        return self._send_json(404, {"error": "not found"})


def serve(gateway: Gateway, host: str = "127.0.0.1", port: int = 8080):
    _Handler.gateway = gateway
    server = ThreadingHTTPServer((host, port), _Handler)
    return server
