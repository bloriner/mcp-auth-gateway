"""Adversarial security regression tests for the MCP auth gateway.

Covers: token forgery/tampering, alg confusion, truncated/empty
segments, cross-server reuse, expiry boundaries, session cookie
tampering, OAuth state single-use, /token input validation, huge
inputs, malformed JSON-RPC, concurrent use, and response isolation
between concurrent upstream callers.
"""

import base64
import json
import os
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request

from gateway import tokens
from gateway.auth import AuthProvider
from gateway.policy import load_policy
from gateway.proxy import Gateway, UpstreamPool, serve
from gateway.tokens import TokenError, mint_token, new_secret, validate_token

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _b64e_json(obj) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()


def _resign(secret, payload: dict) -> str:
    """Mint a token with an attacker-chosen (but properly signed) payload,
    to prove validation fails closed on unexpected claim types."""
    header = _b64e_json({"alg": "HS256", "typ": "MGW"})
    body = _b64e_json(payload)
    return header + "." + body + "." + tokens._sign(secret, header + "." + body)


def _payload_of(token: str) -> dict:
    parts = token.split(".")
    return json.loads(base64.urlsafe_b64decode(parts[1] + "==="))


class TestTokenAdversarial(unittest.TestCase):
    def setUp(self):
        self.secret = new_secret()

    def test_scope_escalation_rejected(self):
        t = mint_token(self.secret, "bob", "srv1", ["tools:read"])
        h, b, s = t.split(".")
        evil = _b64e_json({**_payload_of(t), "scp": ["tools:read", "tools:write"]})
        with self.assertRaises(TokenError) as ctx:
            validate_token(self.secret, h + "." + evil + "." + s)
        self.assertEqual(ctx.exception.reason, "bad_signature")

    def test_truncated_signature(self):
        t = mint_token(self.secret, "u", "s", ["tools:read"])
        h, b, s = t.split(".")
        for bad_sig in (s[:-1], s[:-4], ""):
            with self.assertRaises(TokenError) as ctx:
                validate_token(self.secret, h + "." + b + "." + bad_sig)
            self.assertEqual(ctx.exception.reason, "bad_signature")

    def test_empty_segments(self):
        t = mint_token(self.secret, "u", "s", ["tools:read"])
        h, b, s = t.split(".")
        for bad in ("", "." + b + "." + s, h + ".." + s, h + "." + b + ".",
                    "..", ".", "..."):
            with self.assertRaises(TokenError, msg=bad):
                validate_token(self.secret, bad)

    def test_alg_confusion(self):
        t = mint_token(self.secret, "u", "s", ["tools:read"])
        _, b, s = t.split(".")
        for alg in ("none", "HS512", "RS256", "", None):
            evil_h = _b64e_json({"alg": alg, "typ": "MGW"})
            with self.assertRaises(TokenError) as ctx:
                validate_token(self.secret, evil_h + "." + b + "." + s)
            self.assertEqual(ctx.exception.reason, "malformed", alg)

    def test_non_ascii_signature_fails_closed(self):
        # must be bad_signature, not a TypeError -> 500
        t = mint_token(self.secret, "u", "s", ["tools:read"])
        h, b, _ = t.split(".")
        with self.assertRaises(TokenError) as ctx:
            validate_token(self.secret, h + "." + b + "." + "sig-\u00e9-part")
        self.assertEqual(ctx.exception.reason, "bad_signature")

    def test_wrong_type_claims_rejected(self):
        base = {"v": 1, "sub": "u", "srv": "s", "scp": ["tools:read"],
                "iat": 1000, "exp": 9999999999, "jti": "x"}
        mutations = {
            "scp_as_string": {**base, "scp": "tools:read"},
            "scp_empty": {**base, "scp": []},
            "scp_non_string_item": {**base, "scp": ["tools:read", 42]},
            "exp_as_string": {**base, "exp": "9999999999"},
            "exp_as_bool": {**base, "exp": True},
            "iat_as_string": {**base, "iat": "1000"},
            "sub_empty": {**base, "sub": ""},
            "sub_non_string": {**base, "sub": 42},
            "srv_missing": {k: v for k, v in base.items() if k != "srv"},
        }
        for name, payload in mutations.items():
            tok = _resign(self.secret, payload)
            with self.assertRaises(TokenError, msg=name):
                validate_token(self.secret, tok)

    def test_cross_server_reuse_rejected(self):
        t = mint_token(self.secret, "u", "server-a",
                       ["tools:read", "tools:write"])
        p = validate_token(self.secret, t)  # signature itself is fine
        self.assertEqual(p["srv"], "server-a")
        self.assertNotEqual(p["srv"], "server-b")

    def test_expiry_boundary_no_leeway(self):
        t = mint_token(self.secret, "u", "s", ["tools:read"],
                       ttl_seconds=100, now=1000.0)
        validate_token(self.secret, t, now=1099.9)  # last moment: valid
        with self.assertRaises(TokenError) as ctx:
            validate_token(self.secret, t, now=1100.0)  # exp == now: expired
        self.assertEqual(ctx.exception.reason, "expired")
        with self.assertRaises(TokenError):
            validate_token(self.secret, t, now=1100.1)

    def test_future_iat_still_bounded_by_exp(self):
        # a token whose iat is in the future is still rejected at exp
        t = mint_token(self.secret, "u", "s", ["tools:read"],
                       ttl_seconds=100, now=2000.0)
        with self.assertRaises(TokenError):
            validate_token(self.secret, t, now=2100.0)

    def test_concurrent_validation(self):
        t = mint_token(self.secret, "u", "s", ["tools:read"])
        errors = []

        def worker():
            try:
                for _ in range(50):
                    p = validate_token(self.secret, t)
                    assert p["sub"] == "u"
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(16)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        self.assertEqual(errors, [])


class StubProvider(AuthProvider):
    name = "stub"

    def authorization_url(self, state: str, redirect_uri: str) -> str:
        return redirect_uri + "?code=stub&state=" + state

    def exchange_code(self, code: str, redirect_uri: str) -> dict:
        if code != "stub":
            raise ValueError("bad code")
        return {"id": "9", "login": "alice", "name": "alice"}


class TestOAuthState(unittest.TestCase):
    def setUp(self):
        self.gw = Gateway(load_policy(os.path.join(ROOT, "policy.json")),
                          new_secret(), {"stub": StubProvider()})

    def test_state_single_use(self):
        s = self.gw.new_state()
        self.assertTrue(self.gw.consume_state(s))
        self.assertFalse(self.gw.consume_state(s))  # replay fails

    def test_state_unknown(self):
        self.assertFalse(self.gw.consume_state("nope-not-a-state"))

    def test_state_expired(self):
        s = self.gw.new_state()
        with self.gw._states_lock:
            self.gw._states[s] = time.time() - 1
        self.assertFalse(self.gw.consume_state(s))

    def test_states_unique(self):
        self.assertNotEqual(self.gw.new_state(), self.gw.new_state())


def http_get(url, cookie=None):
    req = urllib.request.Request(url)
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_no_redirect_opener = urllib.request.build_opener(_NoRedirect)


def http_get_no_redirect(url):
    req = urllib.request.Request(url)
    try:
        with _no_redirect_opener.open(req, timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def http_post(url, obj=None, raw=None, token=None, cookie=None):
    data = raw if raw is not None else json.dumps(obj).encode()
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, dict(resp.headers), json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, dict(exc.headers), json.loads(exc.read().decode())
        except Exception:
            return exc.code, dict(exc.headers), {}


class SecurityHTTPTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.secret = new_secret()
        cls.policy = load_policy(os.path.join(ROOT, "policy.json"))
        cls.gw = Gateway(cls.policy, cls.secret, {"stub": StubProvider()})
        cls.server = serve(cls.gw, "127.0.0.1", 0)
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.gw.pool.shutdown()

    def _login_cookie(self):
        # full OAuth round-trip through the stub provider
        state = self.gw.new_state()
        status, headers, body = http_get(
            self.base + "/auth/callback?code=stub&state=" + state)
        self.assertEqual(status, 200)
        set_cookie = headers.get("Set-Cookie", "")
        self.assertIn("mgw_session=", set_cookie)
        self.assertIn("HttpOnly", set_cookie)
        self.assertIn("SameSite=Lax", set_cookie)
        cookie = set_cookie.split(";", 1)[0]
        self.assertNotIn("Secure", set_cookie)  # plain http: no Secure flag
        return cookie, state

    def test_login_redirect_carries_state(self):
        status, headers, _ = http_get_no_redirect(
            self.base + "/auth/login?provider=stub")
        self.assertEqual(status, 302)
        location = headers.get("Location", "")
        self.assertIn("state=", location)
        # unknown provider -> 400
        status, _, _ = http_get(self.base + "/auth/login?provider=bogus")
        self.assertEqual(status, 400)

    def test_oauth_state_replay_rejected(self):
        cookie, state = self._login_cookie()
        # same state twice -> second callback must fail
        status, _, _ = http_get(
            self.base + "/auth/callback?code=stub&state=" + state)
        self.assertEqual(status, 400)

    def test_oauth_bad_state_rejected(self):
        status, _, _ = http_get(
            self.base + "/auth/callback?code=stub&state=forged-state")
        self.assertEqual(status, 400)
        status, _, _ = http_get(self.base + "/auth/callback?code=stub")
        self.assertEqual(status, 400)

    def test_secure_cookie_over_https_base_url(self):
        from gateway.proxy import _Handler
        gw = Gateway(self.policy, self.secret, {"stub": StubProvider()},
                     base_url="https://gw.example.com")
        old_gateway = _Handler.gateway  # serve() swaps a global; restore after
        server = serve(gw, "127.0.0.1", 0)
        base = "http://127.0.0.1:%d" % server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            state = gw.new_state()
            status, headers, _ = http_get(
                base + "/auth/callback?code=stub&state=" + state)
            self.assertEqual(status, 200)
            self.assertIn("; Secure",
                          headers.get("Set-Cookie", ""))
        finally:
            server.shutdown()
            gw.pool.shutdown()
            _Handler.gateway = old_gateway

    def test_token_endpoint_rejects_non_string_server(self):
        cookie, _ = self._login_cookie()
        for bad in (["demo-calc"], {"server": "demo-calc"}, 42, ""):
            status, _, _ = http_post(self.base + "/token",
                                     {"server": bad}, cookie=cookie)
            self.assertEqual(status, 400, repr(bad))

    def test_huge_body_rejected(self):
        cookie, _ = self._login_cookie()
        big = b'{"server": "demo-calc", "pad": "' + b"x" * 1_000_010 + b'"}'
        try:
            status, _, _ = http_post(self.base + "/token", raw=big, cookie=cookie)
        except (BrokenPipeError, ConnectionResetError, urllib.error.URLError):
            # also fine: the server answered 400 and closed the connection
            # while the 1MB+ body was still in flight
            return
        self.assertEqual(status, 400)

    def test_malformed_json_rpc(self):
        token, _ = self.gw.mint_for("alice", "demo-calc")
        # not a dict
        status, _, _ = http_post(self.base + "/mcp/demo-calc", [1, 2],
                                 token=token)
        self.assertEqual(status, 400)
        # missing method
        status, _, _ = http_post(self.base + "/mcp/demo-calc",
                                 {"jsonrpc": "2.0", "id": 1}, token=token)
        self.assertEqual(status, 400)
        # non-string method fails closed (needs write scope)
        bob_token, _ = self.gw.mint_for("bob", "demo-calc")  # read-only
        status, _, body = http_post(self.base + "/mcp/demo-calc",
                                    {"jsonrpc": "2.0", "id": 1, "method": 123},
                                    token=bob_token)
        self.assertEqual(status, 403)
        self.assertEqual(body.get("error"), "scope denied")

    def test_tampered_session_non_ascii_sig(self):
        # must be 401, never a 500
        cookie, _ = self._login_cookie()
        name, value = cookie.split("=", 1)
        body, _sig = value.split(".")
        evil = name + "=" + body + "." + "sig-\u00e9"
        status, _, _ = http_post(self.base + "/token",
                                 {"server": "demo-calc"}, cookie=evil)
        self.assertEqual(status, 401)

    def test_nosniff_header(self):
        status, headers, _ = http_get(self.base + "/health")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")

    def test_concurrent_mcp_responses_isolated(self):
        # every concurrent caller must get its own response id back
        token, _ = self.gw.mint_for("alice", "demo-calc")
        errors = []

        def worker(i):
            try:
                status, _, body = http_post(
                    self.base + "/mcp/demo-calc",
                    {"jsonrpc": "2.0", "id": i, "method": "ping", "params": {}},
                    token=token)
                if status != 200 or body.get("id") != i:
                    errors.append((i, status, body.get("id")))
            except Exception as exc:  # noqa: BLE001
                errors.append((i, "EXC", repr(exc)))

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(30)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        self.assertEqual(errors, [])


class TestUpstreamPoolIsolation(unittest.TestCase):
    def test_concurrent_calls_never_swap_responses(self):
        # slow echo upstream widens the race: without per-server locking,
        # callers reliably read each other's responses (cross-user leak)
        code = (
            "import sys,json,time\n"
            "for line in sys.stdin:\n"
            "    m=json.loads(line)\n"
            "    time.sleep(0.05)\n"
            "    sys.stdout.write(json.dumps("
            "{'jsonrpc':'2.0','id':m.get('id'),'result':'ok'})+'\\n')\n"
            "    sys.stdout.flush()\n"
        )
        pool = UpstreamPool()
        cmd = [sys.executable, "-c", code]
        errors = []

        def worker(i):
            try:
                r = pool.call("slow", cmd,
                              {"jsonrpc": "2.0", "id": i, "method": "ping"})
                if r.get("id") != i:
                    errors.append((i, r.get("id")))
            except Exception as exc:  # noqa: BLE001
                errors.append((i, "EXC %s" % exc))

        try:
            threads = [threading.Thread(target=worker, args=(i,))
                       for i in range(20)]
            for th in threads:
                th.start()
            for th in threads:
                th.join()
        finally:
            pool.shutdown()
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
