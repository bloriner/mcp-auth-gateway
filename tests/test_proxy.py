import json
import os
import threading
import time
import unittest
import urllib.error
import urllib.request

from gateway import tokens
from gateway.auth import DemoAuthProvider
from gateway.policy import load_policy
from gateway.proxy import Gateway, serve

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def http_post(url, obj, token=None, cookie=None):
    req = urllib.request.Request(url, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode())
        except Exception:
            return exc.code, {}


RPC_LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
RPC_CALL = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "multiply", "arguments": {"x": 6, "y": 7}}}


class ProxyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.secret = tokens.new_secret()
        cls.policy = load_policy(os.path.join(ROOT, "policy.json"))
        cls.gw = Gateway(cls.policy, cls.secret, {"demo": DemoAuthProvider()})
        cls.server = serve(cls.gw, "127.0.0.1", 0)
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.gw.pool.shutdown()

    def mcp(self, server_id, rpc, token=None):
        return http_post(self.base + "/mcp/" + server_id, rpc, token=token)

    def test_initialize_and_tool_call(self):
        token, _ = self.gw.mint_for("alice", "demo-calc")
        status, body = self.mcp("demo-calc",
                                {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                 "params": {}}, token)
        self.assertEqual(status, 200)
        self.assertEqual(body["result"]["serverInfo"]["name"], "demo-calc")
        status, body = self.mcp("demo-calc", RPC_CALL, token)
        self.assertEqual(status, 200)
        inner = json.loads(body["result"]["content"][0]["text"])
        self.assertEqual(inner["result"], 42)

    def test_scope_denied(self):
        token, scopes = self.gw.mint_for("bob", "demo-calc")
        self.assertEqual(scopes, ["tools:read"])
        status, body = self.mcp("demo-calc", RPC_CALL, token)
        self.assertEqual(status, 403)
        self.assertEqual(body["error"], "scope denied")
        # read still works
        status, _ = self.mcp("demo-calc", RPC_LIST, token)
        self.assertEqual(status, 200)

    def test_expired_token(self):
        token = tokens.mint_token(self.secret, "alice", "demo-calc",
                                  ["tools:read", "tools:write"], ttl_seconds=-5)
        status, body = self.mcp("demo-calc", RPC_LIST, token)
        self.assertEqual(status, 401)
        self.assertEqual(body["reason"], "expired")

    def test_forged_token(self):
        token, _ = self.gw.mint_for("alice", "demo-calc")
        forged = token[:-1] + ("A" if token[-1] != "A" else "B")
        status, body = self.mcp("demo-calc", RPC_LIST, forged)
        self.assertEqual(status, 401)
        self.assertEqual(body["reason"], "bad_signature")

    def test_missing_token(self):
        status, body = self.mcp("demo-calc", RPC_LIST, None)
        self.assertEqual(status, 401)

    def test_cross_server_token(self):
        token = tokens.mint_token(self.secret, "alice", "other",
                                  ["tools:read", "tools:write"])
        status, _ = self.mcp("demo-calc", RPC_LIST, token)
        self.assertEqual(status, 403)

    def test_token_mint_endpoint(self):
        session = self.gw.make_session({"login": "alice", "id": "1"})
        cookie = "mgw_session=" + session
        status, body = http_post(self.base + "/token", {"server": "demo-calc"},
                                 cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual(body["scopes"], ["tools:read", "tools:write"])
        # the minted token actually works
        status, _ = self.mcp("demo-calc", RPC_LIST, body["token"])
        self.assertEqual(status, 200)

    def test_token_mint_requires_login(self):
        status, _ = http_post(self.base + "/token", {"server": "demo-calc"})
        self.assertEqual(status, 401)

    def test_token_mint_no_access(self):
        # carol has no grant and wildcard only covers demo-calc read... use unknown server
        session = self.gw.make_session({"login": "carol", "id": "3"})
        cookie = "mgw_session=" + session
        status, body = http_post(self.base + "/token", {"server": "nope"},
                                 cookie=cookie)
        self.assertEqual(status, 403)

    def test_tampered_session_rejected(self):
        session = self.gw.make_session({"login": "alice", "id": "1"})
        bad = session[:-1] + ("A" if session[-1] != "A" else "B")
        status, _ = http_post(self.base + "/token", {"server": "demo-calc"},
                              cookie="mgw_session=" + bad)
        self.assertEqual(status, 401)

    def test_bad_json_rpc(self):
        token, _ = self.gw.mint_for("alice", "demo-calc")
        status, _ = self.mcp("demo-calc", {"nope": True}, token)
        self.assertEqual(status, 400)

    def test_unknown_server_path(self):
        token = tokens.mint_token(self.secret, "alice", "demo-calc",
                                  ["tools:read"])
        # path traversal attempt is rejected as 404
        status, _ = http_post(self.base + "/mcp/../x", RPC_LIST, token=token)
        self.assertIn(status, (403, 404))


if __name__ == "__main__":
    unittest.main()
