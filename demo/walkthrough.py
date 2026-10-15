#!/usr/bin/env python3
"""End-to-end walkthrough: login -> grant -> scoped token -> gateway.

Shows: allowed call succeeds, out-of-scope call is rejected, expired
token is rejected, forged token is rejected.

Run from the repo root:  python3 demo/walkthrough.py
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gateway import tokens
from gateway.auth import DemoAuthProvider
from gateway.policy import load_policy
from gateway.proxy import Gateway, serve

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
results = []


def check(name: str, ok: bool, detail: str = ""):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + ((" — " + detail) if detail else ""))


def post(url: str, obj: dict, token: str | None = None):
    req = urllib.request.Request(
        url, data=json.dumps(obj).encode(),
        headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode())
        except Exception:
            return exc.code, {}


def main() -> int:
    secret = tokens.new_secret()
    policy = load_policy(os.path.join(ROOT, "policy.json"))
    auth = DemoAuthProvider()

    # 1. login (demo provider trusts the username)
    alice = auth.login_as("alice")
    check("login as alice", alice["login"] == "alice")

    # 2. grant: policy says alice gets read+write on demo-calc
    gw = Gateway(policy, secret, {"demo": auth})
    token, scopes = gw.mint_for("alice", "demo-calc")
    check("grant scopes for alice", scopes == ["tools:read", "tools:write"],
          ",".join(scopes))

    # 3. start the real HTTP gateway
    server = serve(gw, "127.0.0.1", 0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = "http://127.0.0.1:%d" % port

    rpc = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    status, body = post(base + "/mcp/demo-calc", rpc, token)
    check("allowed call: initialize", status == 200 and
          body.get("result", {}).get("serverInfo", {}).get("name") == "demo-calc",
          "http %d" % status)

    rpc = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
           "params": {"name": "add", "arguments": {"x": 2, "y": 2}}}
    status, body = post(base + "/mcp/demo-calc", rpc, token)
    try:
        inner = json.loads(body["result"]["content"][0]["text"])
        ok = status == 200 and inner.get("result") == 4
    except (KeyError, IndexError, TypeError, ValueError):
        ok = False
    check("allowed call: tools/call add(2,2)=4", ok, "http %d" % status)

    # 4. out-of-scope: bob only has the wildcard tools:read grant
    bob_token, bob_scopes = gw.mint_for("bob", "demo-calc")
    check("bob gets read-only grant", bob_scopes == ["tools:read"])
    status, body = post(base + "/mcp/demo-calc", rpc, bob_token)
    check("out-of-scope call rejected", status == 403 and
          body.get("error") == "scope denied", "http %d" % status)
    # ...but bob CAN list tools
    rpc_list = {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}
    status, body = post(base + "/mcp/demo-calc", rpc_list, bob_token)
    check("read call allowed for bob", status == 200 and "tools" in body.get("result", {}),
          "http %d" % status)

    # 5. expired token
    expired = tokens.mint_token(secret, "alice", "demo-calc",
                               ["tools:read", "tools:write"], ttl_seconds=-10)
    status, body = post(base + "/mcp/demo-calc", rpc_list, expired)
    check("expired token rejected", status == 401 and
          body.get("reason") == "expired", "http %d" % status)

    # 6. forged token (flip the last signature char)
    forged = token[:-1] + ("A" if token[-1] != "A" else "B")
    status, body = post(base + "/mcp/demo-calc", rpc_list, forged)
    check("forged token rejected", status == 401 and
          body.get("reason") == "bad_signature", "http %d" % status)

    # 7. token minted for a different server
    other = tokens.mint_token(secret, "alice", "other-server",
                             ["tools:read", "tools:write"])
    status, body = post(base + "/mcp/demo-calc", rpc_list, other)
    check("cross-server token rejected", status == 403, "http %d" % status)

    # 8. no token at all
    status, body = post(base + "/mcp/demo-calc", rpc_list, None)
    check("missing token rejected", status == 401, "http %d" % status)

    server.shutdown()
    gw.pool.shutdown()
    print("\n%d/%d checks passed" % (sum(results), len(results)))
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
