import time
import unittest

from gateway import tokens
from gateway.tokens import TokenError, mint_token, new_secret, validate_token


class TestTokens(unittest.TestCase):
    def setUp(self):
        self.secret = new_secret()

    def test_roundtrip(self):
        t = mint_token(self.secret, "alice", "srv1", ["tools:read", "tools:write"])
        p = validate_token(self.secret, t)
        self.assertEqual(p["sub"], "alice")
        self.assertEqual(p["srv"], "srv1")
        self.assertEqual(sorted(p["scp"]), ["tools:read", "tools:write"])
        self.assertLessEqual(p["iat"], p["exp"])

    def test_scopes_sorted_deduped(self):
        t = mint_token(self.secret, "u", "s", ["tools:write", "tools:read", "tools:read"])
        self.assertEqual(validate_token(self.secret, t)["scp"],
                         ["tools:read", "tools:write"])

    def test_expired(self):
        t = mint_token(self.secret, "u", "s", ["tools:read"], ttl_seconds=-5)
        with self.assertRaises(TokenError) as ctx:
            validate_token(self.secret, t)
        self.assertEqual(ctx.exception.reason, "expired")

    def test_expiry_boundary(self):
        t = mint_token(self.secret, "u", "s", ["tools:read"], ttl_seconds=100, now=1000.0)
        validate_token(self.secret, t, now=1099.0)  # still valid
        with self.assertRaises(TokenError):
            validate_token(self.secret, t, now=1100.0)  # exp == now -> expired

    def test_tampered_signature(self):
        t = mint_token(self.secret, "u", "s", ["tools:read"])
        forged = t[:-1] + ("A" if t[-1] != "A" else "B")
        with self.assertRaises(TokenError) as ctx:
            validate_token(self.secret, forged)
        self.assertEqual(ctx.exception.reason, "bad_signature")

    def test_tampered_payload(self):
        import base64, json
        parts = mint_token(self.secret, "u", "s", ["tools:read"]).split(".")
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        payload["scp"] = ["tools:read", "tools:write"]  # escalate!
        evil = parts[1]
        import re
        # re-encode without re-signing
        evil = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=").decode()
        with self.assertRaises(TokenError) as ctx:
            validate_token(self.secret, parts[0] + "." + evil + "." + parts[2])
        self.assertEqual(ctx.exception.reason, "bad_signature")

    def test_wrong_secret(self):
        t = mint_token(self.secret, "u", "s", ["tools:read"])
        with self.assertRaises(TokenError) as ctx:
            validate_token(new_secret(), t)
        self.assertEqual(ctx.exception.reason, "bad_signature")

    def test_malformed(self):
        for bad in ["", "abc", "a.b", "a.b.c.d", "...", "a.b.c"]:
            with self.assertRaises(TokenError, msg=bad):
                validate_token(self.secret, bad)

    def test_empty_secret_rejected(self):
        with self.assertRaises(ValueError):
            mint_token("", "u", "s", ["tools:read"])

    def test_empty_sub_or_server_rejected(self):
        with self.assertRaises(ValueError):
            mint_token(self.secret, "", "s", ["tools:read"])
        with self.assertRaises(ValueError):
            mint_token(self.secret, "u", "", ["tools:read"])

    def test_tokens_unique(self):
        a = mint_token(self.secret, "u", "s", ["tools:read"])
        b = mint_token(self.secret, "u", "s", ["tools:read"])
        self.assertNotEqual(a, b)  # jti differs

    def test_new_secret_strength(self):
        s = new_secret()
        self.assertEqual(len(s), 64)  # 32 bytes hex


if __name__ == "__main__":
    unittest.main()
