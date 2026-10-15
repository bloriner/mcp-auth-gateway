import json
import os
import tempfile
import unittest

from gateway.policy import PolicyError, load_policy

POLICY = {
    "servers": {
        "s1": {"command": ["python3", "x.py"], "default_scopes": ["tools:read"]},
        "s2": {"command": ["python3", "y.py"]},
    },
    "grants": {
        "alice": {"s1": ["tools:read", "tools:write"]},
        "*": {"s1": ["tools:read"], "s2": ["tools:read"]},
    },
}


def write_policy(data):
    f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(data, f)
    f.close()
    return f.name


class TestPolicy(unittest.TestCase):
    def setUp(self):
        self.path = write_policy(POLICY)

    def tearDown(self):
        os.unlink(self.path)

    def test_explicit_grant_wins(self):
        p = load_policy(self.path)
        self.assertEqual(p.resolve_scopes("alice", "s1"),
                         ["tools:read", "tools:write"])

    def test_wildcard_grant(self):
        p = load_policy(self.path)
        self.assertEqual(p.resolve_scopes("bob", "s1"), ["tools:read"])
        self.assertEqual(p.resolve_scopes("anyone", "s2"), ["tools:read"])

    def test_default_scopes_fallback(self):
        data = {"servers": {"s1": {"command": ["x"],
                                    "default_scopes": ["tools:read"]}},
                "grants": {}}
        path = write_policy(data)
        try:
            p = load_policy(path)
            self.assertEqual(p.resolve_scopes("nobody", "s1"), ["tools:read"])
        finally:
            os.unlink(path)

    def test_no_access(self):
        data = {"servers": {"s9": {"command": ["x"]}}, "grants": {}}
        path = write_policy(data)
        try:
            p = load_policy(path)
            self.assertEqual(p.resolve_scopes("nobody", "s9"), [])
        finally:
            os.unlink(path)

    def test_unknown_server(self):
        p = load_policy(self.path)
        with self.assertRaises(PolicyError):
            p.resolve_scopes("alice", "nope")
        with self.assertRaises(PolicyError):
            p.get_server("nope")

    def test_missing_file(self):
        with self.assertRaises(PolicyError):
            load_policy("/nonexistent/policy.json")

    def test_invalid_json(self):
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        f.write("{not json")
        f.close()
        try:
            with self.assertRaises(PolicyError):
                load_policy(f.name)
        finally:
            os.unlink(f.name)

    def test_allowed_servers(self):
        p = load_policy(self.path)
        self.assertEqual(p.allowed_servers("alice"),
                         {"s1": ["tools:read", "tools:write"],
                          "s2": ["tools:read"]})
        self.assertEqual(p.allowed_servers("bob"),
                         {"s1": ["tools:read"], "s2": ["tools:read"]})

    def test_scopes_deduped_sorted(self):
        data = {"servers": {"s1": {"command": ["x"]}},
                "grants": {"u": {"s1": ["tools:write", "tools:read", "tools:write"]}}}
        path = write_policy(data)
        try:
            p = load_policy(path)
            self.assertEqual(p.resolve_scopes("u", "s1"),
                             ["tools:read", "tools:write"])
        finally:
            os.unlink(path)

    def test_relative_command_resolved_to_policy_dir(self):
        d = tempfile.mkdtemp()
        try:
            open(os.path.join(d, "x.py"), "w").close()
            path = os.path.join(d, "policy.json")
            with open(path, "w") as f:
                json.dump({"servers": {"s1": {"command": ["x.py"]}},
                           "grants": {}}, f)
            p = load_policy(path)
            cmd = p.server_command("s1")
            self.assertTrue(os.path.isabs(cmd[0]))
            self.assertEqual(cmd[0], os.path.join(d, "x.py"))
        finally:
            import shutil
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
