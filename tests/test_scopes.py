import unittest

from gateway.scopes import SCOPE_READ, SCOPE_WRITE, has_scope, required_scope


class TestScopes(unittest.TestCase):
    def test_read_methods(self):
        for m in ["initialize", "ping", "tools/list", "resources/list",
                  "resources/templates/list", "resources/read",
                  "prompts/list", "prompts/get", "completion/complete"]:
            self.assertEqual(required_scope(m), SCOPE_READ, m)

    def test_write_methods(self):
        for m in ["tools/call", "resources/subscribe", "logging/setLevel",
                  "sampling/createMessage", "elicitation/create"]:
            self.assertEqual(required_scope(m), SCOPE_WRITE, m)

    def test_notifications_need_no_scope(self):
        self.assertIsNone(required_scope("notifications/initialized"))
        self.assertIsNone(required_scope("notifications/tools/list_changed"))

    def test_unknown_method_fails_closed(self):
        self.assertEqual(required_scope("something/new"), SCOPE_WRITE)
        self.assertEqual(required_scope(""), SCOPE_WRITE)
        self.assertEqual(required_scope(None), SCOPE_WRITE)

    def test_has_scope(self):
        self.assertTrue(has_scope(["tools:read"], "tools/list"))
        self.assertTrue(has_scope(["tools:read"], "initialize"))
        self.assertFalse(has_scope(["tools:read"], "tools/call"))
        self.assertTrue(has_scope(["tools:read", "tools:write"], "tools/call"))
        self.assertTrue(has_scope(["tools:read"], "notifications/initialized"))
        self.assertTrue(has_scope([], "notifications/initialized"))
        self.assertFalse(has_scope([], "tools/list"))
        self.assertFalse(has_scope(None, "tools/call"))


if __name__ == "__main__":
    unittest.main()
