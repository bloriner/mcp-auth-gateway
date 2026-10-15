#!/usr/bin/env python3
"""Policy file: which users may access which servers, with what scopes.

policy.json shape::

    {
      "servers": {
        "<server_id>": {
          "command": ["python3", "demo/server.py"],
          "default_scopes": ["tools:read"],
          "description": "..."
        }
      },
      "grants": {
        "<user>": {"<server_id>": ["tools:read", "tools:write"]},
        "*":      {"<server_id>": ["tools:read"]}
      }
    }

Resolution order for (user, server): explicit user grant -> "*" grant ->
server ``default_scopes`` -> no access. Commands given as relative paths
are resolved against the directory containing the policy file.
"""

from __future__ import annotations

import json
import os


class PolicyError(Exception):
    pass


class Policy:
    def __init__(self, data: dict, base_dir: str):
        self._data = data
        self._base_dir = base_dir

    @property
    def server_ids(self):
        return list(self._data.get("servers", {}).keys())

    def get_server(self, server_id: str) -> dict:
        try:
            return self._data["servers"][server_id]
        except KeyError:
            raise PolicyError("unknown server: %s" % server_id) from None

    def server_command(self, server_id: str) -> list:
        cmd = self.get_server(server_id).get("command")
        if not cmd or not isinstance(cmd, list):
            raise PolicyError("server %s has no command" % server_id)
        prog = cmd[0]
        if not os.path.isabs(prog):
            maybe = os.path.join(self._base_dir, prog)
            if os.path.exists(maybe):
                return [maybe] + cmd[1:]
        return cmd

    def resolve_scopes(self, user: str, server_id: str) -> list:
        """Scopes this user holds on this server (may be empty)."""
        if server_id not in self._data.get("servers", {}):
            raise PolicyError("unknown server: %s" % server_id)
        grants = self._data.get("grants", {})
        user_grant = grants.get(user, {}).get(server_id)
        if user_grant is not None:
            return sorted(set(user_grant))
        wild_grant = grants.get("*", {}).get(server_id)
        if wild_grant is not None:
            return sorted(set(wild_grant))
        default = self.get_server(server_id).get("default_scopes") or []
        return sorted(set(default))

    def allowed_servers(self, user: str) -> dict:
        """{server_id: scopes} for every server the user can reach."""
        out = {}
        for sid in self.server_ids:
            scopes = self.resolve_scopes(user, sid)
            if scopes:
                out[sid] = scopes
        return out


def load_policy(path: str) -> Policy:
    if not os.path.exists(path):
        raise PolicyError("policy file not found: %s" % path)
    with open(path, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as exc:
            raise PolicyError("policy file is not valid JSON: %s" % exc) from exc
    if not isinstance(data, dict):
        raise PolicyError("policy file must contain a JSON object")
    return Policy(data, os.path.dirname(os.path.abspath(path)))
