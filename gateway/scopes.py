#!/usr/bin/env python3
"""Which MCP methods require which scope.

Scope model (v0.1):
  - ``tools:read``  — introspection: initialize, ping, tools/list,
    resources/*, prompts/*, completion.
  - ``tools:write`` — actions: tools/call and other state-changing or
    privileged methods (sampling, elicitation, logging level changes).

Notifications (``notifications/*``) require a *valid token* but no
specific scope — they carry no data out and change no state.
"""

from __future__ import annotations

SCOPE_READ = "tools:read"
SCOPE_WRITE = "tools:write"

_READ_METHODS = frozenset({
    "initialize",
    "ping",
    "tools/list",
    "resources/list",
    "resources/templates/list",
    "resources/read",
    "prompts/list",
    "prompts/get",
    "completion/complete",
})

_WRITE_METHODS = frozenset({
    "tools/call",
    "resources/subscribe",
    "resources/unsubscribe",
    "logging/setLevel",
    "sampling/createMessage",
    "elicitation/create",
    "roots/list_changed",
})


def required_scope(method: str) -> str | None:
    """Return the scope a JSON-RPC method needs, or None if it needs
    only a valid token (notifications). Unknown methods are treated as
    write — fail closed."""
    if not isinstance(method, str):
        return SCOPE_WRITE
    if method.startswith("notifications/"):
        return None
    if method in _READ_METHODS:
        return SCOPE_READ
    return SCOPE_WRITE


def has_scope(token_scopes, method: str) -> bool:
    """True if the token's scope set authorizes the method."""
    need = required_scope(method)
    if need is None:
        return True
    return need in set(token_scopes or [])
