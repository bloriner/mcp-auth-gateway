#!/usr/bin/env python3
"""Demo MCP server: a tiny calculator behind the gateway.

Speaks MCP over newline-delimited JSON-RPC 2.0 on stdin/stdout.
Tools: add, multiply, echo.
"""

from __future__ import annotations

import json
import sys

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "demo-calc"
SERVER_VERSION = "0.1.0"

TOOLS = {
    "add": {
        "fn": lambda a: {"result": a["x"] + a["y"]},
        "description": "Add two numbers.",
        "inputSchema": {"type": "object",
                        "properties": {"x": {"type": "number"}, "y": {"type": "number"}},
                        "required": ["x", "y"]},
    },
    "multiply": {
        "fn": lambda a: {"result": a["x"] * a["y"]},
        "description": "Multiply two numbers.",
        "inputSchema": {"type": "object",
                        "properties": {"x": {"type": "number"}, "y": {"type": "number"}},
                        "required": ["x", "y"]},
    },
    "echo": {
        "fn": lambda a: {"echo": a.get("text", "")},
        "description": "Echo text back.",
        "inputSchema": {"type": "object",
                        "properties": {"text": {"type": "string"}}},
    },
}


def _ok(msg_id, result):
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _err(msg_id, code, message):
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def handle(msg: dict):
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or "method" not in msg:
        return None
    method, msg_id = msg["method"], msg.get("id")
    if method == "initialize":
        return _ok(msg_id, {"protocolVersion": PROTOCOL_VERSION,
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION}})
    if method == "notifications/initialized":
        return None
    if method == "ping":
        return _ok(msg_id, {})
    if method == "tools/list":
        return _ok(msg_id, {"tools": [
            {"name": n, "description": t["description"], "inputSchema": t["inputSchema"]}
            for n, t in TOOLS.items()]})
    if method == "tools/call":
        params = msg.get("params") or {}
        name, args = params.get("name"), params.get("arguments") or {}
        tool = TOOLS.get(name)
        if tool is None:
            result = {"content": [{"type": "text", "text": "unknown tool: %s" % name}],
                      "isError": True}
        else:
            try:
                result = {"content": [{"type": "text",
                                       "text": json.dumps(tool["fn"](args))}]}
            except Exception as exc:
                result = {"content": [{"type": "text", "text": str(exc)}],
                          "isError": True}
        return _ok(msg_id, result)
    if "id" not in msg:
        return None
    return _err(msg_id, -32601, "Method not found: %s" % method)


def serve():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    serve()
