# MCP Auth Gateway

**Every MCP server gets real auth. The server author writes none.**

Right now, MCP servers have two settings: wide open, or "roll your own OAuth and get it wrong." There is no standard way to say *"Alice's coding agent may call tools on the production database server, but only read-only, and only for the next 15 minutes."* This gateway is that standard: a reverse proxy that sits in front of any stdio MCP server and adds GitHub login, per-server scoped tokens, and a policy file — with zero changes to the server.

## How it works

```
agent --(Bearer token)--> gateway --(stdio)--> your MCP server (unchanged)
```

1. The user logs in once via GitHub OAuth.
2. The gateway mints a short-lived token bound to **(user, server, scopes)** — e.g. `alice` + `prod-db` + `["tools:read"]`.
3. Every request through the gateway is validated: signature, expiry, server binding, and scope for the exact method being called (`tools/list` needs `tools:read`; `tools/call` needs `tools:write`).
4. Valid requests are proxied to the upstream server over stdio. Rejected ones get a clear error: expired, forged, wrong server, or out of scope.

## Quickstart

```bash
# 1. generate a secret
python -m gateway --gen-secret   # put it in GATEWAY_SECRET

# 2. run with the demo policy (insecure demo auth — local use only)
GATEWAY_SECRET=<secret> python -m gateway --policy policy.json --port 8080

# 3. walk through the whole story
python3 demo/walkthrough.py
```

The walkthrough shows: login → scoped grant → allowed call succeeds →
out-of-scope call rejected (403) → expired token rejected (401) →
forged token rejected (401).

With real GitHub OAuth:

```bash
GATEWAY_SECRET=<secret> \
GITHUB_CLIENT_ID=<id> GITHUB_CLIENT_SECRET=<secret> \
GATEWAY_BASE_URL=https://gateway.example.com \
python -m gateway --policy policy.json --port 8080
```

Then: `GET /auth/login?provider=github` → authorize → `POST /token {"server": "<id>"}` → use the token as `Authorization: Bearer` on `POST /mcp/<id>`. See `notes/oauth-setup.md`.

## Policy file

`policy.json` declares servers and who may use them:

```json
{
  "servers": {
    "prod-db": {"command": ["python3", "db_server.py"],
                "default_scopes": ["tools:read"]}
  },
  "grants": {
    "alice": {"prod-db": ["tools:read", "tools:write"]},
    "*":     {"prod-db": ["tools:read"]}
  }
}
```

Resolution: explicit user grant → `*` grant → server default → no access.

## The money path

This repo is the open core — free forever, self-host it. The hosted cloud version is the business:

- **Per-seat pricing.** Teams pay per developer/agent identity per month. The gateway is the control plane every MCP deployment needs, and nobody wants to run auth infrastructure themselves.
- **Why we'll win it:** the open-source gateway becomes the standard; the hosted version adds the things enterprises pay for — SSO/SAML, audit logs, team management, multi-region, uptime SLA, token analytics ("which agent called what, when").
- **Land-and-expand:** one team puts one server behind the gateway; six months later all their MCP servers run through it.

## Honest v0.1 limits

- GitHub OAuth only (the auth module is pluggable — Google next).
- Single node: no shared revocation list (mitigated by 15-minute token TTLs).
- No refresh-token rotation yet; clients re-mint via their session.
- Upstream servers must speak stdio MCP; no SSE upstream yet.
- Demo provider is **insecure by design** — never expose it.

See `notes/threat-model.md` for what's mitigated and what's future work.
