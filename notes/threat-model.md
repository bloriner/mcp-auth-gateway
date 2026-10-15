# Threat model — MCP auth gateway v0.1

## Threats and mitigations

### 1. Token theft
An attacker who steals a Bearer token can use it until it expires.
**Mitigated:** tokens are short-lived (15 min default) and bound to one
server — a stolen token can't be used anywhere else. Not mitigated: use
over the network without TLS (deploy behind HTTPS; the gateway itself
doesn't terminate TLS in v0.1). Future: sender-constrained tokens
(DPoP/mTLS).

### 2. Token forgery / tampering
An attacker mints their own token or escalates scopes (e.g. flipping
`tools:read` to `tools:write`).
**Mitigated:** HMAC-SHA256 with a 256-bit secret; signatures compared
with `hmac.compare_digest`. Any bit flip invalidates the token
(tested: `test_tampered_signature`, `test_tampered_payload`).

### 3. Replay
A captured token reused within its lifetime.
**Partially mitigated:** 15-minute window bounds the damage; each token
carries a unique `jti` so a future replay-detection cache can reject
reused tokens. Future: jti replay cache on the hosted version.

### 4. Scope escalation via policy
A user edits the policy file to grant themselves more.
**Mitigated:** the policy file lives server-side; users only ever see
the scopes the gateway minted for them. Policy changes require
deploy access, not user access.

### 5. Cross-server token reuse
Using a token minted for server A against server B.
**Mitigated:** the server id is inside the signed payload and checked
against the URL path on every request (tested).

### 6. Rogue / compromised upstream server
The gateway proxies to whatever the policy file points at; a malicious
upstream could exfiltrate data the user's token legitimately unlocked.
**Not mitigated in v0.1** — upstream servers are trusted by
configuration, like any reverse proxy backend. Future: per-server
egress review, response schema validation.

### 7. OAuth flow attacks (CSRF, code interception)
**Mitigated:** `state` parameter is random, single-use, 10-minute
expiry, and verified on callback. Not mitigated: PKCE (v0.1 uses the
plain code flow server-side, where the client secret already protects
the exchange).

### 8. Session cookie theft
**Mitigated:** cookies are HMAC-signed and HttpOnly; theft only yields
token-minting ability within the session TTL, and minted tokens are
still policy-bounded. Future: bind sessions to IP/User-Agent.

### 9. Upstream impersonation of the gateway
An attacker who can reach the upstream stdio server directly bypasses
auth entirely.
**Not mitigated by design** — upstreams must not be network-reachable.
Run them on the same host (or a private network) and treat the gateway
as the only ingress. Documented in README quickstart.

## Deliberately out of scope for v0.1
- Revocation lists (TTL is the revocation mechanism)
- Refresh token rotation
- Audit logging (hosted version)
- Rate limiting per token (hosted version)
