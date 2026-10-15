#!/usr/bin/env python3
"""Run the MCP auth gateway.

    python -m gateway --policy policy.json --port 8080

The gateway secret signs tokens and session cookies. Pass it with
``--secret`` or the ``GATEWAY_SECRET`` environment variable (generate
one with ``python -c "from gateway.tokens import new_secret; print(new_secret())"``).

GitHub OAuth is enabled with --github-client-id / --github-client-secret
(or GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET). Without them, only the
``demo`` provider exists — do not expose that publicly.
"""

from __future__ import annotations

import argparse
import os
import sys

from .auth import DemoAuthProvider, GitHubAuthProvider
from .policy import load_policy
from .proxy import Gateway, serve
from .tokens import new_secret


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="MCP auth gateway")
    ap.add_argument("--policy", default="policy.json")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--secret", default=os.environ.get("GATEWAY_SECRET", ""))
    ap.add_argument("--github-client-id",
                    default=os.environ.get("GITHUB_CLIENT_ID", ""))
    ap.add_argument("--github-client-secret",
                    default=os.environ.get("GITHUB_CLIENT_SECRET", ""))
    ap.add_argument("--base-url", default=os.environ.get("GATEWAY_BASE_URL", ""),
                    help="Public base URL, e.g. https://gateway.example.com")
    ap.add_argument("--gen-secret", action="store_true",
                    help="Print a fresh secret and exit")
    args = ap.parse_args(argv)

    if args.gen_secret:
        print(new_secret())
        return 0

    secret = args.secret
    if not secret:
        print("error: set --secret or GATEWAY_SECRET", file=sys.stderr)
        return 2

    policy = load_policy(args.policy)
    providers: dict = {}
    if args.github_client_id and args.github_client_secret:
        providers["github"] = GitHubAuthProvider(args.github_client_id,
                                                 args.github_client_secret)
    else:
        providers["demo"] = DemoAuthProvider()
        print("warning: no GitHub OAuth configured; using INSECURE demo provider",
              file=sys.stderr)

    gw = Gateway(policy, secret, providers, base_url=args.base_url)
    server = serve(gw, args.host, args.port)
    print("mcp-auth-gateway on http://%s:%d (%d servers, providers: %s)"
          % (args.host, args.port, len(policy.server_ids), ",".join(providers)))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        gw.pool.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
