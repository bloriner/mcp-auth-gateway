# GitHub OAuth app setup

The gateway needs a GitHub OAuth App to log users in. Five minutes:

1. Go to https://github.com/settings/developers → **New OAuth App**.
2. Fill in:
   - **Application name:** anything, e.g. `My MCP Gateway`
   - **Homepage URL:** your gateway's public URL
   - **Authorization callback URL:** `https://<gateway-host>/auth/callback`
     (must match `GATEWAY_BASE_URL + /auth/callback` exactly)
3. Click **Register application**, then **Generate a new client secret**.
4. Start the gateway with the credentials:

```bash
GATEWAY_SECRET="$(python -m gateway --gen-secret)" \
GITHUB_CLIENT_ID=<client id> \
GITHUB_CLIENT_SECRET=<client secret> \
GATEWAY_BASE_URL=https://<gateway-host> \
python -m gateway --policy policy.json --port 8080
```

5. Send users to `https://<gateway-host>/auth/login?provider=github`.
   After they authorize, the callback sets a session cookie and returns
   the servers they're allowed on. `POST /token {"server": "<id>"}` mints
   their scoped token.

The gateway requests only `read:user` + `user:email` — the minimum needed
to identify the user for policy resolution. It never sees passwords and
never stores GitHub tokens beyond the single exchange.
