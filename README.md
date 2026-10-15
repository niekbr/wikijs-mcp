# WikiJS MCP Server

An MCP server that connects Claude to your [Wiki.js](https://js.wiki/) 2.5 instance,
**as each signed-in wiki user**. Search, read and (optionally) edit wiki pages through
natural language, with exactly the rights that user has in Wiki.js.

> This is a fork of [jaalbin24/wikijs-mcp](https://github.com/jaalbin24/wikijs-mcp).
> The original runs locally with one Wiki.js API key that has full access. This fork
> is a centrally hosted server without an API key: every user signs in through the
> wiki's own login (e.g. SSO), and every request runs with that user's own Wiki.js
> session.

## How it works

```
Claude ──OAuth token──▶ nginx ──/mcp/──▶ wikijs-mcp ──user's Wiki.js JWT──▶ Wiki.js
                          │                    ▲
                          └──── everything else ──────────────────────────▶ Wiki.js
```

- The MCP server lives under `/mcp/` on the **same host name as the wiki**. That is
  required: after a user signs in through Wiki.js, the server takes over Wiki.js's
  login cookie.
- **Connecting a client:** clients connect through OAuth: Claude Code, claude.ai and
  Claude Desktop. When a user adds the server, the client opens the normal Wiki.js
  login (and so your identity provider), and then a consent screen. The server
  stores the resulting Wiki.js session, encrypted. There are no personal tokens to
  copy around.
- **Rights:** Wiki.js decides everything — groups, page rules, deactivated accounts.
  The server has no API key and no permission logic of its own. A page you may not
  see behaves as if it does not exist.

## Tools

| Tool | Description |
|------|-------------|
| `wiki_search` | Search the pages you may read |
| `wiki_get_page` | A page by path (preferred) or ID; also past versions (`version_id`) or metadata only |
| `wiki_list_pages` | List pages with tag filtering and sort order |
| `wiki_get_tree` | The folder/page tree |
| `wiki_list_tags` | Tags used on pages you may read |
| `wiki_get_site_info` | The wiki's URL, default locale and namespacing |
| `wiki_get_history` | Edit history of a page |
| `wiki_get_version` | One historical version of a page |
| `wiki_whoami` | Your name, groups and permissions, also effective permissions on one page |
| `wiki_create_page`* | Create a page |
| `wiki_update_page`* | Update a page, by full content or surgical find-and-replace (`edits`) |
| `wiki_move_page`* | Move a page (needs `manage:pages`) |
| `wiki_delete_page`* | Delete a page (needs `delete:pages`) |

\* Only with `WIKIJS_MCP_READ_ONLY=false`. Wiki.js still checks each user's rights.

**Rights users need in Wiki.js:**
- `read:pages` to find pages.
- **`read:source`** to read page content. Wiki.js's API only returns page content to
  page managers, so the server reads the page source view, which needs this right.
- `read:history` for history and versions.
- `write:pages` to edit.

Give the groups both the permission and a page rule that grants it.

## Deployment (Wiki.js in an LXC container, nginx in front)

This setup runs wikijs-mcp as a systemd service inside the same LXC container as
Wiki.js, and adds a few locations to the nginx reverse proxy that terminates TLS.

### 1. Install in the Wiki.js container

```bash
apt install python3-venv git
useradd --system --home /nonexistent --shell /usr/sbin/nologin wikijs-mcp
git clone <this repository> /opt/wikijs-mcp/src
python3 -m venv /opt/wikijs-mcp/venv
/opt/wikijs-mcp/venv/bin/pip install /opt/wikijs-mcp/src
```

Python 3.10 or newer is required.

### 2. Configure

```bash
install -d -m 750 /etc/wikijs-mcp
install -m 600 /opt/wikijs-mcp/src/.env.example /etc/wikijs-mcp/env
# Generate the encryption key and put it in WIKIJS_MCP_ENCRYPTION_KEY:
/opt/wikijs-mcp/venv/bin/python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
editor /etc/wikijs-mcp/env
```

[.env.example](.env.example) documents every setting. The important ones:

- `WIKIJS_URL`: Wiki.js as seen from this container, e.g. `http://127.0.0.1:3000`.
- `WIKIJS_PUBLIC_URL`: the address users open, e.g. `https://wiki.example.com`.
- `WIKIJS_STRATEGY_KEY`: the key of your SSO login strategy. Find it under
  Administration → Authentication, or as the last part of the login button's link
  (`/login/<key>`).
- `WIKIJS_MCP_HOST` and `WIKIJS_MCP_FORWARDED_ALLOW_IPS`: the proxy runs in another
  container, so listen on this container's address and trust forwarded headers only
  from the proxy's IP.
- `WIKIJS_TOKEN_RENEWAL`: must equal Administration → Security → Token Renewal
  Period.

### 3. Run

```bash
cp /opt/wikijs-mcp/src/deploy/lxc/wikijs-mcp.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now wikijs-mcp
journalctl -u wikijs-mcp -f
```

The unit is hardened (`ProtectSystem=strict`, no capabilities, a syscall filter). In an
unprivileged LXC container without nesting, systemd may fail to set up the sandbox
(`status=226/NAMESPACE`). Enable nesting for the container, or comment out the
`Protect*`/`Private*` lines.

### 4. nginx

Add [deploy/nginx/wikijs-mcp.conf](deploy/nginx/wikijs-mcp.conf) to the proxy:
- the `upstream` and `limit_req_zone` lines at `http` level
- the locations inside the wiki's `server` block, **before** `location /`

Then set the upstream address to the Wiki.js container, and run
`nginx -t && systemctl reload nginx`.

The two `/.well-known/...` locations are required: MCP clients discover the sign-in
through them. Everything else under `/.well-known` stays with Wiki.js.

### 5. Check

- `https://wiki.example.com/mcp/apps` → the wiki's login → the connected-apps page.
- `curl -i -X POST https://wiki.example.com/mcp/` → `401` with a `WWW-Authenticate`
  header.

### Updating

```bash
git -C /opt/wikijs-mcp/src pull
/opt/wikijs-mcp/venv/bin/pip install /opt/wikijs-mcp/src
systemctl restart wikijs-mcp
```

The database schema is upgraded automatically. To back it up, back up
`/var/lib/wikijs-mcp/` together with `/etc/wikijs-mcp/env`.

## Using it

### Claude Code

```bash
claude mcp add --transport http wikijs https://wiki.example.com/mcp/
```

Then run `/mcp` in Claude Code, choose `wikijs` and **Authenticate**: sign in to the
wiki and allow access.

### claude.ai and Claude Desktop

Add a custom connector with the URL `https://wiki.example.com/mcp/`. The wiki has to
be reachable from the internet for claude.ai.

### Disconnecting

`https://wiki.example.com/mcp/apps` lists a user's connected apps, each with a
**Disconnect** button. Deactivating a user in Wiki.js also stops their access at
once.

## Sessions and lifetimes

- **Wiki session:** the stored Wiki.js session lapses when none of a user's apps is
  used for longer than the Token Renewal Period (Wiki.js default: 14 days). There is
  deliberately no background job that keeps it alive.
- **Sign-in:** at most `WIKIJS_MCP_SESSION_MAX_AGE` (default 30 days) after the last
  sign-in, users must sign in again, even when they use the server daily. That way
  your identity provider stays in control (e.g. for removed accounts or MFA).
- **Signing in again:** when the wiki session lapses, the sign-in is too old, or Wiki.js
  rejects the session (e.g. a deactivated account), the server answers the app with
  `401`. The app then runs the sign-in again by itself. In Claude Code: `/mcp` →
  re-authenticate.
- **Tokens:** OAuth access tokens last 1 hour, and refresh tokens rotate on every use.
- **Logging out of the wiki** does not disconnect apps. Disconnect them on `/mcp/apps`.

## Security notes

- **Encryption:** stored Wiki.js sessions are encrypted with `WIKIJS_MCP_ENCRYPTION_KEY`.
  This mainly protects a **leaked copy of the database** (e.g. a backup). Someone with
  access to the running container also has the key.
- **Hashing:** access tokens, refresh tokens, authorization codes and web session ids are
  stored only as SHA-256 hashes.
- **Logs:** they never contain tokens, Wiki.js sessions or page content. Each tool
  call writes one audit line to the `wikijs_mcp.audit` logger (user, tool, path or
  search term, outcome).
- **Sign-in:**
  - The login state is single-use and bound to the browser.
  - Only a Wiki.js session issued during that very sign-in is accepted, so an old wiki
    cookie cannot bypass the identity provider.
  - Redirects after sign-in stay under `/mcp/`.
- **Web pages:** the sign-in, consent and apps pages use CSRF tokens, origin checks, a strict
  Content Security Policy and `Cache-Control: no-store`.
- **OAuth:**
  - Registration is open (as MCP clients expect).
  - Redirect URIs must be `https`, or `http` on a loopback address.
  - Every authorization needs the user's explicit consent.
- **Leaks in Wiki.js:**
  - Wiki.js does not filter search totals and suggestions by permission. The server
    never requests them.
  - Wiki.js answers differently for page IDs that do not exist. The server checks IDs
    against the pages the user may see before asking Wiki.js.

## Known limitations

- Wiki.js 2.5 only.
- Updating a page through MCP clears its publish window (start and end date) unless
  the user has `manage:pages` on that page. Pages with custom CSS/JS can only be
  updated by such users, because Wiki.js would otherwise erase that CSS/JS.
- The `db` search engine only searches titles and descriptions. The `postgres` engine
  also searches content.

## Development

```bash
poetry install
poetry run pytest
```

A local Wiki.js 2.5 with test users, and nginx in front, as in production:

```bash
docker compose -f deploy/dev/docker-compose.yml up -d
.venv/bin/python scripts/spike_setup.py   # test groups, users, pages -> scripts/.env.spike
```

Run the server with `WIKIJS_URL=http://127.0.0.1:3080`,
`WIKIJS_PUBLIC_URL=http://127.0.0.1:3090`, `WIKIJS_STRATEGY_KEY=local`,
`WIKIJS_MCP_PORT=8765` (plus a database path and key). Then connect a client to
`http://127.0.0.1:3090/mcp/` (the repository's `.mcp.json` does this for Claude
Code), and sign in with a test account using the local login.

`wikijs-mcp stdio --dev-jwt-file <file>` runs over stdio as one user, without OAuth.

[FASE0-RESULTATEN.md](FASE0-RESULTATEN.md) records how Wiki.js 2.5 behaves; the
server's design rests on it.

## License

MIT
