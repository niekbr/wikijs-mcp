"""Zet de lokale Wiki.js uit deploy/dev op met testgroepen, -gebruikers en -pagina's.

Idempotent genoeg om opnieuw te draaien: bestaande groepen, gebruikers en pagina's
worden overgeslagen. Schrijft scripts/.env.spike met de wachtwoorden.

Testopzet:
- Guest           : alleen read:pages op publiek/
- lezers-a        : read:pages, read:source, read:history op alles
- lezers-b        : als lezers-a, maar geen toegang tot geheim/
- lezers-c        : alleen read:pages op alles (geen bron, geen history)
- schrijvers      : read + write:pages op alles, zonder manage:pages / delete:pages
"""

import secrets
import sys
import time

import httpx

import spike_common as c

ADMIN_EMAIL = "admin@test.local"
SITE_URL = c.WIKI_URL

READ_ALL = ["read:pages", "read:source", "read:history", "read:assets"]


def rule(roles, path="", deny=False, match="START"):
    return {
        "id": secrets.token_hex(4),
        "deny": deny,
        "match": match,
        "roles": roles,
        "path": path,
        "locales": [],
    }


GROUPS = {
    "lezers-a": (READ_ALL, [rule(READ_ALL)]),
    "lezers-b": (READ_ALL, [rule(READ_ALL), rule(READ_ALL, "geheim", deny=True)]),
    "lezers-c": (["read:pages"], [rule(["read:pages"])]),
    "schrijvers": (
        READ_ALL + ["write:pages"],
        [rule(READ_ALL + ["write:pages"])],
    ),
}

USERS = {
    "LEZER_A": ("lezer-a@test.local", "Lezer A", "lezers-a"),
    "LEZER_B": ("lezer-b@test.local", "Lezer B", "lezers-b"),
    "LEZER_C": ("lezer-c@test.local", "Lezer C", "lezers-c"),
    "SCHRIJVER": ("schrijver@test.local", "Schrijver", "schrijvers"),
}

PAGES = [
    ("home", "Home", "# Home\n\nStartpagina van de testwiki.", ["algemeen"]),
    ("publiek/info", "Publieke info", "Iedereen mag dit lezen. Woord: ballon.", ["publiek"]),
    ("docs/algemeen", "Algemene docs", "Gewone documentatie. Woord: ballon.", ["algemeen"]),
    (
        "geheim/plan",
        "Geheim plan",
        "Alleen voor lezers-a. Woorden: ballon zeppelin.",
        ["geheim-tag"],
    ),
]


def finalize_setup(admin_password: str) -> None:
    resp = httpx.get(f"{c.WIKI_URL}/", timeout=10)
    if "setup" not in resp.text.lower() or "/finalize" in resp.url.path:
        return
    print("Setup afronden…")
    r = httpx.post(
        f"{c.WIKI_URL}/finalize",
        json={
            "adminEmail": ADMIN_EMAIL,
            "adminPassword": admin_password,
            "adminPasswordConfirm": admin_password,
            "siteUrl": SITE_URL,
            "telemetry": False,
        },
        timeout=120,
    )
    r.raise_for_status()
    if not r.json().get("ok"):
        sys.exit(f"Setup mislukt: {r.text}")
    # Wiki.js herstart na de setup
    for _ in range(60):
        time.sleep(3)
        try:
            if c.gql("{ site { config { title } } }").status_code == 200:
                return
        except httpx.HTTPError:
            pass
    sys.exit("Wiki.js kwam niet terug na de setup")


def ensure_env() -> dict[str, str]:
    env = dict(c.ENV)
    if "SPIKE_ADMIN_PASSWORD" not in env:
        env["SPIKE_WIKI_URL"] = c.WIKI_URL
        env["SPIKE_ADMIN_EMAIL"] = ADMIN_EMAIL
        env["SPIKE_ADMIN_PASSWORD"] = secrets.token_urlsafe(16)
        for role, (email, _, _) in USERS.items():
            env[f"SPIKE_{role}_EMAIL"] = email
            env[f"SPIKE_{role}_PASSWORD"] = secrets.token_urlsafe(16)
        lines = ["# Lokale testaccounts voor fase 0 (niet committen)"]
        lines += [f"{k}={v}" for k, v in env.items() if k.startswith("SPIKE_")]
        c.ENV_FILE.write_text("\n".join(lines) + "\n")
        c.ENV_FILE.chmod(0o600)
        c.ENV.update(env)
    return env


def check(result: dict, what: str) -> dict:
    rr = result.get("responseResult", {})
    if not rr.get("succeeded"):
        sys.exit(f"{what} mislukt: {rr}")
    return result


def main() -> None:
    env = ensure_env()
    finalize_setup(env["SPIKE_ADMIN_PASSWORD"])
    admin = c.login(env["SPIKE_ADMIN_EMAIL"], env["SPIKE_ADMIN_PASSWORD"])

    groups = {
        g["name"]: g["id"]
        for g in c.gql_data("{ groups { list { id name } } }", jwt=admin)["groups"]["list"]
    }

    # Guest: alleen publiek/
    guest_id = groups["Guests"]
    check(
        c.gql_data(
            """mutation($id: Int!, $p: [String]!, $r: [PageRuleInput]!) {
              groups { update(id: $id, name: "Guests", redirectOnLogin: "/",
                permissions: $p, pageRules: $r) { responseResult { succeeded message } } } }""",
            {"id": guest_id, "p": ["read:pages"], "r": [rule(["read:pages"], "publiek")]},
            jwt=admin,
        )["groups"]["update"],
        "Guest bijwerken",
    )

    for name, (perms, rules) in GROUPS.items():
        if name not in groups:
            res = c.gql_data(
                """mutation($n: String!) { groups { create(name: $n) {
                  responseResult { succeeded message } group { id } } } }""",
                {"n": name},
                jwt=admin,
            )["groups"]["create"]
            groups[name] = check(res, f"Groep {name}")["group"]["id"]
        check(
            c.gql_data(
                """mutation($id: Int!, $n: String!, $p: [String]!, $r: [PageRuleInput]!) {
                  groups { update(id: $id, name: $n, redirectOnLogin: "/",
                    permissions: $p, pageRules: $r) { responseResult { succeeded message } } } }""",
                {"id": groups[name], "n": name, "p": perms, "r": rules},
                jwt=admin,
            )["groups"]["update"],
            f"Groep {name} bijwerken",
        )
        print(f"Groep {name}: id {groups[name]}")

    existing = {
        u["email"]
        for u in c.gql_data("{ users { list { email } } }", jwt=admin)["users"]["list"]
    }
    for role, (email, name, group) in USERS.items():
        if email in existing:
            continue
        res = c.gql_data(
            """mutation($e: String!, $n: String!, $p: String!, $g: [Int]!) {
              users { create(email: $e, name: $n, passwordRaw: $p, providerKey: "local",
                groups: $g, mustChangePassword: false, sendWelcomeEmail: false) {
                responseResult { succeeded message } } } }""",
            {"e": email, "n": name, "p": env[f"SPIKE_{role}_PASSWORD"], "g": [groups[group]]},
            jwt=admin,
        )["users"]["create"]
        check(res, f"Gebruiker {email}")
        print(f"Gebruiker {email} aangemaakt")

    existing_pages = {
        p["path"]
        for p in c.gql_data("{ pages { list(limit: 1000) { path } } }", jwt=admin)["pages"]["list"]
    }
    for path, title, content, tags in PAGES:
        if path in existing_pages:
            continue
        res = c.gql_data(
            """mutation($path: String!, $title: String!, $content: String!, $tags: [String]!) {
              pages { create(path: $path, title: $title, content: $content, tags: $tags,
                description: "", editor: "markdown", isPublished: true, isPrivate: false,
                locale: "en") { responseResult { succeeded message } page { id } } } }""",
            {"path": path, "title": title, "content": content, "tags": tags},
            jwt=admin,
        )["pages"]["create"]
        print(f"Pagina {path}: id {check(res, f'Pagina {path}')['page']['id']}")

    print("Klaar. Testaccounts staan in scripts/.env.spike")


if __name__ == "__main__":
    main()
