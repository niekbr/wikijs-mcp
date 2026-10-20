"""Fase 0, punt 1, 2, 3, 8 en 9: wat ziet elke rol via GraphQL en via HTML-routes?

Draai eerst spike_setup.py. Print geen tokens.
"""

import base64
import html
import json
import re

import httpx

import spike_common as c

ROLES = ["LEZER_A", "LEZER_B", "LEZER_C", "SCHRIJVER", "GUEST"]


def show_errors(errors: list) -> str:
    out = []
    for e in errors:
        ext = e.get("extensions", {})
        exc = ext.get("exception", {})
        out.append(
            f"message={e.get('message')!r} code={ext.get('code')} "
            f"exception.code={exc.get('code')} exception.name={exc.get('name')}"
        )
    return "; ".join(out)


def q(jwt, query, variables=None):
    resp = c.gql(query, variables, jwt)
    body = resp.json()
    if body.get("errors"):
        return f"FOUT (HTTP {resp.status_code}): {show_errors(body['errors'])}"
    return body["data"]


def source_route(jwt, path):
    headers = {"Authorization": f"Bearer {jwt}"} if jwt else {}
    r = httpx.get(f"{c.WIKI_URL}/s/en/{path}", headers=headers, follow_redirects=False)
    info = {"status": r.status_code}
    if r.status_code in (301, 302):
        info["location"] = r.headers.get("location")
    m = re.search(r"<code v-pre>(.*?)</code>", r.text, re.S)
    if m:
        info["markdown"] = html.unescape(m.group(1))[:60]
    m = re.search(r':page-id="(\d+)"', r.text)
    if m:
        info["page_id"] = int(m.group(1))
    m = re.search(r'effective-permissions="([^"]+)"', r.text)
    if m:
        perms = json.loads(base64.b64decode(m.group(1)))
        info["effective"] = {k: [a for a, v in acts.items() if v] for k, acts in perms.items()}
    return info


def rendered_route(jwt, path):
    headers = {"Authorization": f"Bearer {jwt}"} if jwt else {}
    r = httpx.get(f"{c.WIKI_URL}/en/{path}", headers=headers, follow_redirects=False)
    info = {"status": r.status_code}
    if r.status_code in (301, 302):
        info["location"] = r.headers.get("location")
    info["bevat_inhoud"] = "ballon" in r.text or "Startpagina" in r.text
    info["unauthorized"] = "unauthorized" in r.text.lower()
    return info


def main():
    admin = c.login(c.ENV["SPIKE_ADMIN_EMAIL"], c.ENV["SPIKE_ADMIN_PASSWORD"])
    print("Zoek-engine:", q(admin, "{ search { searchEngines { key isEnabled } } }"))

    for role in ROLES:
        jwt = None if role == "GUEST" else c.login_as(role)
        print(f"\n========== {role} ==========")
        if jwt:
            p = c.jwt_payload(jwt)
            print("JWT-payload velden:", sorted(p))
            print("  id/email/groups/permissions:", p["id"], p["email"], p["groups"], p["permissions"])
            print("  geldig nog (s):", c.seconds_left(jwt))

        d = q(jwt, "{ pages { list(limit: 100) { id path } } }")
        print("list:", d if isinstance(d, str) else [x["path"] for x in d["pages"]["list"]])

        for term in ("Geheim", "docs", "Algemene"):  # db-engine: alleen titel/beschrijving
            d = q(jwt, 'query($q: String!) { pages { search(query: $q) { results { id path locale description } totalHits } } }', {"q": term})
            print(f"search {term}:", d if isinstance(d, str) else d["pages"]["search"])

        d = q(jwt, '{ pages { tree(mode: ALL, locale: "en") { id path isFolder pageId } } }')
        print("tree:", d if isinstance(d, str) else [(x["path"], x["pageId"]) for x in d["pages"]["tree"]])

        d = q(jwt, "{ pages { tags { tag } } }")
        print("tags:", d if isinstance(d, str) else [t["tag"] for t in d["pages"]["tags"]])

        d = q(jwt, "{ pages { single(id: 3) { path content } } }")
        print("single(3):", d if isinstance(d, str) else "OK")
        d = q(jwt, '{ pages { singleByPath(path: "docs/algemeen", locale: "en") { path content render } } }')
        print("singleByPath(docs/algemeen):", d if isinstance(d, str) else "OK")
        d = q(jwt, '{ pages { singleByPath(path: "bestaat/niet", locale: "en") { path } } }')
        print("singleByPath(bestaat/niet):", d if isinstance(d, str) else d)

        for pid in (3, 4, 999):
            d = q(jwt, "query($id: Int!) { pages { history(id: $id) { total trail { versionId } } } }", {"id": pid})
            print(f"history({pid}):", d if isinstance(d, str) else d["pages"]["history"])

        print("site.config:", q(jwt, "{ site { config { title host } } }"))
        print("localization.config:", q(jwt, "{ localization { config { locale namespacing namespaces } } }"))
        print("users.profile:", q(jwt, "{ users { profile { id name email groups } } }"))

        for path in ("docs/algemeen", "geheim/plan", "bestaat/niet"):
            print(f"/s/en/{path}:", source_route(jwt, path))
        for path in ("docs/algemeen", "geheim/plan"):
            print(f"/en/{path}:", rendered_route(jwt, path))

    # Punt 9: hoe ziet een geweigerde mutatie eruit?
    print("\n========== Mutaties ==========")
    a = c.login_as("LEZER_A")
    w = c.login_as("SCHRIJVER")
    upd = """mutation($id: Int!, $content: String) { pages { update(id: $id, content: $content) {
      responseResult { succeeded errorCode slug message } } } }"""
    print("LEZER_A update(3):", q(a, upd, {"id": 3, "content": "poging door lezer"}))
    print("SCHRIJVER update(3):", q(w, upd, {"id": 3, "content": "Gewone documentatie. Woord: ballon. (bijgewerkt)"}))
    print("SCHRIJVER delete(3):", q(w, "mutation { pages { delete(id: 3) { responseResult { succeeded errorCode slug message } } } }"))
    print("SCHRIJVER move(3):", q(w, 'mutation { pages { move(id: 3, destinationPath: "docs/verplaatst", destinationLocale: "en") { responseResult { succeeded errorCode slug message } } } }'))


if __name__ == "__main__":
    main()
