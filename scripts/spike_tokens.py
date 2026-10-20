"""Fase 0, punt 4 en 5: verloop, vernieuwing en intrekken van JWT's.

Zet tijdelijk authJwtExpiration=1m en authJwtRenewablePeriod=2m, en zet daarna
30m / 14d terug. Duurt ongeveer 5 minuten. Alleen tegen de lokale dev-wiki draaien.
"""

import asyncio
import time

import httpx

import spike_common as c

LIST = "{ pages { list(limit: 100) { path } } }"
PROFILE = "{ users { profile { id email } } }"


def admin_jwt() -> str:
    return c.login(c.ENV["SPIKE_ADMIN_EMAIL"], c.ENV["SPIKE_ADMIN_PASSWORD"])


def set_jwt_times(admin: str, expiration: str, renewal: str) -> None:
    res = c.gql_data(
        """mutation($e: String, $r: String) { site { updateConfig(
             authJwtExpiration: $e, authJwtRenewablePeriod: $r) {
             responseResult { succeeded message } } } }""",
        {"e": expiration, "r": renewal},
        jwt=admin,
    )
    print(f"Config {expiration}/{renewal}:", res["site"]["updateConfig"]["responseResult"])


def call(jwt: str, query: str, content_type: str = "application/json") -> dict:
    r = c.gql(query, jwt=jwt, content_type=content_type)
    body = r.json()
    new = r.headers.get("new-jwt")
    cookie = r.cookies.get("jwt")
    out = {
        "new-jwt": c.redact(new),
        "set-cookie jwt": c.redact(cookie),
        "fout": body["errors"][0]["message"] if body.get("errors") else None,
    }
    data = body.get("data") or {}
    if data.get("pages"):
        out["paths"] = [p["path"] for p in data["pages"]["list"]]
    if data.get("users"):
        out["profile"] = data["users"]["profile"]
    out["_new"] = new or cookie
    return out


def show(label: str, out: dict) -> None:
    print(f"{label}:", {k: v for k, v in out.items() if k != "_new"})


def wait_until(ts: float, why: str) -> None:
    left = ts - time.time()
    if left > 0:
        print(f"  … {int(left)} s wachten ({why})")
        time.sleep(left)


async def parallel(jwt: str) -> None:
    async with httpx.AsyncClient() as client:
        reqs = [
            client.post(
                f"{c.WIKI_URL}/graphql",
                json={"query": LIST},
                headers={"Authorization": f"Bearer {jwt}"},
            )
            for _ in range(2)
        ]
        for i, r in enumerate(await asyncio.gather(*reqs)):
            body = r.json()
            print(
                f"  parallel {i}: new-jwt={c.redact(r.headers.get('new-jwt'))}",
                "fout" if body.get("errors") else f"{len(body['data']['pages']['list'])} pagina's",
            )


def main() -> None:
    admin = admin_jwt()
    set_jwt_times(admin, "1m", "2m")
    try:
        a = c.login("lezer-a@test.local", c.ENV["SPIKE_LEZER_A_PASSWORD"])
        exp = c.jwt_payload(a)["exp"]
        print("JWT A geldig nog (s):", c.seconds_left(a))
        show("4 vers", call(a, LIST))

        wait_until(exp + 10, "JWT verlopen, binnen vernieuwingstermijn")
        r = call(a, LIST)
        show("4a POST application/json", r)
        if r["_new"]:
            p = c.jwt_payload(r["_new"])
            print("   nieuwe JWT: zelfde id?", p["id"] == c.jwt_payload(a)["id"], "geldig nog (s):", c.seconds_left(r["_new"]))
        show("4b POST application/json; charset=utf-8", call(a, LIST, "application/json; charset=utf-8"))
        g = httpx.get(f"{c.WIKI_URL}/s/en/docs/algemeen", headers={"Authorization": f"Bearer {a}"})
        print("4b GET /s/ zonder content-type:", g.status_code, "set-cookie jwt:", c.redact(g.cookies.get("jwt")), "new-jwt:", c.redact(g.headers.get("new-jwt")))
        print("4d twee parallelle verzoeken met dezelfde verlopen JWT:")
        asyncio.run(parallel(a))
        show("4d oude JWT daarna nog eens", call(a, LIST))

        wait_until(exp + 120 + 15, "JWT buiten vernieuwingstermijn")
        show("4c list buiten termijn", call(a, LIST))
        show("4c profile buiten termijn", call(a, PROFILE))

        # Punt 5: intrekken. Verse tokens voor B; admin opnieuw (oude is verlopen).
        admin = admin_jwt()
        b = c.login("lezer-b@test.local", c.ENV["SPIKE_LEZER_B_PASSWORD"])
        show("5 B vóór deactiveren", call(b, LIST))
        res = c.gql_data("mutation { users { deactivate(id: 4) { responseResult { succeeded message } } } }", jwt=admin)
        print("5 deactiveer B:", res["users"]["deactivate"]["responseResult"])
        show("5 B list na deactiveren", call(b, LIST))
        show("5 B profile na deactiveren", call(b, PROFILE))
        r = httpx.get(f"{c.WIKI_URL}/s/en/docs/algemeen", headers={"Authorization": f"Bearer {b}"})
        print("5 B GET /s/ na deactiveren:", r.status_code)
        res = c.gql_data("mutation { users { activate(id: 4) { responseResult { succeeded message } } } }", jwt=admin)
        print("5 activeer B weer:", res["users"]["activate"]["responseResult"])
        show("5 B na heractiveren (zelfde JWT)", call(b, LIST))
    finally:
        set_jwt_times(admin_jwt(), "30m", "14d")


if __name__ == "__main__":
    main()
