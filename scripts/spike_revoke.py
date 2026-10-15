"""Fase 0, punt 5 (herhaling): deactiveren met een JWT die ouder is dan 5 s.

Wiki.js trekt alleen tokens in met iat < (moment van deactiveren - 5 s).
"""

import time

import httpx

import spike_common as c
from spike_tokens import LIST, PROFILE, admin_jwt, call, show

admin = admin_jwt()
b = c.login("lezer-b@test.local", c.ENV["SPIKE_LEZER_B_PASSWORD"])
time.sleep(10)
res = c.gql_data("mutation { users { deactivate(id: 4) { responseResult { succeeded message } } } }", jwt=admin)
print("deactiveer B:", res["users"]["deactivate"]["responseResult"])
try:
    show("B list na deactiveren", call(b, LIST))
    show("B profile na deactiveren", call(b, PROFILE))
    try:
        r = httpx.get(f"{c.WIKI_URL}/s/en/docs/algemeen", headers={"Authorization": f"Bearer {b}"}, timeout=10)
    except httpx.ReadTimeout:
        r = None
    print("B GET /s/ na deactiveren:", r.status_code if r else "TIMEOUT (geen antwoord binnen 10 s)")
    try:
        r = httpx.get(f"{c.WIKI_URL}/en/publiek/info", headers={"Authorization": f"Bearer {b}"}, timeout=10)
    except httpx.ReadTimeout:
        r = None
    print("B GET /en/publiek/info na deactiveren:", r.status_code if r else "TIMEOUT (geen antwoord binnen 10 s)")
finally:
    res = c.gql_data("mutation { users { activate(id: 4) { responseResult { succeeded message } } } }", jwt=admin)
    print("activeer B weer:", res["users"]["activate"]["responseResult"])
show("B na heractiveren (zelfde JWT)", call(b, LIST))
