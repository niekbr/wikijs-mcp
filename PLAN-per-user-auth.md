# Plan: wikijs-mcp ombouwen naar login per gebruiker

> Dit plan is bedoeld voor Claude Code in een fork van
> [jaalbin24/wikijs-mcp](https://github.com/jaalbin24/wikijs-mcp).
> Werk fase voor fase en bevestig met de gebruiker na fase 0 voordat je verder bouwt.

## Doel

Nu gebruikt de server één Wiki.js-API-key met volledige rechten (`WIKIJS_API_KEY`).
Het doel is een **centraal gehoste MCP-server** waarbij elke gebruiker inlogt via de
bestaande SSO-login van Wiki.js (eigen OIDC-server). Daarna doet de server elke
GraphQL-aanroep met de **eigen Wiki.js-JWT van die gebruiker**. Wiki.js blijft zo de
enige plek waar rechten worden bepaald.

## Uitgangspunten

- De MCP-server heeft **geen API-key en geen eigen permissielogica**. Rechten komen
  alleen uit Wiki.js (groepen, paginaregels).
- De server praat **niet zelf met de OIDC-server**. De login loopt via Wiki.js
  (`/login/<strategy-key>`). Wiki.js zet daarna de `jwt`-cookie en de server neemt die over.
- De server draait **op hetzelfde host als Wiki.js**, onder `/mcp` via de reverse proxy.
  Anders kan hij de `jwt`-cookie niet lezen.
- Alles wordt zelf gehost. Eén instance is genoeg, dus opslag in SQLite.
- Doelversie is Wiki.js 2.5.x. 3.x valt buiten scope.
- De opgeslagen JWT hoort bij een **Wiki.js-gebruiker** (`id` uit de JWT-payload), niet
  bij één login. Persoonlijke tokens wijzen naar die gebruiker. Opnieuw inloggen
  vervangt alleen de JWT, en bestaande tokens blijven werken.

## Achtergrond: gedrag van Wiki.js 2.5 (bevestigd in fase 0)

Getest tegen Wiki.js 2.5.316 en nagelezen in de bron. Details, foutcodes en scripts
staan in [FASE0-RESULTATEN.md](FASE0-RESULTATEN.md).

**Tokens:**
- **Een ongeldige of verlopen JWT geeft geen 401.** Valt de JWT buiten de
  vernieuwingstermijn, dan wordt het verzoek stil uitgevoerd als **Guest**. Alleen
  `users.profile` geeft dan een fout (1019). Verlopen tokens herkennen moet dus aan
  onze kant gebeuren.
- **Vernieuwen:** valt de JWT binnen `tokenRenewal` (standaard 14 dagen;
  `tokenExpiration` is standaard 30 minuten), dan geeft Wiki.js een nieuwe token terug:
  - in de header `new-jwt`, alleen als `Content-Type` **precies**
    `application/json` is
  - anders, ook bij elke GET, als `Set-Cookie: jwt=...`

  Parallelle vernieuwingen gaan goed, en oude tokens blijven binnen de termijn
  vernieuwbaar. Na een herstart van Wiki.js wordt elke oudere JWT vernieuwd.
- **Waar Wiki.js de JWT zoekt:** eerst `Authorization: Bearer`, daarna de `jwt`-cookie.
  Dat geldt ook voor HTML-routes.
- **Intrekken:** deactiveren of een groep wijzigen trekt tokens meteen in, voor tokens
  die meer dan 5 seconden oud zijn.
  - Een gedeactiveerde gebruiker krijgt van GraphQL `"Unauthorized"`. De HTML-route
    `/s/` geeft dan **geen antwoord (hangt)**, en `/<locale>/<pad>` geeft een 500.
  - Wordt de gebruiker weer geactiveerd, dan werkt de oude JWT weer.
  - Uitloggen in Wiki.js trekt geen JWT in, en Wiki.js controleert de IdP niet bij het
    vernieuwen.

**Pagina's lezen en schrijven:**
- **`pages.single` én `pages.singleByPath` vragen `manage:pages` of `delete:pages`.**
  Pagina-inhoud lezen gaat daarom via **`/s/<locale>/<pad>`** (recht `read:source`).
  Die route geeft:
  - de Markdown in `<code v-pre>`
  - `:page-id`
  - `effective-permissions`: base64-JSON met de effectieve rechten voor die pagina
  - een oude versie met `?v=<versionId>` (vraagt `read:history`)
- **Beslissing:** `read:source` is verplicht om pagina's te lezen; er komt geen
  fallback naar de gerenderde pagina.
- `pages.update` overschrijft `title`, `description` en `tags`. Ontbreekt
  `isPublished`, dan wordt de pagina **gedepubliceerd**. Bij gebruikers met
  `write:styles` of `write:scripts` worden de CSS en JS van de pagina gewist als die
  ontbreken.
- `move` vraagt `manage:pages` en `delete` vraagt `delete:pages`.

**Zoeken en andere queries:**
- `pages.search` filtert de resultaten, maar **`totalHits` en (bij de `postgres`-engine,
  die op productie draait) `suggestions` lekken informatie over verboden pagina's.**
- `site.config` vraagt `manage:system`. `localization.config` en `users.profile`
  werken voor iedereen.
- Fouten komen altijd met HTTP 200, in `errors[]`. Een Wiki.js-code staat in
  `extensions.exception.code`, en het `@auth`-directive geeft `"Forbidden"`.

## Huidige structuur (relevant)

| Bestand | Wat er nu gebeurt | Wat er moet veranderen |
|---|---|---|
| `wikijs_mcp/config.py` | `WikiJSConfig` met `api_key` en `headers` (`Bearer <api_key>`, `Content-Type: application/json`); `validate_config` eist een API-key | `api_key` weg. Headers worden per JWT gemaakt. Nieuwe site-instellingen (zie fase 1) |
| `wikijs_mcp/client.py` | `WikiJSClient(config)`; fouten zijn generieke `Exception`s; `"en"` hardcoded in `search_pages`, `get_page_by_path`, `get_page_tree`, `create_page`, `move_page`; `update_page` haalt de huidige pagina op met `get_page_by_id` (`pages.single`) | Een JWT per gebruiker en vernieuwing van die JWT, eigen exceptions, verlopen tokens zelf herkennen, standaard-locale van de site, pagina's niet meer ophalen via `pages.single` |
| `wikijs_mcp/server.py` | `FastMCP`, 12 tools. Elke tool doet `async with WikiJSClient(self.config)`, en `wiki_update_page` opent er twee na elkaar. `wiki_create_page` leest `localization.config`. Alleen `run_stdio()` | De helper `_client()` voor de huidige gebruiker, één client per tool-call, Streamable HTTP met SDK-auth, stdio alleen als dev-modus |
| `tests/` | `conftest.py` maakt `WikiJSConfig(api_key=...)`; `test_graphql_compatibility.py` controleert de queries in de payload | Fixtures met een JWT. Nieuwe tests voor gebruikersopslag, tokens, vernieuwing en het herkennen van een verlopen token |
| `pyproject.toml` | `mcp = "^1.0.0"` (de lock heeft 1.27.0) | `mcp >= 1.27` (nodig voor `TokenVerifier`, `AuthSettings` en transport security), plus `aiosqlite` en `cryptography` |

Bestaande tools: `wiki_search`, `wiki_get_page`, `wiki_list_pages`, `wiki_get_tree`,
`wiki_create_page`, `wiki_update_page`, `wiki_delete_page`, `wiki_move_page`,
`wiki_list_tags`, `wiki_get_site_info`, `wiki_get_history`, `wiki_get_version`.

## Volgorde van de fases

0 → 1 → 2 → 3 (HTTP-server en tools, met een dev-token) → 4 (SSO-login en persoonlijk
token) → 5 (OAuth, optioneel) → 6 (uitrol) → 7 (verificatie).

Na fase 3 werkt Claude Code al end-to-end met een token dat via de CLI is gemaakt. Elke
latere fase is zo meteen te testen.

---

## Fase 0: aannames controleren ✅ afgerond (2026-10-15)

Uitgevoerd tegen een lokale Wiki.js 2.5.316 in docker:
- `deploy/dev/docker-compose.yml`
- testdata via `scripts/spike_setup.py`
- testaccounts met de local strategy in `scripts/.env.spike`

Uitkomsten en beslissingen staan in [FASE0-RESULTATEN.md](FASE0-RESULTATEN.md) en zijn
hieronder verwerkt.

Nog niet getest, omdat er lokaal geen OIDC is: de echte SSO-redirect via
`loginRedirect`. Volgens de bron werkt die, en hij gaat vóór de redirect van een
groep. Dat test je in fase 4 tegen de echte SSO.

De dev-omgeving blijft bruikbaar voor de tests van de volgende fases en voor fase 7.

---

## Fase 1: client en configuratie per gebruiker ✅ afgerond (2026-10-15)

Gebouwd zoals hieronder beschreven, met deze afwijkingen en aanvullingen:
- `resolve_page_id` en `get_page_meta` gebruiken alleen `pages.list` (één aanroep
  per client, gecachet), en niet `/s/`. Dat scheelt een HTML-verzoek per id.
- `update_page` haalt CSS/JS en het publicatievenster eerst op via `singleByPath`.
  Dat lukt voor gebruikers met `manage:pages` op dat pad (zoals beheerders van een
  onderdeel), en dan blijft alles behouden. Lukt het niet, dan bepalen de
  effectieve rechten **voor die pagina** (`pages.style`/`pages.script` uit `/s/`) of
  de update geweigerd wordt, niet de globale rechten uit de JWT.
- Code 1019 ("authentication required") wordt `WikiAuthRevoked`. De client stuurt
  nooit een JWT die al voorbij de vernieuwingstermijn is, dus 1019 betekent dat
  Wiki.js een token weigert die nog geldig had moeten zijn.
- `search_pages(locale=None)` zoekt in alle locales.
- `get_page_by_path`, `get_page_by_id` en `get_site_info` zijn verwijderd. De server
  roept ze nog aan tot fase 3; tot die tijd is de stdio-server niet bruikbaar (de
  servertests mocken de client en slagen wel).
- `poetry.lock` is niet bijgewerkt voor de nieuwe dependency `cryptography`: poetry is
  hier niet geïnstalleerd. Draai `poetry lock` voordat je commit.


**`config.py`**
- `WikiJSConfig` krijgt alleen nog site-instellingen:
  - `url` (interne Wiki.js-URL)
  - `public_url` (bijvoorbeeld `https://wiki.example.com`)
  - `mcp_base_path` (standaard `/mcp`)
  - `strategy_key`
  - `db_path`
  - `encryption_key` (Fernet, uit een omgevingsvariabele)
  - `default_locale` (optioneel; anders uit `localization.config`, dat werkt voor
    iedereen)
  - `html_timeout` (standaard 10 s, voor de route `/s/`)
  - `token_renewal` (gelijk aan de waarde in Wiki.js, standaard `14d`)
  - `session_max_age` (standaard `30d`), `pat_default_ttl` (standaard `90d`) en
    `pat_max_ttl`
  - `read_only` (standaard `true`) en `debug`
- Haal `api_key` en de property `headers` weg. `validate_config` controleert de nieuwe
  velden.

**`client.py`**
- `WikiJSClient(config, jwt: str, on_new_jwt: Callable[[str], Awaitable[None]] | None)`.

**GraphQL-aanroepen**
- `_execute_query` stuurt `Authorization: Bearer <jwt>` en **precies**
  `Content-Type: application/json`, zonder charset. Een test moet dit vastleggen.

**Verlopen of ingetrokken tokens herkennen.** Wiki.js valt stil terug op Guest, dus de
client moet dit zelf doen:
- Lees vóór elk verzoek `exp` uit de payload. Een handtekeningcontrole is niet nodig,
  want Wiki.js controleert. Is `exp + token_renewal < now`, gooi dan meteen
  `WikiAuthExpired` en doe geen verzoek.
- Was de token verlopen (`exp < now`) en komt er geen nieuwe token terug, gooi dan
  `WikiAuthExpired` en **gooi het resultaat weg**. Dat kwam namelijk van Guest.
- GraphQL-fout `"Unauthorized"` (zonder code) of code 1019 bij een JWT die nog niet
  verlopen is: de gebruiker is ingetrokken of gedeactiveerd. Gooi dan
  `WikiAuthRevoked`.

**Vernieuwen**
- Lees `new-jwt`, en bij HTML-verzoeken `Set-Cookie: jwt=`. Roep dan `on_new_jwt` aan
  en gebruik de nieuwe JWT voor volgende aanroepen op dezelfde client.

**Exceptions** (nieuw in `wikijs_mcp/errors.py`):
- `WikiAuthExpired`: de sessie is verlopen; de gebruiker moet opnieuw inloggen
- `WikiAuthRevoked`: de gebruiker is ingetrokken of gedeactiveerd in Wiki.js
- `WikiForbidden`: 6013, 6012, 6007, `"Forbidden"` van `@auth`, en een 403 van `/s/`
- `WikiNotFound`: 6003, en een 302 van `/s/`
- `WikiError`: al het andere. Vervang hiermee de generieke `Exception`s, ook in
  `create_page`, `update_page`, `delete_page` en `move_page`.

**Locale**
- Haal de hardcoded `"en"` weg in `search_pages`, `get_page_by_path`, `get_page_tree`,
  `create_page` en `move_page`.
- Gebruik de opgegeven locale, anders `default_locale` uit de config, anders
  `localization.config`. Cache die waarde per proces.

**Zoeken**
- Vraag alleen `results { title description path locale }` op.
- **Geen `id`, `totalHits` of `suggestions`**: die lekken informatie over verboden
  pagina's (fase 0, punt 3).

**Pagina-inhoud via de bronroute**
- Maak `get_page_source(path, locale, version_id=None)`. Die doet `GET /s/<locale>/<pad>`
  (met `?v=` voor een oude versie) met de bearer-header, `html_timeout` en zonder
  redirects te volgen. De functie haalt uit de HTML:
  - de Markdown: `html.unescape` van `<code v-pre>…</code>`
  - `page_id` uit `:page-id`
  - de effectieve rechten: base64-JSON uit `effective-permissions`
  - de titel en beschrijving uit `<title>`/meta, als die nodig zijn
- Statuscodes:

  | Antwoord | Betekenis |
  |---|---|
  | 200 | ok |
  | 403 | `WikiForbidden`, met de tekst "je hebt `read:source` nodig voor `<pad>`" |
  | 302 | `WikiNotFound` |
  | timeout of 500 | controleer met `get_profile()`: een fout betekent `WikiAuthRevoked`, anders `WikiError` |

- `get_page_by_path` en `get_page_by_id` (via `pages.single`/`singleByPath`)
  **vervallen**. Metadata (titel, beschrijving, tags, datums, `isPublished`) komt uit
  `pages.list`, en het page-id uit `/s/`.

**Een pad omzetten naar een id**
- `resolve_page_id(path, locale)` gebruikt het `page_id` uit `/s/`. Is dat er niet,
  dan zoekt hij in `pages.list` (bevat id en pad).
- History, version en de schrijftools gebruiken deze functie. Zo bestaat een id
  altijd, en lekt de TypeError die Wiki.js geeft bij een onbekend id in `history`
  niet.
- `get_page_meta(id | path)` haalt de metadata uit `pages.list`. Dat geeft alle
  pagina's terug waar de gebruiker bij mag; cache het resultaat per client.

**Update veilig maken**
- `update_page` stuurt altijd `title`, `description`, `tags` en `isPublished` mee,
  met de huidige waarden uit `get_page_meta`.
- Heeft de JWT `write:styles` of `write:scripts` (globale `permissions`), probeer dan
  eerst de huidige `scriptCss` en `scriptJs` op te halen via `singleByPath`. Dat lukt
  alleen met `manage:pages`. Lukt het niet, **weiger de update** met een duidelijke
  melding, want Wiki.js zou de CSS en JS van de pagina wissen.
- Publicatiedata (`publishStartDate`/`publishEndDate`) gaan verloren. Die zijn niet te
  lezen zonder `manage:pages`. Zet dit in de README als bekende beperking.

**Profiel**
- Nieuw: `get_profile()` via `users { profile { id name email groups } }`. Die
  gebruik je in fase 4 bij de callback, voor `wiki_whoami` en om in te trekken tokens
  te herkennen.

**Tests:** pas `tests/conftest.py`, `test_client.py`, `test_config.py` en
`test_graphql_compatibility.py` aan op de nieuwe constructor. Nieuwe tests:
- `new-jwt` en `Set-Cookie` afhandelen
- een JWT die verder dan de vernieuwingstermijn verlopen is, geeft vóór het verzoek
  `WikiAuthExpired`
- een verlopen JWT zonder nieuwe token geeft `WikiAuthExpired`, en het resultaat
  wordt weggegooid
- `"Unauthorized"` en 1019 geven `WikiAuthRevoked`; 6013, 6012, 6007 en `"Forbidden"`
  geven `WikiForbidden`; 6003 geeft `WikiNotFound`
- `/s/` parsen (Markdown met HTML-entities, page-id, effectieve rechten), en de
  statuscodes 403, 302, timeout en 500
- de search-query vraagt geen `id`, `totalHits` of `suggestions` op
- `update_page` stuurt altijd `isPublished` en de huidige metadata mee, en weigert bij
  `write:styles`/`write:scripts` zonder toegang tot de CSS/JS
- de exacte `Content-Type`
- geen `"en"` meer in de payload als er geen locale is opgegeven

**Klaar als:** de bestaande clienttests draaien met een JWT in plaats van een API-key,
en de nieuwe tests slagen.

---

## Fase 2: opslag van gebruikers en tokens ✅ afgerond (2026-10-15)

Gebouwd in `wikijs_mcp/store.py` (`Store`), met deze afwijkingen en aanvullingen:
- `mcp_tokens` heeft een eigen `id` (PK). `token_hash` is UNIQUE. Daarmee kunnen de
  beheerpagina's een token intrekken zonder de hash te tonen.
  `revoke_token(user_id, token_id)` werkt alleen op tokens van de gebruiker zelf.
- De OAuth-tabellen komen pas in fase 5. Het schema heeft een versie
  (`PRAGMA user_version`), en een nieuwere database wordt geweigerd.
- `purge_expired()`:
  - wist bij een login ouder dan `session_max_age` **alleen de JWT**; tokens werken
    weer na opnieuw inloggen
  - verwijdert een gebruiker pas als die ook geen bruikbare tokens meer heeft
  - bewaart ingetrokken en verlopen tokens nog 30 dagen voor de audit
- Kan de JWT niet ontsleuteld worden (andere Fernet-sleutel) of is hij gewist, dan
  is `TokenUser.jwt` `None`. De server behandelt dat als "log opnieuw in".
- `update_jwt` verlengt `login_at` niet. Alleen een echte SSO-login reset de absolute
  termijn.
- Ook web-sessies (`create/get/delete_web_session`, met CSRF-secret) en login-states
  (`create_login_state`, `consume_login_state`) zijn klaar. Een login-state is één
  keer bruikbaar, gebonden aan de browser, en 10 minuten geldig.


Nieuw: `wikijs_mcp/store.py`

- SQLite via `aiosqlite`. Tabellen:
  - `users(wiki_user_id PK, email, name, jwt_encrypted, jwt_exp, login_at, last_used_at)`.
    `login_at` is het moment van de laatste echte SSO-login en dient voor
    `session_max_age`.
  - `mcp_tokens(token_hash PK, wiki_user_id, name, kind ['pat','oauth'], client_id,
    scopes, created_at, expires_at, last_used_at, revoked_at)`.
    **`expires_at` is verplicht.**
  - `web_sessions(id_hash PK, wiki_user_id, csrf_secret, expires_at)` voor de
    beheerpagina's
  - `login_states(state PK, browser_binding_hash, next, created_at)`, kortlevend
  - OAuth-tabellen voor fase 5: `oauth_clients`, `auth_codes`, `refresh_tokens`
- Versleutel de JWT met Fernet (`cryptography`). Sla MCP-tokens, web-sessie-id's en
  refresh tokens alleen op als hash (SHA-256; ze zijn willekeurig en hebben genoeg
  entropie) en nooit in leesbare vorm.
- API:
  - `upsert_login(jwt, profile)`: zet de JWT en `login_at` voor `wiki_user_id`
  - `update_jwt(wiki_user_id, jwt)`: overschrijft **alleen als de nieuwe `exp` later
    is** dan de opgeslagen `exp`. Zo kunnen parallelle vernieuwingen elkaar niet
    terugdraaien.
  - `get_user_for_token(token)`: geeft `None` bij een ingetrokken of verlopen token, of
    als `login_at + session_max_age < now`
  - `create_token(...)`, `list_tokens(...)`, `revoke_token(...)`, `touch(...)` en
    `purge_expired()` (die laatste regelmatig aanroepen)
- Haal e-mail en naam uit de JWT-payload of uit het profiel, alleen voor weergave en
  de auditlog. Verifieer de handtekening niet zelf, want dat doet Wiki.js.
- Twee levensduren, die je ook in de README uitlegt:
  - **JWT:** de JWT sterft als hij langer dan `token_renewal` niet gebruikt wordt. Er
    komt geen achtergrondtaak die JWT's vers houdt; dat zou elk token een permanente
    API-key maken. Daarna moet de gebruiker opnieuw inloggen via `/mcp/login`. De
    tokens blijven bestaan.
  - **Absoluut:** na `session_max_age` sinds de laatste SSO-login is opnieuw inloggen
    verplicht, ook bij dagelijks gebruik. Zo blijven de controles van de IdP
    (deprovisioning, MFA) gelden.

**Klaar als:** er unittests zijn voor opslaan, ophalen, versleuteling, intrekken,
verlopen tokens, `session_max_age`, de regel "alleen later" in `update_jwt`, en voor
tokens die blijven werken na opnieuw inloggen.

---

## Fase 3: HTTP-server, auth via de SDK en tools aanpassen ✅ afgerond (2026-10-15)

Gebouwd en end-to-end getest tegen de dev-wiki, via HTTP met dev-tokens en de
MCP-client van de SDK. Afwijkingen en aanvullingen:
- **`wikijs_mcp/auth.py`:**
  - `StoreTokenVerifier`: de `TokenVerifier` van de SDK, met de store erachter
  - per tool-call een `SessionUser` uit een "user source": `token_user_source` voor
    HTTP, `static_user_source` voor stdio. De server hangt zo niet af van de
    transport, en de tests gebruiken een nep-gebruiker.
- **Auth en transport:**
  - `AuthSettings(resource_server_url=None)`: zonder OAuth-metadataroute en zonder
    `resource_metadata` in `WWW-Authenticate`. Dat komt in fase 5.
  - Het endpoint is `<mcp_base_path>/`; `/mcp` geeft een 307 naar `/mcp/`.
  - De Host-controle staat aan, met alleen de host uit `public_url` (anders 421).
- **Configuratie:** nieuw zijn `WIKIJS_MCP_HOST` (standaard `127.0.0.1`),
  `WIKIJS_MCP_PORT` (`8000`) en `WIKIJS_MCP_FORWARDED_ALLOW_IPS` (`127.0.0.1`).
  `validate_config(only=...)` controleert per modus alleen wat nodig is.
- **CLI:**
  - `wikijs-mcp [serve]`
  - `wikijs-mcp dev-token --jwt-file F [--name] [--ttl 7d]`: controleert de JWT eerst
    met `users.profile`
  - `wikijs-mcp stdio --dev-jwt-file F`
- **Purge:** `serve` draait elk uur `purge_expired()`.
- **Meldingen** van de tools zijn in het Engels, net als de rest van de tools:
  - "The wiki session has expired. Log in again at …/mcp/login"
  - "The wiki no longer accepts this session …"
  - "No access to X, or it does not exist." plus een hint per tool (`read:source`,
    `read:history`, `manage:pages`, `delete:pages`)
- **History en version** controleren een opgegeven id eerst tegen `pages.list`. Een
  onbekend id bereikt Wiki.js dus nooit (dat lek via de TypeError is dicht).
- **De auditlog** (`wikijs_mcp.audit`) schrijft per call één JSON-regel met tool,
  target, user_id, e-mail en uitkomst. `httpx` logt alleen nog op WARNING, omdat de
  URL's paden bevatten.
- **Versie:** `mcp >= 1.30` (de geteste versie). `poetry lock` moet nog draaien.
- **Bekend:** de stdio-modus en `.mcp.json` in de repo worden in fase 6 bijgewerkt.


**`server.py`**
- Draai als Streamable HTTP via `uvicorn`: `FastMCP.streamable_http_app()`, samen met de
  routes uit fase 4 (`custom_route` of een Starlette-mount). Nginx geeft het volledige
  pad door, dus de app ziet `/mcp/...`. Zet `streamable_http_path` zo dat het endpoint
  `/mcp/` is, en controleer of `/mcp` zonder slash geen verkeerde redirect oplevert.
- Gebruik de auth van de SDK in plaats van eigen middleware:
  - een `TokenVerifier` met `verify_token(token)`. Die zoekt de hash op in de store en
    geeft een `AccessToken` of `None`.
  - `AuthSettings(issuer_url=<public_url>/mcp, resource_server_url=<public_url>/mcp/)`
  - De SDK geeft dan zelf `401` met `WWW-Authenticate`. Controleer de precieze API in
    `mcp` 1.27.
- Zet `TransportSecuritySettings` met de publieke host in `allowed_hosts`. Start
  uvicorn met `--proxy-headers` en `--forwarded-allow-ips` op het adres van de proxy.
- Helper `async def _client(self) -> WikiJSClient`:
  - haalt via `get_access_token()` het token van de huidige request op en daarmee de
    gebruiker
  - geeft een client met de JWT van die gebruiker en
    `on_new_jwt=lambda j: store.update_jwt(user_id, j)`
  - Vervang in alle tools `WikiJSClient(self.config)` door deze helper.
  - Gebruik **één client per tool-call**. `wiki_update_page` opent er nu twee na
    elkaar; voeg die samen, zodat een vernieuwde JWT meteen gebruikt wordt.
- Foutafhandeling:
  - `WikiAuthExpired` wordt een tool-fout: "sessie verlopen, log opnieuw in via
    `<public_url>/mcp/login`". Trek het token niet in.
  - `WikiAuthRevoked` wordt "je account is ingetrokken of gedeactiveerd in de wiki".
  - `WikiForbidden` wordt "geen toegang tot `<pad>`". Een "niet gevonden" en een
    "geen toegang" mogen er voor de gebruiker hetzelfde uitzien.
- **Dev-modus:**
  - de CLI-opdracht `wikijs-mcp dev-token --jwt-file <bestand>` slaat een JWT op als
    login en print een persoonlijk token. Daarmee is deze fase end-to-end te testen
    zonder fase 4.
  - `run_stdio` blijft alleen achter de vlag `--dev-jwt` voor lokaal testen.

**Tools**
- `wiki_search`:
  - toont alleen titel, `path`, `locale` en beschrijving
  - geen `id`, `totalHits` of `suggestions`
  - met een parameter `locale`
- `wiki_get_page(path, locale=None, id=None, metadata_only=False, version_id=None)`:
  - de inhoud komt via `get_page_source`, de metadata via `get_page_meta`
  - een `id` wordt eerst via `pages.list` omgezet naar een pad
  - zonder `read:source` krijgt de gebruiker een duidelijke melding; er is **geen
    fallback** naar de gerenderde pagina
  - `include_render` vervalt
- `wiki_get_history` en `wiki_get_version`:
  - accepteren een pad met locale, of een id; een pad wordt omgezet met
    `resolve_page_id`
  - `wiki_get_version` mag ook `/s/<pad>?v=<versionId>` gebruiken
- `wiki_list_pages` en `wiki_get_tree` blijven; Wiki.js filtert ze al. Gebruik de
  standaard-locale in plaats van `"en"`.
- Nieuwe tool `wiki_whoami(path=None)`:
  - geeft naam, e-mail en groepen (`users.profile`) en de **globale** rechten uit de
    JWT
  - met een `path` erbij: ook de **effectieve rechten voor die pagina** uit `/s/`
    (lezen, schrijven, bron, history)
- **Schrijftools** (`create`, `update`, `delete`, `move`):
  - worden alleen geregistreerd als `read_only=false`
  - accepteren ook een pad; Wiki.js handhaaft de rechten
  - `wiki_update_page` (ook met `edits`) haalt de huidige inhoud uit `/s/` en
    gebruikt de veilige update uit fase 1
  - `wiki_move_page` en `wiki_delete_page` geven een nette melding als
    `manage:pages`/`delete:pages` ontbreekt
- `wiki_get_site_info`: `site.config` vraagt `manage:system`. Toon daarom de
  `public_url` uit de config en `localization.config`.
- `wiki_list_tags`: blijft; Wiki.js filtert al.
- Pas de `instructions` van `FastMCP` aan. Weg moet: "numeric ID (from list/search
  results)" en "by numeric ID for mutations". Erbij moet:
  - werk met paden; de server zoekt id's zelf op
  - een pagina waar je geen recht op hebt, lijkt niet te bestaan
  - pagina's lezen vraagt het recht `read:source`
  - `wiki_whoami` laat zien wat je mag

**Auditlog:** per tool-call één gestructureerde logregel met `wiki_user_id`, e-mail,
tool, pad of zoekterm en ok/denied/expired/error. Log nooit tokens of pagina-inhoud.

**Klaar als:**
- alle tools werken via HTTP met een token uit `dev-token`
- Claude Code kan verbinden met `claude mcp add --transport http ... --header`
- de tests in `test_server.py` slagen met de aangepaste fixtures

---

## Fase 4: loginflow via Wiki.js en persoonlijk token

Nieuw: `wikijs_mcp/web.py`, met routes onder `mcp_base_path`.

1. **`GET /mcp/login?next=...`**
   - Maak een willekeurige `state` en een browser-binding. Sla `state`, de hash van de
     binding en `next` op. Zet de binding in een cookie `mcp_login`
     (`HttpOnly; Secure; SameSite=Lax; Path=/mcp`, max. 10 minuten).
   - `next` mag alleen een relatief pad onder `/mcp/` zijn. Alles anders wordt
     `/mcp/token`, anders heb je een open redirect.
   - Zet de redirect-cookie die in fase 0, punt 6 is gevonden (waarschijnlijk
     `loginRedirect` met `Path=/`), naar `/mcp/auth/callback?state=...`. Stuur dan
     door naar `/login/<strategy_key>`.
   - Optioneel: heeft de browser al een geldige `jwt`-cookie (controleer met
     `get_profile()` en `exp`), ga dan meteen naar stap 2 zonder omweg via de IdP.
2. **`GET /mcp/auth/callback`**
   - Controleer `state` tegen de database **en** tegen de cookie `mcp_login`. Een
     `state` mag maar één keer gebruikt worden.
   - Lees de `jwt`-cookie en controleer die met `get_profile()`. Een Guest-profiel of
     een verlopen `exp` betekent dat de login mislukt is.
   - Roep `upsert_login` aan, maak een web-sessie en ga door naar `next`.
3. **`GET /mcp/token`** (vereist een web-sessie; zonder sessie eerst naar `/mcp/login`)
   - Een simpele pagina waar de gebruiker een **persoonlijk token** maakt, met een naam
     en een vervaldatum (standaard `pat_default_ttl`, maximaal `pat_max_ttl`).
   - Het token verschijnt één keer, met een kant-en-klaar `claude mcp add`-commando.
   - Daaronder een lijst van bestaande tokens met de laatste gebruiksdatum en een knop
     om ze in te trekken.
   - Een melding als de JWT bijna verlopen is of als `session_max_age` bijna bereikt is.
4. Bescherm de beheerpagina's met de web-sessiecookie (`HttpOnly`, `Secure`,
   `SameSite=Lax`, `Path=/mcp`) en CSRF-tokens op alle formulieren. `POST /mcp/logout`
   beëindigt de web-sessie. Laat op de pagina weten dat uitloggen bij Wiki.js de
   MCP-tokens **niet** intrekt.

Het commando dat de gebruiker te zien krijgt:
```
claude mcp add --transport http wikijs https://wiki.example.com/mcp/ \
  --header "Authorization: Bearer <persoonlijk token>"
```

**Klaar als:**
- een testgebruiker kan inloggen via SSO, een token aanmaken en daarmee verbinden in
  Claude Code
- na opnieuw inloggen werkt een eerder gemaakt token nog
- een gebruiker uit een groep met een eigen login-redirect komt toch op
  `/mcp/auth/callback` uit

---

## Fase 5 (optioneel): OAuth voor custom connectors

Pas doen als de gebruiker dat wil, bijvoorbeeld voor claude.ai of Claude Desktop.

- Gebruik de auth-ondersteuning van de `mcp`-SDK: een implementatie van
  `OAuthAuthorizationServerProvider` en `AuthSettings` op `FastMCP`. Controleer de
  precieze API in de geïnstalleerde versie.
- **Paden:** met issuer `<public_url>/mcp` staan de metadata op
  `/.well-known/oauth-authorization-server/mcp` en
  `/.well-known/oauth-protected-resource/mcp`. Die vallen **buiten** `location /mcp/`.
  Zonder aparte proxyregels (fase 6) belanden ze bij Wiki.js. Controleer welke paden
  de SDK echt gebruikt voor de metadata en voor `/register`, `/authorize`, `/token`
  en `/revoke`, en zorg dat ze allemaal onder `/mcp/` vallen waar dat kan.
- Gebruik PKCE en dynamic client registration.
- `/authorize` start de flow uit fase 4 (stap 1 en 2) en toont daarna een
  **toestemmingsscherm** met de clientnaam en de redirect-URI. Pas na akkoord krijgt de
  client een authorization code. Dit scherm is verplicht, als bescherming tegen
  confused-deputy-aanvallen via dynamic client registration.
- Uitgegeven access tokens zijn rijen in `mcp_tokens` met `kind='oauth'` en een korte
  levensduur. Refresh tokens worden bij elk gebruik vervangen (rotatie) en werken
  nooit langer dan `session_max_age` na de laatste SSO-login.

---

## Fase 6: uitrol

- `Dockerfile` (python:3.12-slim, uitvoeren als non-root, volume voor `db_path`).
- `deploy/docker-compose.yml` met de MCP-service naast de bestaande wiki.
- Voorbeeld voor nginx (of Caddy/Traefik, afhankelijk van wat de gebruiker heeft):
  ```nginx
  limit_req_zone $binary_remote_addr zone=mcp_login:10m rate=10r/m;
  limit_req_zone $binary_remote_addr zone=mcp_api:10m rate=10r/s;

  location /mcp/ {
      limit_req zone=mcp_api burst=50 nodelay;
      proxy_pass http://wikijs-mcp:8000;          # zonder URI: pad blijft /mcp/...
      proxy_set_header Host $host;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto https;
      proxy_http_version 1.1;
      proxy_buffering off;                        # streamable HTTP
      proxy_read_timeout 1h;
  }
  location ~ ^/mcp/(login|auth/callback|token)$ {
      limit_req zone=mcp_login burst=5;
      proxy_pass http://wikijs-mcp:8000;
      proxy_set_header Host $host;
      proxy_set_header X-Forwarded-Proto https;
  }
  # Alleen bij fase 5:
  location ~ ^/\.well-known/oauth-(authorization-server|protected-resource)/mcp {
      proxy_pass http://wikijs-mcp:8000;
      proxy_set_header Host $host;
      proxy_set_header X-Forwarded-Proto https;
  }
  ```
- `.env.example` met alle variabelen. Leg uit hoe je een Fernet-sleutel maakt.
- Werk `.mcp.json` en de README bij: architectuur, installatie, gebruik in Claude Code,
  de twee levensduren uit fase 2, en beveiligingsnotities. Zeg daarbij eerlijk dat de
  Fernet-sleutel vooral beschermt tegen een gelekte back-up van de database, en niet
  tegen iemand die toegang heeft tot de host.

---

## Fase 7: verificatie (verplicht voor oplevering)

Automatiseer waar het kan, met de dev-wiki en de testaccounts uit fase 0
(`scripts/spike_setup.py`: lezer A, B en C, een schrijver, en Guest met alleen
`publiek/`). Zet voor punt 2 tijdelijk de `postgres`-engine aan in de dev-wiki, zodat
het lek via `suggestions` en `totalHits` ook getest wordt.

1. De testgebruikers en testpagina's uit `spike_setup.py`. `geheim/plan` is verboden
   voor B.
2. Doorloop voor A en B zoeken, lijsten, de boom, tags, ophalen op pad en ophalen op
   id, en history en version. B mag `geheim/plan` **nergens** zien: niet in
   zoekresultaten, niet in aantallen en niet in suggesties.
3. Lezer A (met `read:source`) kan pagina's lezen via `wiki_get_page`. Lezer C (zonder
   `read:source`) krijgt een duidelijke melding over `read:source`.
4. Zijn de schrijftools aan:
   - de schrijver zonder `manage:pages` kan een pagina bijwerken (ook met `edits`) en
     aanmaken
   - `isPublished`, titel, beschrijving en tags blijven gelijk als ze niet zijn
     opgegeven
   - verplaatsen en verwijderen geven een nette melding
5. Verloop van tokens, met een korte `tokenExpiration`:
   - de vernieuwing werkt
   - twee parallelle tool-calls met een verlopen JWT werken allebei, en de opgeslagen
     JWT gaat daarna niet terug naar een oudere
   - na de vernieuwingstermijn komt er een duidelijke "log opnieuw in"-melding en
     **geen** resultaat als Guest
6. Deactiveer gebruiker A in Wiki.js: de volgende tool-call geeft meteen de melding
   "ingetrokken" (fase 0 zag `"Unauthorized"`). Dat moet ook gelden voor
   `wiki_get_page`, waar `/s/` blijft hangen. Wordt A weer geactiveerd, dan werkt de
   sessie weer.
7. Trek een persoonlijk token in: de volgende aanroep geeft een 401. Een token waarvan
   `expires_at` verstreken is, geeft ook een 401.
8. Log opnieuw in via `/mcp/login`: bestaande tokens blijven werken. Zet
   `session_max_age` kort: daarna is opnieuw inloggen verplicht.
9. Test end-to-end in Claude Code met `claude mcp add --transport http ...` en gebruik
   als extra controle de MCP Inspector.
10. **Pas na akkoord van de gebruiker:** trek de oude API-key met volledige toegang in
    via Admin → API Access en haal hem uit alle lokale configs.

## Beveiligingseisen (doorlopend)

- Nooit tokens, JWT's of cookies in logs of foutmeldingen.
- JWT's versleuteld in de opslag; MCP-tokens, web-sessies en refresh tokens alleen
  gehasht.
- Elk persoonlijk token heeft een vervaldatum. Daarnaast geldt de absolute grens
  `session_max_age`.
- Leg `state` vast in de database en koppel hem aan de browser via een cookie. Gebruik
  PKCE bij OAuth en CSRF-bescherming op formulieren.
- `next` en redirect-URI's alleen naar toegestane bestemmingen (geen open redirect).
- Controleer de Host-header via `TransportSecuritySettings`.
- Rate limiting in de reverse proxy op `/mcp/login`, `/mcp/auth/callback`, `/mcp/token`
  en het MCP-endpoint.
- Een resultaat dat als Guest is opgehaald, komt nooit bij de gebruiker terecht (zie
  fase 1).
- `totalHits` en `suggestions` uit `pages.search` worden nooit opgevraagd of
  doorgegeven.
- Een update via MCP mag nooit stil gegevens wissen: `isPublished` en de huidige
  metadata worden altijd meegestuurd, en bij `write:styles`/`write:scripts` weiger je
  de update als de CSS/JS niet te lezen zijn.
- Geen "raw GraphQL"-tool toevoegen.

## Beantwoord

- Zoek-engine op productie: `postgres`.
- Pagina's lezen: alleen via `/s/`; `read:source` is verplicht, zonder fallback.
- Testomgeving: lokale docker (`deploy/dev`), testaccounts via de local strategy.
- Productie (2026-10-15):
  - de leesgroepen hebben `read:source`, zowel in de globale rechten als in de
    paginaregels
  - `write:styles` en `write:scripts` staan bij geen enkele groep aan, dus de weigering
    bij een update komt in de praktijk niet voor. Hij blijft als vangnet.
  - `manage:pages` wordt via paginaregels per onderdeel gegeven (bijvoorbeeld
    `START committees/acci`). Wiki.js controleert `move` per pad, dus die beheerders
    kunnen binnen hun eigen onderdeel verplaatsen. `delete` vraagt apart
    `delete:pages`.

## Open vragen voor de gebruiker

- Wiki.js-versie op productie (precies) en de strategy key van de OIDC-login?
- Welke waarden staan nu ingesteld voor `tokenExpiration` en `tokenRenewal`?
- Welke reverse proxy (nginx, Traefik, Caddy)?
- Alleen lezen, of moeten schrijftools ook beschikbaar zijn?
- Alleen persoonlijke tokens (fase 4), of ook OAuth voor custom connectors (fase 5)?
- Gewenste `session_max_age` en maximale geldigheid van tokens?
- Zelf onderhouden als fork, of later als PR terug naar upstream?
