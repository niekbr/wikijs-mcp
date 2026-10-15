# Fase 0: resultaten

Getest op 2026-10-15 tegen een lokale **Wiki.js 2.5.316** (`deploy/dev/docker-compose.yml`,
Postgres, zoek-engine `db`), met de scripts in `scripts/spike_*.py`. Waar dat kon is
het gedrag ook nagelezen in de bron in de container.

Testopzet (`scripts/spike_setup.py`):

| Rol | Rechten | Pagina's |
|---|---|---|
| Guest | `read:pages` | alleen `publiek/` |
| lezer A | `read:pages`, `read:source`, `read:history` | alles |
| lezer B | als A | alles behalve `geheim/` (deny-regel) |
| lezer C | alleen `read:pages` | alles |
| schrijver | als A plus `write:pages` (geen `manage:pages` of `delete:pages`) | alles |

Testpagina's: `home` (1), `publiek/info` (2), `docs/algemeen` (3), `geheim/plan` (4).

## Uitkomsten per punt

### 1. JWT als bearer token: werkt
- `Authorization: Bearer <jwt>` werkt op `/graphql` en op HTML-routes. Wiki.js zoekt
  eerst in de header en daarna in de cookie (`extractJWT`).
- De resultaten verschillen per gebruiker: B ziet `geheim/plan` niet in `list`,
  `tree` en `tags`.
- De JWT-payload heeft de velden `id`, `email`, `name`, `groups` (id's),
  `permissions` (alleen globaal), `iat`, `exp`, `aud`, `iss`, `av`, `tz`, `lc`, `df`
  en `ap`.

### 2. Pagina-inhoud zonder `manage:pages`: niet via GraphQL
- **`pages.single` én `pages.singleByPath` vragen `manage:pages` of `delete:pages`.**
  Alle lezers en de schrijver krijgen fout 6013 ("not authorized to view this page").
  Een niet-bestaande pagina geeft 6003.
- **`GET /s/<locale>/<pad>`** (bronweergave, vraagt `read:source`):
  - 200 met de Markdown HTML-escaped in `<code v-pre>…</code>`
  - `:page-id="<id>"` geeft het page-id
  - `effective-permissions="<base64 JSON>"` geeft de effectieve rechten **voor die
    pagina**, zoals `pages: [read, write]`, `source: [read]` en `history: [read]`
  - Zonder recht: 403. Een niet-bestaande pagina geeft een 302 naar `/<pad>` (als je
    `read:source` hebt) of een 403 (als je dat niet hebt).
  - Met `?v=<versionId>` krijg je een oude versie; daarvoor is `read:history` nodig.
- **`GET /<locale>/<pad>`** (gerenderd): werkt met alleen `read:pages` (lezer C); geeft
  403 zonder rechten. Dit is de enige route voor gebruikers zonder `read:source`.

### 3. Zoeken: gefilterd, met één lek
- `pages.search` filtert de resultaten op `read:pages`.
- **`totalHits` wordt niet gefilterd.** B zoekt op "Geheim" en krijgt `results: []`,
  maar `totalHits: 1`. Geef `totalHits` dus nooit door.
- De `db`-engine zoekt **alleen in titel en beschrijving**, niet in de inhoud. Het `id`
  in de resultaten is een string, maar bij `db` wel het page-id.
- **De echte wiki gebruikt de `postgres`-engine.** Dat is niet lokaal getest; uit de bron
  (`server/modules/search/postgres/engine.js`):
  - zoekt in de inhoud (`pagesVector.tokens`) en in het pad (`ILIKE`)
  - `totalHits` is het aantal ongefilterde rijen, dus hetzelfde lek als hierboven
  - **`suggestions` komt uit `pagesWords`, de woorden van álle pagina's, en wordt niet
    gefilterd.** Vraag `suggestions` dus nooit op en geef het nooit door.

### 4. Verloop en vernieuwing: bevestigd
- **(a)** Een verlopen JWT binnen de vernieuwingstermijn, als POST met precies
  `Content-Type: application/json`, geeft de header `new-jwt` met een nieuwe token
  (zelfde `id`, nieuwe `exp`). Het verzoek zelf slaagt als die gebruiker.
- **(b)** Met `application/json; charset=utf-8` of bij een GET komt de nieuwe token
  **alleen** als `Set-Cookie: jwt=…`.
- **(c)** Buiten de vernieuwingstermijn wordt het verzoek **stil uitgevoerd als
  Guest**: `list` geeft alleen `publiek/info` en geen fout. `users.profile` geeft fout
  1019 ("You must be authenticated").
- **(d)** Twee parallelle verzoeken met dezelfde verlopen JWT slagen allebei, en
  allebei krijgen ze een nieuwe token. Binnen de termijn blijft de oude JWT
  vernieuwbaar; vernieuwen maakt oude tokens niet ongeldig.
- Na een **herstart van Wiki.js** wordt elke JWT van vóór de start bij het volgende
  verzoek vernieuwd (`iat <= WIKI.startedAt`). Dat staat in de bron; het is niet apart
  getest.
- Standaardwaarden: `tokenExpiration` 30m en `tokenRenewal` 14d. Via de API zijn ze in
  te stellen met `site.updateConfig(authJwtExpiration, authJwtRenewablePeriod)`.

### 5. Intrekken: werkt meteen, met kanttekeningen
- Bij deactiveren, of bij een wijziging van gebruiker of groep, komt `u<id>` of
  `g<id>` op een revocation list. Die staat in het geheugen en geldt zolang
  `tokenExpiration` duurt.
- Een JWT van **meer dan 5 seconden vóór** het intrekken wordt dan opnieuw gevalideerd:
  - **Gebruiker gedeactiveerd:** GraphQL geeft `"Unauthorized"` (zonder code) en
    `users.profile` geeft 1019.
  - **De HTML-route `/s/` geeft geen antwoord (timeout)** en `/en/<pad>` geeft een 500.
    Wiki.js loopt dan vast op een ontbrekende `req.user`.
  - Wordt de gebruiker weer geactiveerd, dan werkt **dezelfde oude JWT** weer en wordt
    hij vernieuwd.
  - **Groep of rechten gewijzigd:** bij het volgende verzoek wordt de JWT vernieuwd en
    gelden de nieuwe rechten meteen. Dat staat in de bron; het is niet apart getest.
- Een JWT van minder dan 5 seconden vóór het deactiveren blijft geldig tot hij
  verloopt (maximaal `tokenExpiration`). Dat is een randgeval.

### 6. Redirect na de OIDC-login: `loginRedirect` werkt
Dit volgt uit de bron (`server/controllers/auth.js`, callback
`/login/:strategy/callback`); er is lokaal geen OIDC getest.
- Wiki.js zet de `jwt`-cookie en leest dan de cookie `loginRedirect`.
- `loginRedirect === '/'` en de groep heeft een redirect: dan wint de redirect van de
  groep.
- Anders, bij een geldige waarde (begint met `/`, niet met `//`, bevat geen `://`): er
  wordt doorgestuurd naar `loginRedirect`. **Die wint dus van de redirect van de
  groep.**
- `/mcp/auth/callback?state=…` is een geldige bestemming. Zet de cookie op `Path=/`.

### 7. De `jwt`-cookie
Volgens de bron (`commonHelper.getCookieOpts`):
- **niet** `HttpOnly`, geen `SameSite` (de browser gebruikt dan Lax), geen `Domain`
  (alleen voor de host), `Path=/`
- `Secure` alleen als de site-URL met `https://` begint
- verloopt na 365 dagen

De MCP-server op dezelfde host kan de cookie dus lezen.

### 8. Andere queries als gewone gebruiker

| Query | Lezer of schrijver | Opmerking |
|---|---|---|
| `pages.list`, `pages.tree`, `pages.tags` | ✅ gefilterd | `tree` geeft `pageId` alleen bij pagina's, niet bij mappen |
| `pages.history`, `pages.version` | ✅ met `read:history` | Zonder het globale recht: `Forbidden`. Met het globale recht maar een deny op de pagina: 6012. **Een niet-bestaand id geeft een TypeError** ("Cannot read properties of undefined"), dus het bestaan van een id lekt |
| `site.config` | ❌ `Forbidden` | Vraagt `manage:system`. `wiki_get_site_info` moet hierop terugvallen |
| `localization.config` | ✅ | Ook voor Guest. De standaard-locale komt dus gewoon uit Wiki.js |
| `users.profile` | ✅ | Geeft 1019 bij Guest of een ongeldige token, en `AuthAccountBanned` ("Your account has been disabled.") bij een gedeactiveerde gebruiker met een JWT die (nog) niet is ingetrokken |

### 9. Foutvormen
- **Altijd HTTP 200.** Fouten staan in `errors[]`, met `extensions.code =
  INTERNAL_SERVER_ERROR` en een Wiki.js-code in `extensions.exception.code`.
- Gezien:

  | Code | Betekenis |
  |---|---|
  | 6013 | PageViewForbidden |
  | 6012 | PageHistoryForbidden |
  | 6003 | PageNotFound |
  | 1019 | AuthRequired |
  | 6007 | PageMoveForbidden (in `responseResult` bij mutaties) |
  | geen code, `message: "Forbidden"` | `@auth`-directive: het globale recht ontbreekt |
  | geen code, `message: "Unauthorized"` | ingetrokken gebruiker |

- Mutaties geven bij een fout in de resolver `responseResult { succeeded: false,
  errorCode, slug, message }` terug, bijvoorbeeld 6007 `PageMoveForbidden`.
- Schrijven als schrijver zonder `manage:pages`:
  - `pages.update` werkt, maar **alleen als alle velden worden meegestuurd** (anders
    een TypeError op `tags.map`). Dat doet de huidige client al.
  - Een ander `path` meegeven bij `update` geeft 6007.
  - Uit de bron (`pages.updatePage`): `title`, `description` en `tags` worden altijd
    overschreven.
  - **Ontbreekt `isPublished`, dan wordt de pagina gedepubliceerd.**
  - `publishStartDate` en `publishEndDate` worden leeggemaakt als ze ontbreken. Dat
    doet de huidige client nu al.
  - Heeft de gebruiker `write:styles` of `write:scripts`, dan worden de CSS en JS van de
    pagina **gewist** als `scriptCss` en `scriptJs` ontbreken. Ook dat zit al in de
    huidige client (zelfs met de admin-API-key).
  - Gewone gebruikers kunnen de huidige metadata alleen uit `pages.list` halen. Die geeft
    `id`, `title`, `description`, `tags`, `isPublished`, `isPrivate` en `locale`, maar
    geen publicatiedata en geen CSS/JS.
  - `move` vraagt `manage:pages`; `delete` vraagt `delete:pages`.
- Login via `authentication.login` heeft een rate limit van **5 per minuut** (per IP).
  Voor de MCP-server is dat niet relevant, voor tests wel.

## Beslissingen van de gebruiker (2026-10-15)

- **`get_page` gaat alleen via `/s/`, en `read:source` is verplicht.** Er komt geen
  fallback naar de gerenderde pagina. Wie geen `read:source` heeft, krijgt een
  duidelijke melding.
- **Zoek-engine op productie:** `postgres`.

## Gevolgen voor het plan (verwerkt in PLAN-per-user-auth.md)

1. **`get_page`:** gebruik `/s/<locale>/<pad>` (Markdown, page-id, effectieve rechten).
2. **De huidige inhoud voor `update`:** ook via `/s/`. De metadata komt uit
   `pages.list`. `pages.single` vervalt helemaal.
3. **Een pad omzetten naar een id:** gebruik `page-id` uit `/s/`, en anders
   `pages.list` (id plus pad). Zoekresultaten geven geen id meer door.
4. **Sessie verlopen of ingetrokken herkennen:**
   - Vooraf: een JWT die verder dan de termijn verlopen is, kan meteen weg.
   - Na het verzoek: geen `new-jwt` bij een verlopen token, GraphQL-`"Unauthorized"`,
     of 1019.
   - HTML-routes: een korte timeout (bijvoorbeeld 10 s). Bij een timeout of 500
     controleer je met `users.profile` wat er aan de hand is.
5. **`wiki_whoami`:** `users.profile` en de globale rechten. Is er een pad opgegeven,
   dan ook de effectieve rechten voor die pagina uit `/s/`.
6. **`wiki_search`:** vraag `totalHits` en `suggestions` niet op, en geef ook geen
   `id` door.
7. **`wiki_get_history` en `wiki_get_version`:** zet eerst het pad om naar een id, dan
   bestaat het id altijd en kan het niet meer lekken via de TypeError.
8. **`wiki_get_site_info`:** gebruik alleen `localization.config` en de configuratie van
   de server; `site.config` werkt niet voor gewone gebruikers.
9. **`move` en `delete`:** zijn alleen nuttig voor gebruikers met
   `manage:pages`/`delete:pages`. Laat ze bestaan, maar geef een nette melding.
10. **Bij `update`** stuur je altijd `title`, `description`, `tags` en `isPublished` mee,
    met de huidige waarden uit `pages.list`.
    - Heeft de gebruiker globaal `write:styles` of `write:scripts`, haal dan eerst de
      CSS en JS op via `singleByPath`. Dat werkt alleen met `manage:pages`. Lukt het
      niet, weiger dan de update met een duidelijke melding.
    - Publicatiedata gaan verloren. Neem dat op als bekende beperking.
