"""Wiki.js client acting on behalf of a single user.

Every request carries that user's Wiki.js JWT, so Wiki.js decides what the user may
see and do. Notes on Wiki.js 2.5 behaviour this client relies on (see
FASE0-RESULTATEN.md):

- A JWT that expired beyond the renewal period is silently treated as the Guest
  user, so expiry is checked here before and after every request.
- A renewed JWT comes back in the `new-jwt` header only when the request's
  Content-Type is exactly `application/json`; otherwise as a `jwt` cookie.
- `pages.single` / `pages.singleByPath` require `manage:pages`, so page content is
  read from the source view `/s/<locale>/<path>` (requires `read:source`).
"""

import base64
import html
import json
import logging
import re
import ssl
import time
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import truststore

from . import wiki_jwt
from .config import WikiJSConfig
from .errors import (
    WikiAuthExpired,
    WikiAuthRevoked,
    WikiError,
    WikiForbidden,
    WikiNotFound,
    error_for_code,
    error_for_graphql,
)

logger = logging.getLogger(__name__)

_SOURCE_CONTENT_RE = re.compile(r"<code v-pre>(.*?)</code>", re.S)
_SOURCE_PAGE_ID_RE = re.compile(r':page-id="(\d+)"')
_SOURCE_PERMISSIONS_RE = re.compile(r'effective-permissions="([^"]*)"')

_PAGE_LIST_FIELDS = """
                    id
                    path
                    title
                    description
                    contentType
                    isPublished
                    isPrivate
                    updatedAt
                    createdAt
                    locale
                    tags"""

# Default locale per Wiki.js instance, looked up once per process
_default_locale_cache: dict[str, str] = {}


class WikiJSClient:
    """Client for the Wiki.js GraphQL API and source view, as one user."""

    def __init__(
        self,
        config: WikiJSConfig,
        jwt: str,
        on_new_jwt: Callable[[str], Awaitable[None]] | None = None,
        clock: Callable[[], float] = time.time,
    ):
        self.config = config
        self.jwt = jwt
        self._on_new_jwt = on_new_jwt
        self._clock = clock
        self._page_list: list[dict[str, Any]] | None = None
        ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.client = httpx.AsyncClient(timeout=30.0, verify=ctx)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()

    # ------------------------------------------------------------------
    # Transport and token handling
    # ------------------------------------------------------------------

    def _check_token(self) -> bool:
        """Refuse tokens Wiki.js would treat as Guest; return whether it has expired."""
        now = self._clock()
        if not wiki_jwt.is_renewable(self.jwt, self.config.token_renewal, now):
            raise WikiAuthExpired("Wiki.js session expired")
        return wiki_jwt.expires_at(self.jwt) <= now

    async def _track_token(self, response: httpx.Response, was_expired: bool) -> None:
        """Pick up a renewed JWT, or fail if an expired one was not renewed."""
        new_jwt = response.headers.get("new-jwt") or response.cookies.get("jwt")
        if new_jwt and new_jwt != self.jwt:
            self.jwt = new_jwt
            if self._on_new_jwt:
                await self._on_new_jwt(new_jwt)
        elif was_expired:
            # Wiki.js did not accept the token, so it answered as the Guest user
            raise WikiAuthExpired("Wiki.js session expired")

    async def _execute_query(
        self, query: str, variables: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Execute a GraphQL query against the Wiki.js API."""
        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables

        was_expired = self._check_token()
        try:
            response = await self.client.post(
                self.config.graphql_url,
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.jwt}",
                    # Exactly this value, or Wiki.js sends no new-jwt header
                    "Content-Type": "application/json",
                },
            )
        except httpx.HTTPError as e:
            raise WikiError(f"Request to Wiki.js failed: {type(e).__name__}") from e

        await self._track_token(response, was_expired)

        if response.status_code == 401:
            raise WikiAuthRevoked("API request failed: 401")
        if response.status_code == 403:
            raise WikiForbidden("API request failed: 403")
        if response.is_error:
            logger.error(f"Wiki.js returned HTTP {response.status_code}")
            raise WikiError(f"API request failed: {response.status_code}")

        result = response.json()
        if result.get("errors"):
            messages = [e.get("message") for e in result["errors"]]
            logger.warning(f"GraphQL errors: {messages}")
            raise error_for_graphql(result["errors"][0])

        return result.get("data") or {}

    @staticmethod
    def _check_result(result: dict[str, Any], action: str) -> None:
        """Raise if a mutation's responseResult reports failure."""
        response = result.get("responseResult") or {}
        if not response.get("succeeded"):
            raise error_for_code(
                response.get("errorCode"),
                f"Failed to {action}: {response.get('message', 'Unknown error')}",
            )

    async def _diagnose_failure(self, what: str) -> WikiError:
        """Wiki.js hangs or fails on HTML routes for revoked users; find out why."""
        await self.get_profile()  # raises WikiAuthError if the session is gone
        return WikiError(f"Wiki.js did not return {what}")

    # ------------------------------------------------------------------
    # Site and user
    # ------------------------------------------------------------------

    async def get_localization_config(self) -> dict[str, Any]:
        """Get the site's localization configuration."""
        graphql_query = """
        query GetLocalizationConfig {
            localization {
                config {
                    locale
                    autoUpdate
                    namespacing
                    namespaces
                }
            }
        }
        """

        result = await self._execute_query(graphql_query)
        return result.get("localization", {}).get("config", {})

    async def get_default_locale(self) -> str:
        """The configured default locale, else the site's, cached per process."""
        if self.config.default_locale:
            return self.config.default_locale
        if self.config.url not in _default_locale_cache:
            localization = await self.get_localization_config()
            _default_locale_cache[self.config.url] = localization.get("locale") or "en"
        return _default_locale_cache[self.config.url]

    async def _locale(self, locale: str | None) -> str:
        return locale or await self.get_default_locale()

    async def get_profile(self) -> dict[str, Any]:
        """The current user's profile (name, email, group names)."""
        graphql_query = """
        query GetProfile {
            users {
                profile {
                    id
                    name
                    email
                    groups
                }
            }
        }
        """

        result = await self._execute_query(graphql_query)
        return result.get("users", {}).get("profile") or {}

    # ------------------------------------------------------------------
    # Reading pages
    # ------------------------------------------------------------------

    async def search_pages(
        self, query: str, limit: int = 10, locale: str | None = None
    ) -> list[dict[str, Any]]:
        """Search pages. Results are filtered by Wiki.js on the user's rights.

        `totalHits` and `suggestions` are deliberately not requested: Wiki.js does
        not filter them, so they leak information about forbidden pages.
        """
        graphql_query = """
        query SearchPages($query: String!, $locale: String) {
            pages {
                search(query: $query, locale: $locale) {
                    results {
                        title
                        description
                        path
                        locale
                    }
                }
            }
        }
        """

        variables = {"query": query, "locale": locale}

        result = await self._execute_query(graphql_query, variables)
        results = result.get("pages", {}).get("search", {}).get("results", [])
        return [
            {key: page.get(key) for key in ("title", "description", "path", "locale")}
            for page in results[:limit]
        ]

    async def get_page_source(
        self, path: str, locale: str | None = None, version_id: int | None = None
    ) -> dict[str, Any]:
        """Get a page's (or a past version's) Markdown via the source view.

        Requires the `read:source` right (and `read:history` for a version).
        Returns path, locale, page_id, content and effective_permissions (the
        user's rights on this page, as computed by Wiki.js).
        """
        locale = await self._locale(locale)
        path = path.strip("/")
        url = self.config.page_source_url(path, locale)
        params = {"v": version_id} if version_id else None

        was_expired = self._check_token()
        try:
            response = await self.client.get(
                url,
                params=params,
                headers={"Authorization": f"Bearer {self.jwt}"},
                follow_redirects=False,
                timeout=self.config.html_timeout,
            )
        except httpx.TimeoutException:
            raise await self._diagnose_failure(f"the source of '{path}'") from None
        except httpx.HTTPError as e:
            raise WikiError(f"Request to Wiki.js failed: {type(e).__name__}") from e

        await self._track_token(response, was_expired)

        if response.status_code in (301, 302, 303, 307, 308):
            raise WikiNotFound(f"Page not found: {locale}/{path}")
        if response.status_code == 403:
            raise WikiForbidden(
                f"No access to the source of '{locale}/{path}' "
                "(reading pages requires the read:source permission)"
            )
        if response.status_code >= 500:
            raise await self._diagnose_failure(f"the source of '{path}'")
        if response.is_error:
            raise WikiError(f"Source view returned HTTP {response.status_code}")

        return self._parse_source_page(response.text, path, locale)

    @staticmethod
    def _parse_source_page(text: str, path: str, locale: str) -> dict[str, Any]:
        content = _SOURCE_CONTENT_RE.search(text)
        page_id = _SOURCE_PAGE_ID_RE.search(text)
        if not content or not page_id:
            raise WikiError(f"Unexpected source view format for '{locale}/{path}'")

        permissions: dict[str, Any] = {}
        encoded = _SOURCE_PERMISSIONS_RE.search(text)
        if encoded:
            try:
                permissions = json.loads(base64.b64decode(encoded.group(1)))
            except ValueError:
                logger.warning("Could not decode effective permissions")

        return {
            "path": path,
            "locale": locale,
            "page_id": int(page_id.group(1)),
            "content": html.unescape(content.group(1)),
            "effective_permissions": permissions,
        }

    async def list_pages(
        self,
        limit: int | None = 50,
        tags: list[str] | None = None,
        order_by: str = "TITLE",
        order_by_direction: str = "ASC",
        locale: str | None = None,
    ) -> list[dict[str, Any]]:
        """List pages the user may read, with optional filtering and ordering."""
        graphql_query = f"""
        query ListPages($limit: Int, $orderBy: PageOrderBy, $orderByDirection: PageOrderByDirection, $tags: [String!], $locale: String) {{
            pages {{
                list(limit: $limit, orderBy: $orderBy, orderByDirection: $orderByDirection, tags: $tags, locale: $locale) {{{_PAGE_LIST_FIELDS}
                }}
            }}
        }}
        """

        variables: dict[str, Any] = {
            "limit": limit,
            "orderBy": order_by,
            "orderByDirection": order_by_direction,
        }
        if tags is not None:
            variables["tags"] = tags
        if locale is not None:
            variables["locale"] = locale

        result = await self._execute_query(graphql_query, variables)
        return result.get("pages", {}).get("list", [])

    async def get_page_meta(
        self,
        page_id: int | None = None,
        path: str | None = None,
        locale: str | None = None,
    ) -> dict[str, Any] | None:
        """Metadata of one page, by ID or by path, from `pages.list`.

        `pages.list` is the only metadata source that works without manage:pages.
        The full list is fetched once per client.
        """
        if self._page_list is None:
            self._page_list = await self.list_pages(limit=None)
        if page_id is not None:
            return next((p for p in self._page_list if p["id"] == page_id), None)
        if path is None:
            raise ValueError("Either page_id or path is required")
        path = path.strip("/")
        locale = await self._locale(locale)
        return next(
            (
                p
                for p in self._page_list
                if p["path"] == path and p.get("locale", locale) == locale
            ),
            None,
        )

    async def resolve_page_id(self, path: str, locale: str | None = None) -> int:
        """Page ID for a path the user may read."""
        meta = await self.get_page_meta(path=path, locale=locale)
        if not meta:
            raise WikiNotFound(f"Page not found: {path}")
        return meta["id"]

    async def get_page_tree(
        self,
        parent_path: str = "",
        mode: str = "ALL",
        locale: str | None = None,
        parent_id: int = None,
    ) -> list[dict[str, Any]]:
        """Get page tree structure using the correct schema."""
        graphql_query = """
        query GetPageTree($path: String, $parent: Int, $mode: PageTreeMode!, $locale: String!, $includeAncestors: Boolean) {
            pages {
                tree(path: $path, parent: $parent, mode: $mode, locale: $locale, includeAncestors: $includeAncestors) {
                    id
                    path
                    depth
                    title
                    isPrivate
                    isFolder
                    privateNS
                    parent
                    pageId
                    locale
                }
            }
        }
        """

        variables = {
            "path": parent_path if parent_path else None,
            "parent": parent_id,
            "mode": mode,  # ALL, FOLDERS, or PAGES
            "locale": await self._locale(locale),
            "includeAncestors": False,
        }

        result = await self._execute_query(graphql_query, variables)
        return result.get("pages", {}).get("tree", [])

    async def list_tags(self) -> list[dict[str, Any]]:
        """List all tags."""
        graphql_query = """
        query ListTags {
            pages {
                tags {
                    id
                    tag
                    title
                    createdAt
                    updatedAt
                }
            }
        }
        """

        result = await self._execute_query(graphql_query)
        return result.get("pages", {}).get("tags", [])

    async def get_page_history(
        self,
        page_id: int,
        offset_page: int = 0,
        offset_size: int = 100,
    ) -> dict[str, Any]:
        """Get page edit history."""
        graphql_query = """
        query GetPageHistory($id: Int!, $offsetPage: Int, $offsetSize: Int) {
            pages {
                history(id: $id, offsetPage: $offsetPage, offsetSize: $offsetSize) {
                    trail {
                        versionId
                        versionDate
                        authorId
                        authorName
                        actionType
                        valueBefore
                        valueAfter
                    }
                    total
                }
            }
        }
        """

        variables = {
            "id": page_id,
            "offsetPage": offset_page,
            "offsetSize": offset_size,
        }
        result = await self._execute_query(graphql_query, variables)
        return result.get("pages", {}).get("history", {})

    async def get_page_version(
        self, page_id: int, version_id: int
    ) -> dict[str, Any] | None:
        """Get a specific version of a page."""
        graphql_query = """
        query GetPageVersion($pageId: Int!, $versionId: Int!) {
            pages {
                version(pageId: $pageId, versionId: $versionId) {
                    action
                    authorId
                    authorName
                    content
                    contentType
                    createdAt
                    versionDate
                    description
                    editor
                    isPrivate
                    isPublished
                    locale
                    path
                    tags
                    title
                    versionId
                }
            }
        }
        """

        variables = {"pageId": page_id, "versionId": version_id}
        result = await self._execute_query(graphql_query, variables)
        return result.get("pages", {}).get("version")

    # ------------------------------------------------------------------
    # Writing pages
    # ------------------------------------------------------------------

    async def create_page(
        self,
        path: str,
        title: str,
        content: str,
        description: str = "",
        editor: str = "markdown",
        locale: str | None = None,
        tags: list[str] | None = None,
        is_published: bool = True,
        is_private: bool = False,
    ) -> dict[str, Any]:
        """Create a new page."""
        graphql_query = """
        mutation CreatePage(
            $content: String!,
            $description: String!,
            $editor: String!,
            $isPublished: Boolean!,
            $isPrivate: Boolean!,
            $locale: String!,
            $path: String!,
            $tags: [String]!,
            $title: String!
        ) {
            pages {
                create(
                    content: $content,
                    description: $description,
                    editor: $editor,
                    isPublished: $isPublished,
                    isPrivate: $isPrivate,
                    locale: $locale,
                    path: $path,
                    tags: $tags,
                    title: $title
                ) {
                    responseResult {
                        succeeded
                        errorCode
                        slug
                        message
                    }
                    page {
                        id
                        path
                        title
                    }
                }
            }
        }
        """

        variables = {
            "content": content,
            "description": description,
            "editor": editor,
            "isPublished": is_published,
            "isPrivate": is_private,
            "locale": await self._locale(locale),
            "path": path,
            "tags": tags or [],
            "title": title,
        }

        result = await self._execute_query(graphql_query, variables)
        create_result = result.get("pages", {}).get("create", {})
        self._check_result(create_result, "create page")
        return create_result

    async def _get_page_extras(self, path: str, locale: str) -> dict[str, Any] | None:
        """Custom CSS/JS and publish window of a page; needs manage:pages on it."""
        graphql_query = """
        query GetPageExtras($path: String!, $locale: String!) {
            pages {
                singleByPath(path: $path, locale: $locale) {
                    scriptCss
                    scriptJs
                    publishStartDate
                    publishEndDate
                }
            }
        }
        """

        try:
            result = await self._execute_query(
                graphql_query, {"path": path, "locale": locale}
            )
        except WikiForbidden:
            return None
        return result.get("pages", {}).get("singleByPath")

    async def update_page(
        self,
        page_id: int,
        content: str | None = None,
        title: str | None = None,
        description: str | None = None,
        tags: list[str] | None = None,
        is_private: bool | None = None,
        is_published: bool | None = None,
        locale: str | None = None,
        path: str | None = None,
    ) -> dict[str, Any]:
        """Update a page, keeping every field that is not explicitly changed.

        Wiki.js overwrites title, description, tags and isPublished on every update
        (a missing isPublished unpublishes the page), clears the publish window,
        and clears custom CSS/JS for users allowed to edit those. So the current
        values are always sent along:
        - metadata from `pages.list`, content from the source view
        - CSS/JS and publish window via `singleByPath`, which needs manage:pages.
          Without it the publish window is lost, and the update is refused if the
          user could edit the page's CSS/JS (they would be erased).
        """
        meta = await self.get_page_meta(page_id=page_id)
        if not meta:
            raise WikiNotFound(f"Page with ID {page_id} not found")

        source = await self.get_page_source(meta["path"], meta["locale"])
        page_rights = source["effective_permissions"].get("pages", {})

        update_data: dict[str, Any] = {
            "id": page_id,
            "content": content if content is not None else source["content"],
            "title": title if title is not None else meta.get("title") or "",
            "description": (
                description
                if description is not None
                else meta.get("description") or ""
            ),
            "tags": tags if tags is not None else meta.get("tags") or [],
            "isPublished": (
                is_published if is_published is not None else meta["isPublished"]
            ),
            "isPrivate": is_private if is_private is not None else meta["isPrivate"],
            "locale": locale if locale is not None else meta["locale"],
            "path": path if path is not None else meta["path"],
        }

        extras = await self._get_page_extras(meta["path"], meta["locale"])
        if extras:
            update_data.update(
                {
                    "scriptCss": extras.get("scriptCss") or "",
                    "scriptJs": extras.get("scriptJs") or "",
                    "publishStartDate": extras.get("publishStartDate") or None,
                    "publishEndDate": extras.get("publishEndDate") or None,
                }
            )
        elif page_rights.get("style") or page_rights.get("script"):
            raise WikiForbidden(
                f"Refusing to update '{meta['path']}': Wiki.js would erase the page's "
                "custom CSS/JS, which cannot be read without manage:pages"
            )

        graphql_query = """
        mutation UpdatePage(
            $id: Int!,
            $content: String,
            $description: String,
            $isPrivate: Boolean,
            $isPublished: Boolean,
            $locale: String,
            $path: String,
            $publishEndDate: Date,
            $publishStartDate: Date,
            $scriptCss: String,
            $scriptJs: String,
            $tags: [String],
            $title: String
        ) {
            pages {
                update(
                    id: $id,
                    content: $content,
                    description: $description,
                    isPrivate: $isPrivate,
                    isPublished: $isPublished,
                    locale: $locale,
                    path: $path,
                    publishEndDate: $publishEndDate,
                    publishStartDate: $publishStartDate,
                    scriptCss: $scriptCss,
                    scriptJs: $scriptJs,
                    tags: $tags,
                    title: $title
                ) {
                    responseResult {
                        succeeded
                        errorCode
                        message
                    }
                    page {
                        id
                        path
                        title
                        updatedAt
                    }
                }
            }
        }
        """

        result = await self._execute_query(graphql_query, update_data)
        update_result = result.get("pages", {}).get("update", {})
        self._check_result(update_result, "update page")
        self._page_list = None
        return update_result

    async def delete_page(self, page_id: int) -> dict[str, Any]:
        """Delete a page (requires delete:pages)."""
        graphql_query = """
        mutation DeletePage($id: Int!) {
            pages {
                delete(id: $id) {
                    responseResult {
                        succeeded
                        errorCode
                        message
                    }
                }
            }
        }
        """

        result = await self._execute_query(graphql_query, {"id": page_id})
        delete_result = result.get("pages", {}).get("delete", {})
        self._check_result(delete_result, "delete page")
        self._page_list = None
        return delete_result

    async def move_page(
        self,
        page_id: int,
        destination_path: str,
        destination_locale: str | None = None,
    ) -> dict[str, Any]:
        """Move a page to a new path and/or locale (requires manage:pages)."""
        graphql_query = """
        mutation MovePage($id: Int!, $destinationPath: String!, $destinationLocale: String!) {
            pages {
                move(id: $id, destinationPath: $destinationPath, destinationLocale: $destinationLocale) {
                    responseResult {
                        succeeded
                        errorCode
                        message
                    }
                }
            }
        }
        """

        variables = {
            "id": page_id,
            "destinationPath": destination_path,
            "destinationLocale": await self._locale(destination_locale),
        }

        result = await self._execute_query(graphql_query, variables)
        move_result = result.get("pages", {}).get("move", {})
        self._check_result(move_result, "move page")
        self._page_list = None
        return move_result
