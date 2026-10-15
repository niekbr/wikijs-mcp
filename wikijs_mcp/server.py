"""WikiJS MCP Server.

Every tool call runs as the Wiki.js user behind the caller's MCP token, with that
user's own Wiki.js session. Wiki.js decides what the user may see and do.
"""

import argparse
import asyncio
import contextlib
import json
import logging
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from urllib.parse import urlsplit

from mcp.server import FastMCP
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette

from . import wiki_jwt
from .auth import (
    StoreTokenVerifier,
    UserSource,
    static_user_source,
    token_user_source,
)
from .client import WikiJSClient
from .config import WikiJSConfig, parse_duration
from .errors import (
    WikiAuthExpired,
    WikiAuthRevoked,
    WikiError,
    WikiForbidden,
    WikiNotFound,
)
from .oauth import WikiOAuthProvider, issuer_url, oauth_routes
from .store import Store
from .web import WebRoutes

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("wikijs_mcp.audit")

INSTRUCTIONS = (
    "Wiki.js MCP server — you act as the signed-in wiki user and see only what "
    "they may see.\n"
    "- Start with wiki_list_pages or wiki_get_tree to orient yourself, or "
    "wiki_search when you know keywords.\n"
    "- Work with page paths (e.g. 'team/onboarding'). The server looks up page "
    "IDs itself; every tool that takes a page also accepts a path.\n"
    "- Reading page content requires the read:source permission in the wiki.\n"
    "- A page the user has no access to looks the same as a page that does not "
    "exist.\n"
    "- wiki_whoami shows the user's groups and permissions, also for one page.\n"
    "- Use metadata_only=True on wiki_get_page to skip content and save context.\n"
    "- Use wiki_list_tags to discover tags, then filter wiki_list_pages by tag.\n"
    "- When the wiki session has expired, tell the user to log in again at the "
    "URL given in the error."
)
WRITE_INSTRUCTIONS = (
    "\n- wiki_update_page supports surgical find-and-replace edits via 'edits' — "
    "prefer this over full content replacement for small changes.\n"
    "- When creating a page without an explicit locale, the site's default locale "
    "is used."
)


def _page_label(path: str | None, id: int | None, locale: str | None = None) -> str:
    if path:
        return f"{locale}/{path.strip('/')}" if locale else path.strip("/")
    if id is not None:
        return f"page {id}"
    return "the page"


def _require_page(path: str | None, id: int | None) -> None:
    if path is None and id is None:
        raise ValueError("Either 'path' or 'id' parameter is required")
    if path is not None and id is not None:
        raise ValueError(
            "Cannot specify both 'path' and 'id' parameters - use only one"
        )


def _rights(effective: dict) -> str:
    parts = []
    for area, actions in effective.items():
        allowed = [name for name, value in actions.items() if value]
        if allowed:
            parts.append(f"{area}: {', '.join(allowed)}")
    return "; ".join(parts) or "none"


class WikiJSMCPServer:
    """MCP Server for Wiki.js integration, acting per user."""

    def __init__(
        self,
        config: WikiJSConfig | None = None,
        user_source: UserSource | None = None,
        token_verifier: StoreTokenVerifier | None = None,
    ):
        self.config = config or WikiJSConfig.load_config()
        self._user_source = user_source
        settings: dict = {}
        if token_verifier is not None:
            public_host = urlsplit(self.config.public_url).netloc
            settings = {
                "token_verifier": token_verifier,
                "auth": self._auth_settings(),
                "streamable_http_path": self.config.mcp_base_path.rstrip("/") + "/",
                "transport_security": TransportSecuritySettings(
                    enable_dns_rebinding_protection=True,
                    allowed_hosts=[public_host],
                    allowed_origins=[self.config.public_url.rstrip("/")],
                ),
            }
        instructions = INSTRUCTIONS + (
            "" if self.config.read_only else WRITE_INSTRUCTIONS
        )
        self.app = FastMCP(
            name="wikijs-mcp-server", instructions=instructions, **settings
        )
        self._setup_tools()

    def _auth_settings(self) -> AuthSettings:
        if self.config.oauth_enabled:
            # Advertise our authorization server: WWW-Authenticate then points to
            # /.well-known/oauth-protected-resource<base>/, served by the SDK
            return AuthSettings(
                issuer_url=issuer_url(self.config),
                resource_server_url=self.config.mcp_url,
                validate_token_resource=False,  # personal tokens have no resource
            )
        # Resource server only: no OAuth metadata, personal tokens only
        return AuthSettings(
            issuer_url=self.config.public_url.rstrip("/") + self.config.mcp_base_path,
            resource_server_url=None,
        )

    # ------------------------------------------------------------------
    # Running a tool as the current user
    # ------------------------------------------------------------------

    def _error_message(self, error: WikiError, target: str, denied_hint: str) -> str:
        if isinstance(error, WikiAuthRevoked):
            return (
                "The wiki no longer accepts this session: the account may have been "
                "deactivated or its access revoked. Log in again at "
                f"{self.config.login_url}; if that fails, contact a wiki administrator."
            )
        if isinstance(error, WikiAuthExpired):
            return (
                "The wiki session has expired. Log in again at "
                f"{self.config.login_url} and retry."
            )
        if isinstance(error, WikiForbidden | WikiNotFound):
            message = f"No access to {target}, or it does not exist."
            return f"{message} {denied_hint}".strip()
        return f"Wiki.js error: {error}"

    @contextlib.asynccontextmanager
    async def _session(
        self, tool: str, target: str = "", denied_hint: str = ""
    ) -> AsyncIterator[WikiJSClient]:
        """One Wiki.js client for one tool call, with error mapping and auditing."""
        audit = {"tool": tool, "target": target, "user_id": None, "email": None}
        outcome = "error"
        try:
            if self._user_source is None:
                raise WikiAuthExpired("No user source configured")
            user = await self._user_source()
            audit.update(user_id=user.wiki_user_id, email=user.email)
            async with WikiJSClient(self.config, user.jwt, user.on_new_jwt) as client:
                yield client
            outcome = "ok"
        except WikiError as e:
            outcome = (
                "expired"
                if isinstance(e, WikiAuthExpired | WikiAuthRevoked)
                else "denied"
                if isinstance(e, WikiForbidden | WikiNotFound)
                else "error"
            )
            raise ToolError(
                self._error_message(e, target or "this", denied_hint)
            ) from e
        finally:
            audit_logger.info(json.dumps({**audit, "outcome": outcome}))

    def _setup_tools(self):
        """Setup MCP tools."""
        config = self.config

        @self.app.tool(
            description="Full-text search across the wiki pages the user may read. Returns titles, paths, locales and descriptions. Use this when you know keywords but not the page location."
        )
        async def wiki_search(
            query: str, limit: int = 10, locale: str | None = None
        ) -> str:
            """Search for pages in Wiki.js.

            Args:
                query: Search query for finding pages
                limit: Maximum number of results (default: 10)
                locale: Only search pages in this locale (default: all locales)
            """
            async with self._session("wiki_search", query) as client:
                results = await client.search_pages(query, limit, locale)

            if not results:
                return f"No pages found for query: {query}"

            response = f"Found {len(results)} pages for query '{query}':\n\n"
            for page in results:
                response += f"**{page['title']}**\n"
                response += f"Path: {page['path']}\n"
                if page.get("description"):
                    response += f"Description: {page['description']}\n"
                if page.get("locale"):
                    response += f"Locale: {page['locale']}\n"
                response += "\n"
            return response

        @self.app.tool(
            description="Retrieve a single wiki page by its path (preferred) or numeric ID. Returns content plus metadata (title, tags, content type, dates). Set metadata_only=True to skip content and save context tokens. Set version_id (from wiki_get_history) to read a past version. Reading content requires the read:source permission."
        )
        async def wiki_get_page(
            path: str | None = None,
            id: int | None = None,
            locale: str | None = None,
            metadata_only: bool = False,
            version_id: int | None = None,
        ) -> str:
            """Get a specific wiki page by path or ID.

            Args:
                path: Page path (e.g., 'docs/getting-started'). Use either path OR id, not both.
                id: Page ID. Use either path OR id, not both.
                locale: Page locale (default: the site's default locale). Only used with path.
                metadata_only: If True, skip page content to save context tokens (default: False).
                version_id: Return the content of this past version instead (optional).
            """
            _require_page(path, id)
            target = _page_label(path, id, locale)
            hint = "Reading page content requires the read:source permission; wiki_whoami shows your permissions."
            async with self._session("wiki_get_page", target, hint) as client:
                if id is not None:
                    page = await client.get_page_meta(page_id=id)
                else:
                    page = await client.get_page_meta(path=path, locale=locale)
                if not page:
                    raise WikiNotFound(target)
                source = None
                if not metadata_only:
                    source = await client.get_page_source(
                        page["path"], page["locale"], version_id
                    )

            response = f"# {page['title']}\n\n"
            response += f"**Path:** {page['path']}\n"
            response += f"**ID:** {page['id']}\n"
            if page.get("description"):
                response += f"**Description:** {page['description']}\n"
            if page.get("contentType"):
                response += f"**Content Type:** {page['contentType']}\n"
            response += f"**Locale:** {page['locale']}\n"
            if page.get("isPublished") is False:
                response += "**Published:** no\n"
            if page.get("isPrivate"):
                response += "**Private:** yes\n"
            response += f"**Created:** {page.get('createdAt', 'unknown')}\n"
            response += f"**Updated:** {page.get('updatedAt', 'unknown')}\n"
            if page.get("tags"):
                response += f"**Tags:** {', '.join(page['tags'])}\n"
            if version_id:
                response += f"**Version:** {version_id}\n"
            if source is not None:
                response += "\n---\n\n"
                response += source["content"]
            return response

        @self.app.tool(
            description="List the wiki pages the user may read, with optional tag filtering and sort order. Returns page metadata (including tags and content type) without content. Supports filtering by tags (AND logic) and ordering by CREATED, ID, PATH, TITLE, or UPDATED."
        )
        async def wiki_list_pages(
            limit: int = 50,
            tags: list[str] | None = None,
            order_by: str = "TITLE",
            order_by_direction: str = "ASC",
            locale: str | None = None,
        ) -> str:
            """List wiki pages with optional filtering and ordering.

            Args:
                limit: Number of pages to return (default: 50)
                tags: Filter by tags — only pages with ALL specified tags are returned (optional)
                order_by: Sort field — CREATED, ID, PATH, TITLE, or UPDATED (default: TITLE)
                order_by_direction: Sort direction — ASC or DESC (default: ASC)
                locale: Only list pages in this locale (default: all locales)
            """
            valid_order_by = {"CREATED", "ID", "PATH", "TITLE", "UPDATED"}
            if order_by not in valid_order_by:
                raise ValueError(
                    f"Invalid order_by value '{order_by}'. Must be one of: {', '.join(sorted(valid_order_by))}"
                )
            valid_directions = {"ASC", "DESC"}
            if order_by_direction not in valid_directions:
                raise ValueError(
                    f"Invalid order_by_direction value '{order_by_direction}'. Must be one of: {', '.join(sorted(valid_directions))}"
                )

            async with self._session("wiki_list_pages", ",".join(tags or [])) as client:
                pages = await client.list_pages(
                    limit,
                    tags=tags,
                    order_by=order_by,
                    order_by_direction=order_by_direction,
                    locale=locale,
                )

            if not pages:
                return "No pages found"

            response = f"Found {len(pages)} pages (limit: {limit}):\n\n"
            for page in pages:
                response += f"**{page['title']}**\n"
                response += f"Path: {page['path']} (ID: {page['id']})\n"
                if page.get("description"):
                    response += f"Description: {page['description']}\n"
                if page.get("contentType"):
                    response += f"Content Type: {page['contentType']}\n"
                if page.get("tags"):
                    response += f"Tags: {', '.join(page['tags'])}\n"
                response += f"Updated: {page['updatedAt']}\n\n"
            return response

        @self.app.tool(
            description="Get the hierarchical folder/page tree structure starting from a given path. Use this instead of list_pages when you need to understand how pages are organized in folders. Returns depth-indented entries showing folders and pages."
        )
        async def wiki_get_tree(
            parent_path: str = "",
            mode: str = "ALL",
            locale: str | None = None,
            parent_id: int | None = None,
        ) -> str:
            """Get wiki page tree structure.

            Args:
                parent_path: Parent path to get tree from (default: root)
                mode: Tree mode - ALL, FOLDERS, or PAGES (default: ALL)
                locale: Page locale (default: the site's default locale)
                parent_id: Parent tree item ID (optional)
            """
            async with self._session("wiki_get_tree", parent_path) as client:
                tree = await client.get_page_tree(parent_path, mode, locale, parent_id)

            if not tree:
                return "No pages found in tree"

            response = (
                f"Wiki page tree from '{parent_path or 'root'}' (mode: {mode}):\n\n"
            )
            for item in tree:
                indent = "  " * item.get("depth", 0)
                if item.get("isFolder"):
                    response += f"{indent}📁 {item['title']}/\n"
                else:
                    response += f"{indent}📄 {item['title']} ({item['path']})\n"
            return response

        @self.app.tool(
            description="List the tags used on wiki pages the user may read. Use this to discover available tags before filtering wiki_list_pages by tag."
        )
        async def wiki_list_tags() -> str:
            """List all tags."""
            async with self._session("wiki_list_tags") as client:
                tags = await client.list_tags()

            if not tags:
                return "No tags found"

            response = f"Found {len(tags)} tag(s):\n\n"
            for tag in tags:
                response += f"**{tag.get('title') or tag.get('tag', 'Unknown')}**\n"
                response += f"Tag: {tag.get('tag', '')}\n\n"
            return response

        @self.app.tool(
            description="Get Wiki.js site information: the wiki's URL, its default locale and multilingual namespacing. Useful to know which locale page operations should use."
        )
        async def wiki_get_site_info() -> str:
            """Get site and localization settings."""
            async with self._session("wiki_get_site_info") as client:
                localization = await client.get_localization_config()

            response = "**Wiki Site Information:**\n\n"
            if config.public_url:
                response += f"**URL:** {config.public_url}\n"
            if localization.get("locale"):
                response += f"**Default Locale:** {localization['locale']}\n"
            if "namespacing" in localization:
                namespacing = "Enabled" if localization["namespacing"] else "Disabled"
                response += f"**Multilingual Namespacing:** {namespacing}\n"
            if localization.get("namespaces"):
                response += (
                    f"**Locale Namespaces:** {', '.join(localization['namespaces'])}\n"
                )
            return response

        @self.app.tool(
            description="Get the edit history of a wiki page by path (preferred) or ID. Returns versions with timestamps, authors, and change types. Requires the read:history permission. Supports pagination via offset_page and offset_size."
        )
        async def wiki_get_history(
            path: str | None = None,
            id: int | None = None,
            locale: str | None = None,
            offset_page: int = 0,
            offset_size: int = 100,
        ) -> str:
            """Get page edit history.

            Args:
                path: Page path. Use either path OR id, not both.
                id: Page ID. Use either path OR id, not both.
                locale: Page locale (default: the site's default locale). Only used with path.
                offset_page: Page offset for pagination (default: 0)
                offset_size: Number of entries per page (default: 100)
            """
            _require_page(path, id)
            target = _page_label(path, id, locale)
            async with self._session(
                "wiki_get_history",
                target,
                "History requires the read:history permission.",
            ) as client:
                page_id = await self._page_id(client, path, id, locale)
                history = await client.get_page_history(
                    page_id, offset_page, offset_size
                )

            trail = history.get("trail", [])
            total = history.get("total", 0)
            if not trail:
                return f"No history found for {target}"

            response = f"Page history for {target} ({total} total version(s)):\n\n"
            for entry in trail:
                response += f"**Version {entry.get('versionId', '?')}**\n"
                response += f"Date: {entry.get('versionDate', 'Unknown')}\n"
                response += f"Author: {entry.get('authorName', 'Unknown')}\n"
                response += f"Action: {entry.get('actionType', 'Unknown')}\n\n"
            return response

        @self.app.tool(
            description="Retrieve a specific historical version of a wiki page, by page path (preferred) or ID plus a version ID from wiki_get_history. Returns the content and metadata as they were then. Requires the read:history permission."
        )
        async def wiki_get_version(
            version_id: int,
            path: str | None = None,
            id: int | None = None,
            locale: str | None = None,
        ) -> str:
            """Get a specific page version.

            Args:
                version_id: Version ID (from wiki_get_history)
                path: Page path. Use either path OR id, not both.
                id: Page ID. Use either path OR id, not both.
                locale: Page locale (default: the site's default locale). Only used with path.
            """
            _require_page(path, id)
            target = _page_label(path, id, locale)
            async with self._session(
                "wiki_get_version",
                target,
                "History requires the read:history permission.",
            ) as client:
                page_id = await self._page_id(client, path, id, locale)
                version = await client.get_page_version(page_id, version_id)

            if not version:
                return "Version not found"

            response = f"# {version.get('title', 'Unknown')}\n\n"
            response += f"**Version ID:** {version.get('versionId', '?')}\n"
            response += f"**Version Date:** {version.get('versionDate', 'Unknown')}\n"
            response += f"**Author:** {version.get('authorName', 'Unknown')}\n"
            response += f"**Action:** {version.get('action', 'Unknown')}\n"
            response += f"**Path:** {version.get('path', 'Unknown')}\n"
            response += f"**Editor:** {version.get('editor', 'Unknown')}\n"
            if version.get("contentType"):
                response += f"**Content Type:** {version['contentType']}\n"
            if version.get("tags"):
                response += f"**Tags:** {', '.join(version['tags'])}\n"
            response += "\n---\n\n"
            response += version.get("content", "")
            return response

        @self.app.tool(
            description="Show who you are acting as in the wiki: name, email, groups and global permissions. Pass a page path to also see the effective permissions on that page (read, write, source, history, ...)."
        )
        async def wiki_whoami(
            path: str | None = None, locale: str | None = None
        ) -> str:
            """Show the current wiki user and their permissions.

            Args:
                path: Page path to show effective permissions for (optional)
                locale: Page locale (default: the site's default locale)
            """
            target = _page_label(path, None, locale) if path else ""
            async with self._session(
                "wiki_whoami",
                target,
                "Effective permissions are read from the page source view, which requires read:source.",
            ) as client:
                profile = await client.get_profile()
                permissions = wiki_jwt.payload(client.jwt).get("permissions", [])
                page = await client.get_page_source(path, locale) if path else None

            response = "**Wiki user:**\n\n"
            response += f"**Name:** {profile.get('name', 'Unknown')}\n"
            response += f"**Email:** {profile.get('email', 'Unknown')}\n"
            response += (
                f"**Groups:** {', '.join(profile.get('groups') or []) or 'none'}\n"
            )
            response += f"**Global permissions:** {', '.join(permissions) or 'none'}\n"
            response += (
                "\nGlobal permissions are only part of the picture: page rules in "
                "the wiki decide per path. Pass a path to see the effective "
                "permissions on a page.\n"
            )
            if page is not None:
                response += (
                    f"\n**Effective permissions on {page['locale']}/{page['path']}:** "
                    f"{_rights(page['effective_permissions'])}\n"
                )
            return response

        if not config.read_only:
            self._setup_write_tools()

    async def _page_id(
        self, client: WikiJSClient, path: str | None, id: int | None, locale: str | None
    ) -> int:
        """Page ID for a path or ID the user may read."""
        if id is not None:
            if not await client.get_page_meta(page_id=id):
                raise WikiNotFound(f"page {id}")
            return id
        return await client.resolve_page_id(path, locale)

    def _setup_write_tools(self):
        """Tools that change pages; only registered when not read-only."""

        @self.app.tool(
            description="Create a new wiki page at the specified path. Content should match the wiki's editor format (usually markdown). When locale is omitted, the site's default locale is used. The page path determines its location in the wiki hierarchy (e.g., 'team/onboarding' creates under 'team')."
        )
        async def wiki_create_page(
            path: str,
            title: str,
            content: str,
            description: str = "",
            tags: list[str] | None = None,
            editor: str = "markdown",
            locale: str | None = None,
        ) -> str:
            """Create a new wiki page.

            Args:
                path: Page path (e.g., 'docs/new-feature')
                title: Page title
                content: Page content matching the selected editor format
                description: Page description (optional)
                tags: Page tags (optional)
                editor: Page editor format (default: 'markdown')
                locale: Page locale. Uses the site's default when omitted.
            """
            target = _page_label(path, None, locale)
            async with self._session(
                "wiki_create_page", target, "Creating pages requires write:pages there."
            ) as client:
                result = await client.create_page(
                    path=path,
                    title=title,
                    content=content,
                    description=description,
                    tags=tags or [],
                    editor=editor,
                    locale=locale,
                )

            page_info = result.get("page") or {}
            response = "✅ Successfully created page:\n\n"
            response += f"**Title:** {page_info.get('title', title)}\n"
            response += f"**Path:** {page_info.get('path', path)}\n"
            response += f"**ID:** {page_info.get('id', 'Unknown')}\n"
            return response

        @self.app.tool(
            description="Update an existing wiki page by path (preferred) or ID. Supports two content-editing modes: (1) full replacement via 'content', or (2) surgical find-and-replace via 'edits' — a list of {old_text, new_text} pairs applied sequentially. Prefer 'edits' for small, targeted changes. Title, description, and tags can also be updated independently; everything not given is kept."
        )
        async def wiki_update_page(
            path: str | None = None,
            id: int | None = None,
            locale: str | None = None,
            content: str | None = None,
            edits: list[dict] | None = None,
            title: str | None = None,
            description: str | None = None,
            tags: list[str] | None = None,
        ) -> str:
            """Update an existing wiki page.

            Supports two modes for changing content:
            - Full replace: provide 'content' with the entire new page body.
            - Find-and-replace: provide 'edits' as a list of
              {"old_text": "...", "new_text": "..."} pairs. Each old_text is
              replaced with new_text in the existing page content.

            Use 'edits' for small changes to avoid regenerating the full page.
            Do not provide both 'content' and 'edits'.

            Args:
                path: Page path. Use either path OR id, not both.
                id: Page ID. Use either path OR id, not both.
                locale: Page locale (default: the site's default locale). Only used with path.
                content: Full replacement content in markdown (optional)
                edits: List of find-and-replace edits (optional)
                title: New page title (optional)
                description: New page description (optional)
                tags: New page tags (optional)
            """
            _require_page(path, id)
            if content is not None and edits is not None:
                raise ValueError(
                    "Cannot specify both 'content' and 'edits' — use one or the other"
                )
            for edit in edits or []:
                if not edit.get("old_text"):
                    raise ValueError("Each edit must have a non-empty 'old_text'")

            target = _page_label(path, id, locale)
            applied_edits = []
            async with self._session(
                "wiki_update_page",
                target,
                "Updating pages requires write:pages (and read:source to read the current content).",
            ) as client:
                page_id = await self._page_id(client, path, id, locale)
                if edits is not None:
                    meta = await client.get_page_meta(page_id=page_id)
                    current = await client.get_page_source(meta["path"], meta["locale"])
                    content = current["content"]
                    for edit in edits:
                        old_text = edit["old_text"]
                        new_text = edit.get("new_text", "")
                        if old_text not in content:
                            raise ValueError(
                                f"old_text not found in page content: {old_text[:80]!r}"
                            )
                        content = content.replace(old_text, new_text, 1)
                        applied_edits.append((old_text, new_text))

                result = await client.update_page(
                    page_id=page_id,
                    content=content,
                    title=title,
                    description=description,
                    tags=tags,
                )

            page_info = result.get("page") or {}
            response = "Successfully updated page:\n\n"
            response += f"**Title:** {page_info.get('title', 'Unknown')}\n"
            response += f"**Path:** {page_info.get('path', 'Unknown')}\n"
            response += f"**ID:** {page_info.get('id', page_id)}\n"
            response += f"**Updated:** {page_info.get('updatedAt', 'Just now')}\n"
            if applied_edits:
                response += f"\nApplied {len(applied_edits)} edit(s):\n"
                for old_text, new_text in applied_edits:
                    old_preview = (
                        old_text[:60] + "..." if len(old_text) > 60 else old_text
                    )
                    new_preview = (
                        new_text[:60] + "..." if len(new_text) > 60 else new_text
                    )
                    response += f'  - "{old_preview}" → "{new_preview}"\n'
            return response

        @self.app.tool(
            description="Permanently delete a wiki page by path (preferred) or ID. This action cannot be undone. Requires the delete:pages permission."
        )
        async def wiki_delete_page(
            path: str | None = None, id: int | None = None, locale: str | None = None
        ) -> str:
            """Delete a wiki page.

            Args:
                path: Page path. Use either path OR id, not both.
                id: Page ID. Use either path OR id, not both.
                locale: Page locale (default: the site's default locale). Only used with path.
            """
            _require_page(path, id)
            target = _page_label(path, id, locale)
            async with self._session(
                "wiki_delete_page", target, "Deleting pages requires delete:pages."
            ) as client:
                page_id = await self._page_id(client, path, id, locale)
                result = await client.delete_page(page_id=page_id)

            response = f"✅ Successfully deleted {target} (ID: {page_id})\n"
            response_result = result.get("responseResult", {})
            if response_result.get("message"):
                response += f"**Message:** {response_result['message']}\n"
            return response

        @self.app.tool(
            description="Move a wiki page to a new path and/or locale, by path (preferred) or ID. The page keeps its numeric ID. Requires the manage:pages permission on the source and destination."
        )
        async def wiki_move_page(
            destination_path: str,
            path: str | None = None,
            id: int | None = None,
            locale: str | None = None,
            destination_locale: str | None = None,
        ) -> str:
            """Move a wiki page to a new path and/or locale.

            Args:
                destination_path: New path for the page (e.g., 'docs/moved-page')
                path: Current page path. Use either path OR id, not both.
                id: Page ID. Use either path OR id, not both.
                locale: Current page locale (default: the site's default locale).
                destination_locale: New locale (default: the site's default locale)
            """
            _require_page(path, id)
            target = _page_label(path, id, locale)
            async with self._session(
                "wiki_move_page",
                target,
                "Moving pages requires manage:pages on both the source and the destination.",
            ) as client:
                page_id = await self._page_id(client, path, id, locale)
                current = await client.get_page_meta(page_id=page_id)
                result = await client.move_page(
                    page_id=page_id,
                    destination_path=destination_path,
                    destination_locale=destination_locale,
                )
                destination_locale = (
                    destination_locale or await client.get_default_locale()
                )

            response = "✅ Successfully moved page:\n\n"
            response += f"**Title:** {current.get('title', 'Unknown')}\n"
            response += f"**From:** {current['path']} (locale: {current['locale']})\n"
            response += f"**To:** {destination_path} (locale: {destination_locale})\n"
            response += f"**Page ID:** {page_id}\n"
            response_result = result.get("responseResult", {})
            if response_result.get("message"):
                response += f"**Message:** {response_result['message']}\n"
            return response


# ----------------------------------------------------------------------
# Entry points
# ----------------------------------------------------------------------


def build_http_app(config: WikiJSConfig, store: Store) -> Starlette:
    """The complete HTTP app: MCP endpoint, web pages and (optionally) OAuth."""
    server = WikiJSMCPServer(
        config,
        user_source=token_user_source(store),
        token_verifier=StoreTokenVerifier(store),
    )
    WebRoutes(config, store).register(server.app)
    app = server.app.streamable_http_app()
    if config.oauth_enabled:
        app.router.routes.extend(oauth_routes(config, WikiOAuthProvider(config, store)))
    return app


async def _serve(config: WikiJSConfig) -> None:
    """Run the Streamable HTTP server with per-user token auth."""
    import uvicorn

    config.validate_config()
    async with Store(
        config.db_path, config.encryption_key, config.session_max_age
    ) as store:
        app = build_http_app(config, store)

        async def purge_regularly() -> None:
            while True:
                try:
                    await store.purge_expired()
                except Exception:
                    logger.exception("Purging expired data failed")
                await asyncio.sleep(3600)

        purge_task = asyncio.create_task(purge_regularly())
        uvicorn_config = uvicorn.Config(
            app,
            host=config.host,
            port=config.port,
            proxy_headers=True,
            forwarded_allow_ips=config.forwarded_allow_ips,
            log_level="debug" if config.debug else "info",
        )
        logger.info(f"Starting WikiJS MCP Server for {config.url} at {config.mcp_url}")
        try:
            await uvicorn.Server(uvicorn_config).serve()
        finally:
            purge_task.cancel()


async def _verified_profile(config: WikiJSConfig, jwt: str) -> dict:
    """Check that Wiki.js accepts the JWT; returns the user's profile."""
    async with WikiJSClient(config, jwt) as client:
        profile = await client.get_profile()
    if not profile.get("id"):
        raise WikiAuthRevoked("Wiki.js did not return a profile for this token")
    return profile


async def _dev_token(config: WikiJSConfig, jwt_file: str, name: str, ttl: str) -> None:
    """Store a JWT as if the user logged in, and print a personal token."""
    config.validate_config(only=["url", "db_path", "encryption_key"])
    jwt = Path(jwt_file).read_text().strip()
    profile = await _verified_profile(config, jwt)
    async with Store(
        config.db_path, config.encryption_key, config.session_max_age
    ) as store:
        user_id = await store.upsert_login(jwt, profile)
        _, token = await store.create_token(user_id, name, parse_duration(ttl))
    print(f"Personal token for {profile.get('name')} <{profile.get('email')}>:\n")
    print(token)
    print("\nAdd it to Claude Code with:\n")
    print(
        f"claude mcp add --transport http wikijs {config.mcp_url or '<public url>/mcp/'} \\\n"
        f'  --header "Authorization: Bearer {token}"'
    )


async def _stdio(config: WikiJSConfig, jwt_file: str) -> None:
    """Run over stdio as one fixed user, for local development."""
    config.validate_config(only=["url"])
    jwt = Path(jwt_file).read_text().strip()
    profile = await _verified_profile(config, jwt)
    server = WikiJSMCPServer(
        config,
        user_source=static_user_source(jwt, profile["id"], profile.get("email", "")),
    )
    logger.info(
        f"Starting WikiJS MCP Server (stdio) for {config.url} as {profile.get('email')}"
    )
    await server.app.run_stdio_async()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wikijs-mcp",
        description="MCP server for Wiki.js that acts as each signed-in wiki user.",
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="Run the Streamable HTTP server (default)")

    dev_token = sub.add_parser(
        "dev-token", help="Store a Wiki.js JWT and print a personal token (development)"
    )
    dev_token.add_argument("--jwt-file", required=True, help="File with a Wiki.js JWT")
    dev_token.add_argument("--name", default="dev-token", help="Token name")
    dev_token.add_argument("--ttl", default="7d", help="Token lifetime, e.g. 7d")

    stdio = sub.add_parser("stdio", help="Run over stdio as one user (development)")
    stdio.add_argument(
        "--dev-jwt-file", required=True, help="File with the Wiki.js JWT to act as"
    )
    return parser


async def _async_main(argv: list[str] | None = None) -> None:
    """Async entry point."""
    args = _parser().parse_args(argv)
    # Logs go to stderr: stdout carries the MCP protocol in stdio mode
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    # Request URLs contain page paths; the audit log records tool calls instead
    logging.getLogger("httpx").setLevel(logging.WARNING)
    config = WikiJSConfig.load_config()

    if args.command == "dev-token":
        await _dev_token(config, args.jwt_file, args.name, args.ttl)
    elif args.command == "stdio":
        await _stdio(config, args.dev_jwt_file)
    else:
        await _serve(config)


def main():
    """Entry point for the wikijs-mcp command."""
    try:
        asyncio.run(_async_main())
    except (ValueError, WikiError) as e:
        sys.exit(f"wikijs-mcp: {e}")


if __name__ == "__main__":
    main()
