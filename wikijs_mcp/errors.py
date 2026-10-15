"""Exceptions for Wiki.js API errors."""

# Wiki.js 2.5 error codes (server/helpers/error.js)
CODE_AUTH_ACCOUNT_BANNED = 1013
CODE_AUTH_REQUIRED = 1019
CODE_PAGE_NOT_FOUND = 6003
FORBIDDEN_CODES = {
    6007,  # PageMoveForbidden
    6008,  # PageCreateForbidden
    6009,  # PageUpdateForbidden
    6010,  # PageDeleteForbidden
    6011,  # PageRestoreForbidden
    6012,  # PageHistoryForbidden
    6013,  # PageViewForbidden
}


class WikiError(Exception):
    """Any error returned by or while talking to Wiki.js."""


class WikiAuthError(WikiError):
    """The user's Wiki.js session can no longer be used."""


class WikiAuthExpired(WikiAuthError):
    """The JWT expired beyond its renewal period; the user must log in again."""


class WikiAuthRevoked(WikiAuthError):
    """Wiki.js rejected a token that has not expired.

    Usually the account was deactivated or its tokens were revoked; also seen when
    the Wiki.js signing keys changed.
    """


class WikiForbidden(WikiError):
    """Wiki.js refused the action for this user."""


class WikiNotFound(WikiError):
    """The page (or version) does not exist."""


def error_for_code(code: int | None, message: str) -> WikiError:
    """Map a Wiki.js error code to an exception."""
    # The client never sends a JWT past its renewal period, so "authentication
    # required" means Wiki.js did not accept a token it should have.
    if code in (CODE_AUTH_REQUIRED, CODE_AUTH_ACCOUNT_BANNED):
        return WikiAuthRevoked(message)
    if code == CODE_PAGE_NOT_FOUND:
        return WikiNotFound(message)
    if code in FORBIDDEN_CODES:
        return WikiForbidden(message)
    return WikiError(message)


def error_for_graphql(error: dict) -> WikiError:
    """Map one entry of a GraphQL `errors` list to an exception."""
    message = error.get("message", "Unknown error")
    code = error.get("extensions", {}).get("exception", {}).get("code")
    if code is None:
        # The @auth directive: no user at all (revoked) or missing global permission
        if message == "Unauthorized":
            return WikiAuthRevoked(message)
        if message == "Forbidden":
            return WikiForbidden(message)
    return error_for_code(code, message)
