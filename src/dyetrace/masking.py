"""Shared credential/URL masking (R22, R27, KTD19).

A single home for the masking primitives the loader, the walkers, the renderer,
and the propagator all depend on. These were underscore-private members of
``session`` that three other modules reached into; promoting them to a named
internal module makes the dependency explicit and gives the masking rules one
place to live and be tested. Over-masking a diagnostic is safe; under-masking
leaks a credential, so every rule here errs toward masking.
"""

import re
from urllib.parse import urlsplit, urlunsplit

__all__ = [
    "MASK",
    "SENSITIVE_HEADERS",
    "SENSITIVE_HEADER_SUBSTRINGS",
    "is_sensitive_header",
    "mask_headers",
    "mask_path",
    "mask_route_detail",
    "mask_text",
    "sanitize_url",
    "terminal_safe",
]

MASK = "***"

# Header names whose values are secret and must be masked in any diagnostic.
# Explicit names plus substring patterns so a custom auth header (an operator's
# own X-Api-Key or X-Session-Token) is masked even though a RecordedRequest does
# not carry a back-reference to the session's auth_headers.
SENSITIVE_HEADERS = frozenset(
    {
        "cookie",
        "set-cookie",
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
    }
)
SENSITIVE_HEADER_SUBSTRINGS = (
    "token",
    "secret",
    "key",
    "auth",
    "cookie",
    "session",
    "credential",
)

# A path segment that looks like a secret: a JWT (three substantial base64url
# parts), or a long opaque token mixing letters and digits (reset tokens, API
# keys, hashes, capability UUIDs). Readable slugs ("profile", "reset-password")
# and plain numeric ids are left intact so the report stays useful; only
# high-entropy opaque segments are masked (R22).
_JWT_SEGMENT = re.compile(r"\A[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\Z")
_OPAQUE_SEGMENT = re.compile(r"\A[A-Za-z0-9_-]{20,}\Z")


def is_sensitive_header(name: str) -> bool:
    low = name.lower()
    if low in SENSITIVE_HEADERS:
        return True
    return any(part in low for part in SENSITIVE_HEADER_SUBSTRINGS)


def mask_headers(headers):
    """Mask the value of every sensitive header, leaving the rest legible."""
    return [
        (name, MASK if is_sensitive_header(name) else value)
        for name, value in headers
    ]


def _segment_looks_secret(segment: str) -> bool:
    if _JWT_SEGMENT.match(segment):
        return True
    return bool(
        _OPAQUE_SEGMENT.match(segment)
        and any(c.isdigit() for c in segment)
        and any(c.isalpha() for c in segment)
    )


def mask_path(path: str) -> str:
    """Mask only the path segments that look like secrets (R22).

    A reset token or JWT embedded in the URL path must not reach a report, but
    masking every segment would destroy the endpoint readability the report
    exists for, so each segment is judged on its own.
    """
    if not path:
        return path
    return "/".join(
        MASK if seg and _segment_looks_secret(seg) else seg
        for seg in path.split("/")
    )


def mask_route_detail(detail: str) -> str:
    """Mask a jevsec "<verb> <path>" entry detail for report output (R22).

    The path token gets segment masking; anything after a "?" is a query and
    is masked whole, since _pattern-guarded details reach here unparseable and
    may carry secrets. A single-token detail (no "<verb> <path>" shape) is
    masked when it looks like an opaque secret.
    """
    parts = detail.split(None, 1)
    text = parts[1].strip() if len(parts) == 2 else detail
    path, sep, query = text.partition("?")
    out = mask_path(path)
    if sep:
        out += "?" + MASK
    return out


def sanitize_url(url: str) -> str:
    """Strip userinfo, mask secret-looking path segments, query values, and any
    fragment, so a URL in a repr or a report cannot leak a token (R22)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return MASK
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:
        return MASK
    netloc = f"{host}:{port}" if port else host
    query = parts.query
    if query:
        masked = []
        for comp in query.split("&"):
            # Keep a param name so the shape is legible, but mask its value; a
            # component with no '=' is a bare token and is masked whole.
            name, sep, _ = comp.partition("=")
            masked.append(f"{name}={MASK}" if sep else MASK)
        query = "&".join(masked)
    fragment = MASK if parts.fragment else ""
    return urlunsplit((parts.scheme, netloc, mask_path(parts.path), query, fragment))


# A CSI/ANSI escape sequence (ESC [ ... final byte) plus a lone ESC, stripped so
# a response body cannot move the cursor, recolor, or spoof the terminal.
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b")
# C0 (0x00-0x1f) and C1 (0x80-0x9f) control bytes. Tab and newline are stripped
# too: a table cell is single-line, so an embedded newline would itself corrupt
# the layout.
_CTRL_RE = re.compile(r"[\x00-\x1f\x80-\x9f]")


def terminal_safe(text):
    """Neutralize ANSI escapes and C0/C1 control bytes for a terminal (R23)."""
    return _CTRL_RE.sub("", _ANSI_RE.sub("", text))


_DELIMS = " \t\r\n=:,;\"'()[]{}<>|&"


def _is_plain_url(word):
    """True only for a word that is a URL from its first character
    (scheme://host...). A word that merely contains '://' after other text
    (key=secret://x) is not parsed as a URL, because the URL parser would read
    the whole word as a path and miss the secret; it takes the delimiter path."""
    try:
        parts = urlsplit(word)
    except ValueError:
        return False
    return bool(parts.scheme and parts.netloc and word.startswith(parts.scheme + "://"))


def mask_text(text):
    """Mask a free-form static value: URLs via sanitize_url, other chunks via
    segment masking after splitting on delimiters, so a secret inside a
    sentence or key=value pair is still caught. Over-masking is safe."""
    out = []
    for word in text.split(" "):
        if _is_plain_url(word):
            out.append(sanitize_url(word))
            continue
        chunk, pieces = "", []
        for ch in word:
            if ch in _DELIMS:
                if chunk:
                    pieces.append(mask_path(chunk))
                    chunk = ""
                pieces.append(ch)
            else:
                chunk += ch
        if chunk:
            pieces.append(mask_path(chunk))
        out.append("".join(pieces))
    return " ".join(out)
