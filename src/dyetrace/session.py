"""U3 session loader.

Parses and schema-validates the portable session JSON (KTD14) into a typed
session object the walkers consume: cookies, auth headers, base URL, the
operator-supplied allowlist host, and the ordered recorded requests. Rejects a
schema-invalid file before any use, and stops fail-closed when the recorded set
yields nothing plantable (R11, R12, R17).

Credential lifecycle (KTD19, R27): cookie and auth-header values are never
logged; the diagnostic helpers here mask them as ``***``. This loader creates no
temporary copy of the session file, so there is none to delete. Encrypted
at-rest storage is out of scope for v1.
"""

import base64
import binascii
import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .masking import MASK, mask_headers, sanitize_url

__all__ = [
    "SessionError",
    "SchemaError",
    "NoPlantableInputError",
    "MultipartPart",
    "Body",
    "RecordedRequest",
    "Session",
    "load_session",
]

# Standard request headers do not count as writable (plantable) inputs for the
# light presence check. Anything else on a request is treated as a custom header
# and so a plantable leaf. Compared lowercased.
_STANDARD_HEADERS = frozenset(
    {
        "host",
        "user-agent",
        "accept",
        "accept-encoding",
        "accept-language",
        "accept-charset",
        "connection",
        "content-type",
        "content-length",
        "cookie",
        "authorization",
        "referer",
        "origin",
        "cache-control",
        "pragma",
        "upgrade-insecure-requests",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-dest",
        "sec-fetch-user",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "dnt",
        "te",
        "date",
    }
)

class SessionError(Exception):
    """Base class for all session-loading failures (fail-closed family)."""


class SchemaError(SessionError):
    """The session file does not conform to the schema; reject before use."""


class NoPlantableInputError(SessionError):
    """The recorded set yields zero plantable parameters; stop fail-closed."""


@dataclass
class MultipartPart:
    name: str | None
    filename: str | None
    content_type: str | None
    data: bytes


@dataclass
class Body:
    content_type: str
    # Byte-faithful payload for text/base64 bodies; None for multipart, whose
    # content lives in ``parts``.
    data: bytes | None = None
    parts: list[MultipartPart] | None = None


@dataclass(repr=False)
class RecordedRequest:
    method: str
    url: str
    headers: list[tuple[str, str]]
    body: Body | None

    def __repr__(self) -> str:
        has_body = self.body is not None
        return (
            f"RecordedRequest(method={self.method!r}, "
            f"url={sanitize_url(self.url)!r}, "
            f"headers={mask_headers(self.headers)!r}, "
            f"body={'<present>' if has_body else None})"
        )


@dataclass(repr=False)
class Session:
    version: str
    cookies: dict[str, str]
    auth_headers: dict[str, str]
    base_url: str
    allowlist_host: str
    recorded_requests: list[RecordedRequest] = field(default_factory=list)

    def __repr__(self) -> str:
        return self.describe()

    def describe(self) -> str:
        """A diagnostic string with every secret value masked (KTD19, R27)."""
        cookies = {name: MASK for name in self.cookies}
        auth = {name: MASK for name in self.auth_headers}
        return (
            "Session("
            f"version={self.version!r}, "
            f"base_url={self.base_url!r}, "
            f"allowlist_host={self.allowlist_host!r}, "
            f"cookies={cookies!r}, "
            f"auth_headers={auth!r}, "
            f"recorded_requests={len(self.recorded_requests)})"
        )


def _require(obj: dict, key: str) -> object:
    if key not in obj:
        raise SchemaError(f"session file missing required field: {key!r}")
    return obj[key]


def _decode_payload(entry: dict, where: str) -> bytes:
    """Decode one text/base64 payload into faithful bytes, or raise SchemaError."""
    encoding = entry.get("encoding", "text")
    data = entry.get("data")
    if not isinstance(data, str):
        raise SchemaError(f"{where}: body 'data' must be a string")
    if encoding == "text":
        return data.encode("utf-8")
    if encoding == "base64":
        try:
            return base64.b64decode(data, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise SchemaError(f"{where}: malformed base64 body") from exc
    raise SchemaError(f"{where}: unknown body encoding {encoding!r}")


def _parse_multipart(parts, where: str) -> list[MultipartPart]:
    if not isinstance(parts, list):
        raise SchemaError(f"{where}: multipart 'parts' must be a list")
    out: list[MultipartPart] = []
    for i, p in enumerate(parts):
        if not isinstance(p, dict):
            raise SchemaError(f"{where}: part {i} must be an object")
        out.append(
            MultipartPart(
                name=p.get("name"),
                filename=p.get("filename"),
                content_type=p.get("content_type"),
                data=_decode_payload(p, f"{where} part {i}"),
            )
        )
    return out


def _parse_body(raw, where: str) -> Body | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise SchemaError(f"{where}: 'body' must be an object or null")
    content_type = _require(raw, "content_type")
    if not isinstance(content_type, str):
        raise SchemaError(f"{where}: body 'content_type' must be a string")
    encoding = raw.get("encoding", "text")
    if encoding == "multipart":
        return Body(
            content_type=content_type,
            data=None,
            parts=_parse_multipart(_require(raw, "parts"), where),
        )
    return Body(content_type=content_type, data=_decode_payload(raw, where))


def _parse_headers(raw, where: str) -> list[tuple[str, str]]:
    if not isinstance(raw, list):
        raise SchemaError(f"{where}: 'headers' must be a list")
    headers: list[tuple[str, str]] = []
    for i, h in enumerate(raw):
        if (
            not isinstance(h, (list, tuple))
            or len(h) != 2
            or not isinstance(h[0], str)
            or not isinstance(h[1], str)
        ):
            raise SchemaError(f"{where}: header {i} must be a [name, value] pair")
        headers.append((h[0], h[1]))
    return headers


def _parse_request(raw, index: int) -> RecordedRequest:
    where = f"recorded_requests[{index}]"
    if not isinstance(raw, dict):
        raise SchemaError(f"{where} must be an object")
    method = _require(raw, "method")
    url = _require(raw, "url")
    if not isinstance(method, str) or not method:
        raise SchemaError(f"{where}: 'method' must be a non-empty string")
    if not isinstance(url, str) or not url:
        raise SchemaError(f"{where}: 'url' must be a non-empty string")
    try:
        split = urlsplit(url)
    except ValueError as exc:
        raise SchemaError(f"{where}: 'url' is malformed: {exc}") from exc
    if not split.scheme or not split.netloc:
        raise SchemaError(f"{where}: 'url' must be absolute")
    return RecordedRequest(
        method=method,
        url=url,
        headers=_parse_headers(raw.get("headers", []), where),
        body=_parse_body(raw.get("body"), where),
    )


def _is_plantable(req: RecordedRequest) -> bool:
    """Light presence check: does this request carry any writable leaf?

    A request is plantable if it has any query string, any path beyond "/", any
    custom (non-standard) header, or any body. Deep per-leaf walking is U4's job.
    """
    split = urlsplit(req.url)
    if split.query:
        return True
    if split.path not in ("", "/"):
        return True
    if any(name.lower() not in _STANDARD_HEADERS for name, _ in req.headers):
        return True
    if req.body is not None:
        return True
    return False


def load_session(path, allowlist_host: str) -> Session:
    """Load, schema-validate, and return a typed Session.

    The allowlist host is taken from the operator (``allowlist_host``), not
    derived from ``base_url`` alone (KTD8). Raises SchemaError for a
    schema-invalid file before any use, and NoPlantableInputError when the
    recorded set yields zero plantable parameters (R12, R17, KTD11).
    """
    path = Path(path)
    if not isinstance(allowlist_host, str) or not allowlist_host:
        raise SessionError("allowlist_host must be a non-empty string")

    try:
        text = path.read_text()
    except OSError as exc:
        # Report the path, never any file content.
        raise SessionError(f"cannot read session file: {path}") from exc

    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SchemaError(f"session file is not valid JSON: {path}") from exc

    if not isinstance(obj, dict):
        raise SchemaError("session file must be a JSON object")

    version = _require(obj, "version")
    cookies = _require(obj, "cookies")
    auth_headers = _require(obj, "auth_headers")
    base_url = _require(obj, "base_url")
    recorded = _require(obj, "recorded_requests")

    if not isinstance(cookies, dict):
        raise SchemaError("'cookies' must be an object")
    if not isinstance(auth_headers, dict):
        raise SchemaError("'auth_headers' must be an object")
    if not isinstance(base_url, str) or not base_url:
        raise SchemaError("'base_url' must be a non-empty string")
    if not isinstance(recorded, list):
        raise SchemaError("'recorded_requests' must be a list")
    if not recorded:
        raise NoPlantableInputError("recorded_requests is empty")

    requests = [_parse_request(r, i) for i, r in enumerate(recorded)]

    if not any(_is_plantable(r) for r in requests):
        raise NoPlantableInputError(
            "recorded requests contain zero plantable parameters"
        )

    return Session(
        version=str(version),
        cookies={str(k): str(v) for k, v in cookies.items()},
        auth_headers={str(k): str(v) for k, v in auth_headers.items()},
        base_url=base_url,
        allowlist_host=allowlist_host,
        recorded_requests=requests,
    )
