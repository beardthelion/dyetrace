"""U4 injection walkers and plant.

Substitutes a fresh self-identifying tracer (U2) into every observed writable
input of every recorded request (U3), one planted descriptor per injection site
per enabled encoding variant. Each writable leaf is reached by a structure-aware
walker that parses the input, injects at exactly one leaf, and re-serializes
once; nothing is regex- or string-spliced into serialized text (KTD6). Leaves
carry a stable canonical path id so a resurfacing is unambiguously attributable
(R7, R19), and recorded mutating methods are fired only behind an explicit
confirm flag, skipped and recorded otherwise (R26, KTD15).

Decoupling boundary: this module sends nothing and builds no httpx objects. It
emits planted-request descriptors for the network layer (U5/U6) to send. A raw
body is carried as bytes for ``content=``; a multipart body is carried as text
fields plus file parts so the sender hands httpx ``data=``/``files=`` and httpx
owns the boundary and Content-Length (KTD7).
"""

import json
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from . import marker
from .masking import mask_headers, sanitize_url
from .session import _STANDARD_HEADERS


def _masked_original(value):
    """Redact a site's original value in diagnostics.

    Any site value can be a secret (a token in a query or form field, a
    password in a JSON body, a credential in a header), so show only its type
    and length, never the value.
    """
    if isinstance(value, (str, bytes)):
        return f"<{type(value).__name__} len={len(value)}>"
    return f"<{type(value).__name__}>"

__all__ = [
    "RawBody",
    "MultipartBody",
    "PlantedRequest",
    "Attribution",
    "SkippedRequest",
    "PlantResult",
    "plant",
]

# Methods that only read. Anything else mutates and is gated by R26 (KTD15).
_SAFE_METHODS = frozenset({"GET", "HEAD"})


@dataclass
class RawBody:
    """A raw text/bytes body the sender hands httpx as ``content=``.

    The Content-Type stays in the descriptor's header list, so it is not
    repeated here.
    """

    data: bytes


@dataclass
class MultipartBody:
    """A multipart body split for the sender to hand httpx.

    ``data_fields`` are the text parts (no filename) as ordered (name, value)
    pairs for ``data=``; ``file_parts`` are the file parts as ordered
    (name, (filename, content, content_type)) tuples for ``files=``. httpx
    generates the boundary and Content-Length, so the recorded multipart
    Content-Type header is dropped from the descriptor (KTD7).
    """

    data_fields: list
    file_parts: list


@dataclass(repr=False)
class PlantedRequest:
    """One request to send: a fresh tracer at exactly one site, originals else."""

    entry_id: str
    variant: str
    method: str
    url: str
    headers: list
    body: object  # RawBody | MultipartBody | None
    path_id: str
    original_value: object

    def __repr__(self) -> str:
        return (
            f"PlantedRequest(entry_id={self.entry_id!r}, variant={self.variant!r}, "
            f"method={self.method!r}, url={sanitize_url(self.url)!r}, "
            f"headers={mask_headers(self.headers)!r}, "
            f"body={'<present>' if self.body is not None else None}, "
            f"path_id={self.path_id!r}, "
            f"original_value={_masked_original(self.original_value)!r})"
        )


@dataclass(repr=False)
class Attribution:
    """Maps a planted (entry_id, variant) back to its source request and site.

    ``candidate_ids`` carries the jevsec candidate ids that claimed this site
    in OSS mode (several candidates can share one request; KTD7). Empty in
    black-box mode.
    """

    entry_id: str
    variant: str
    source_index: int
    method: str
    url: str
    path_id: str
    original_value: object
    candidate_ids: tuple = ()

    def __repr__(self) -> str:
        return (
            f"Attribution(entry_id={self.entry_id!r}, variant={self.variant!r}, "
            f"source_index={self.source_index!r}, method={self.method!r}, "
            f"url={sanitize_url(self.url)!r}, path_id={self.path_id!r}, "
            f"original_value={_masked_original(self.original_value)!r}, "
            f"candidate_ids={self.candidate_ids!r})"
        )


@dataclass(repr=False)
class SkippedRequest:
    """A recorded mutating request not fired for lack of the confirm flag."""

    method: str
    url: str
    source_index: int = -1  # index into session.recorded_requests

    def __repr__(self) -> str:
        return f"SkippedRequest(method={self.method!r}, url={sanitize_url(self.url)!r})"


@dataclass
class PlantResult:
    planted: list = field(default_factory=list)
    mapping: dict = field(default_factory=dict)
    skipped: list = field(default_factory=list)


# --- Site model ------------------------------------------------------------
#
# A site is one writable leaf. ``build(payload)`` returns the (url, headers,
# body) triple with the tracer at that leaf and every other leaf untouched.


@dataclass
class _Site:
    path_id: str
    original_value: object
    build: object  # callable(payload) -> (url, headers, body)


def _json_sites(req):
    """Walk the parsed JSON body; one site per string leaf, insertion order."""
    if req.body is None or req.body.data is None:
        return []
    if "json" not in req.body.content_type.lower():
        return []
    try:
        root = json.loads(req.body.data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return []

    sites = []

    def recurse(node, label, path):
        if isinstance(node, dict):
            for key, value in node.items():
                recurse(value, label + "." + key, path + [("key", key)])
        elif isinstance(node, list):
            for index, value in enumerate(node):
                recurse(value, label + "[%d]" % index, path + [("idx", index)])
        elif isinstance(node, str):
            frozen = tuple(path)
            original = node

            def build(payload, frozen=frozen):
                mutated = _json_set(root, frozen, payload)
                serialized = json.dumps(
                    mutated, separators=(",", ":"), ensure_ascii=False
                ).encode("utf-8")
                return req.url, _base_headers(req), RawBody(serialized)

            sites.append(_Site("json:" + label, original, build))

    recurse(root, "$", [])
    return sites


def _json_set(node, path, value):
    """Return a copy of ``node`` with the leaf at ``path`` set to ``value``."""
    if not path:
        return value
    kind, key = path[0]
    if kind == "key":
        clone = dict(node)
        clone[key] = _json_set(node[key], path[1:], value)
        return clone
    clone = list(node)
    clone[key] = _json_set(node[key], path[1:], value)
    return clone


def _form_sites(req):
    """Walk an urlencoded body; preserve order and duplicate keys (parse_qsl)."""
    if req.body is None or req.body.data is None:
        return []
    if "application/x-www-form-urlencoded" not in req.body.content_type.lower():
        return []
    pairs = parse_qsl(req.body.data.decode("utf-8"), keep_blank_values=True)

    def rebuild(index, payload):
        mutated = list(pairs)
        key = mutated[index][0]
        mutated[index] = (key, payload)
        return req.url, _base_headers(req), RawBody(urlencode(mutated).encode("utf-8"))

    return _pair_sites(pairs, "form", rebuild)


def _query_sites(req):
    """Walk the query string; preserve order and duplicate keys (parse_qsl)."""
    split = urlsplit(req.url)
    if not split.query:
        return []
    pairs = parse_qsl(split.query, keep_blank_values=True)

    def rebuild(index, payload):
        mutated = list(pairs)
        key = mutated[index][0]
        mutated[index] = (key, payload)
        new_url = urlunsplit(
            (split.scheme, split.netloc, split.path, urlencode(mutated), split.fragment)
        )
        return new_url, _base_headers(req), _base_body(req)

    return _pair_sites(pairs, "query", rebuild)


def _pair_sites(pairs, prefix, rebuild):
    """Shared (key, value) list walker for queries and urlencoded forms.

    A key seen once keeps a bare id (``query:q``); a repeated key is indexed by
    occurrence (``query:a[0]``, ``query:a[1]``) so duplicates stay distinct.
    """
    counts = {}
    for key, _ in pairs:
        counts[key] = counts.get(key, 0) + 1
    occurrence = {}
    sites = []
    for index, (key, value) in enumerate(pairs):
        seen = occurrence.get(key, 0)
        occurrence[key] = seen + 1
        if counts[key] == 1:
            path_id = "%s:%s" % (prefix, key)
        else:
            path_id = "%s:%s[%d]" % (prefix, key, seen)

        def build(payload, index=index):
            return rebuild(index, payload)

        sites.append(_Site(path_id, value, build))
    return sites


def _path_sites(req):
    """Walk the path; one site per non-empty segment, re-quoting only that one."""
    split = urlsplit(req.url)
    segments = split.path.split("/")
    sites = []
    for index, segment in enumerate(segments):
        if segment == "":
            continue
        label = "/".join(
            "{seg%d}" % i if i == index else seg for i, seg in enumerate(segments)
        )

        def build(payload, index=index):
            mutated = list(segments)
            mutated[index] = quote(payload, safe="")
            new_url = urlunsplit(
                (split.scheme, split.netloc, "/".join(mutated), split.query, split.fragment)
            )
            return new_url, _base_headers(req), _base_body(req)

        sites.append(_Site("path:" + label, segment, build))
    return sites


def _header_sites(req):
    """Walk custom (non-standard) headers; each value is a site.

    Index into the base header list (the one ``build`` rewrites), not
    ``req.headers``: a multipart request drops its Content-Type from the base
    list, so enumerating the raw headers would misalign the write position.
    """
    sites = []
    base = _base_headers(req)
    for position, (name, value) in enumerate(base):
        if name.lower() in _STANDARD_HEADERS:
            continue

        def build(payload, position=position):
            headers = _base_headers(req)
            headers[position] = (headers[position][0], payload)
            return req.url, headers, _base_body(req)

        sites.append(_Site("header:" + name, value, build))
    return sites


def _multipart_sites(req):
    """Walk multipart parts; each part value and each present filename is a site."""
    if req.body is None or req.body.parts is None:
        return []
    parts = req.body.parts
    sites = []
    for index, part in enumerate(parts):
        label = part.name if part.name is not None else "[%d]" % index

        def build_value(payload, index=index):
            body = _multipart_body(parts, (index, "value", payload))
            return req.url, _base_headers(req), body

        sites.append(
            _Site("multipart:%s.value" % label, part.data, build_value)
        )
        if part.filename is not None:

            def build_filename(payload, index=index):
                body = _multipart_body(parts, (index, "filename", payload))
                return req.url, _base_headers(req), body

            sites.append(
                _Site("multipart:%s.filename" % label, part.filename, build_filename)
            )
    return sites


def _multipart_body(parts, inject):
    """Build a MultipartBody, optionally injecting ``(index, which, payload)``.

    ``which`` is ``value`` (replace the part's content) or ``filename``. A part
    with no filename is a text field for ``data=``; one with a filename is a
    file part for ``files=``. Per-part filename and content type are preserved.
    """
    inject_index, inject_which, inject_payload = inject if inject else (None, None, None)
    data_fields = []
    file_parts = []
    for index, part in enumerate(parts):
        filename = part.filename
        content = part.data
        if index == inject_index:
            if inject_which == "filename":
                filename = inject_payload
            else:
                content = inject_payload.encode("utf-8")
        name = part.name if part.name is not None else ""
        if filename is None:
            data_fields.append((name, content.decode("utf-8")))
        else:
            file_parts.append((name, (filename, content, part.content_type)))
    return MultipartBody(data_fields, file_parts)


def _base_headers(req):
    """The request's headers as an ordered list, dropping a multipart
    Content-Type so the sender lets httpx own the boundary (KTD7)."""
    multipart = req.body is not None and req.body.parts is not None
    headers = []
    for name, value in req.headers:
        if multipart and name.lower() == "content-type":
            continue
        headers.append((name, value))
    return headers


def _base_body(req):
    """The unmodified body descriptor, for injections that land elsewhere."""
    if req.body is None:
        return None
    if req.body.parts is not None:
        return _multipart_body(req.body.parts, None)
    return RawBody(req.body.data)


def _sites_for(req):
    """All writable leaves of one request, in a stable component order."""
    return (
        _query_sites(req)
        + _path_sites(req)
        + _header_sites(req)
        + _json_sites(req)
        + _form_sites(req)
        + _multipart_sites(req)
    )


def plant(session, key, run_id, *, raw_only=False, confirm_mutating=False,
          targets=None):
    """Plant a fresh tracer into every observed writable input (R7, R11).

    Returns a PlantResult carrying the planted descriptors (one per site per
    enabled variant), the (entry_id, variant) -> source attribution mapping
    (R7, R19), and the recorded mutating requests skipped for lack of
    ``confirm_mutating`` (R26, KTD15). Only observed inputs are planted; nothing
    is invented. Tracer data is inert (R15); destructive effects from replaying
    recorded mutating requests are governed by the confirm gate.

    ``targets`` restricts planting to OSS mode (SPEC-OSS step 3): a mapping of
    recorded-request index to claims, each claim a ``(candidate_id, path_id)``
    pair where a None path_id claims every leaf and a named path_id claims
    just that one. When supplied, only targeted requests plant, and each site
    co-attributes to the candidates claiming it.
    """
    result = PlantResult()
    counter = 0

    for source_index, req in enumerate(session.recorded_requests):
        if targets is not None and source_index not in targets:
            continue
        if req.method.upper() not in _SAFE_METHODS and not confirm_mutating:
            result.skipped.append(
                SkippedRequest(req.method, req.url, source_index)
            )
            continue

        for site in _sites_for(req):
            if targets is not None:
                claimants = tuple(
                    cid for cid, pid in targets[source_index]
                    if pid is None or pid == site.path_id
                )
                if not claimants:
                    continue
            else:
                claimants = ()
            entry_id = format(counter, "x")
            counter += 1
            nonce = marker.new_nonce()
            for record in marker.build_variants(
                key, run_id, entry_id, nonce, raw_only=raw_only
            ):
                variant = record["variant"]
                url, headers, body = site.build(record["payload"])
                result.planted.append(
                    PlantedRequest(
                        entry_id=entry_id,
                        variant=variant,
                        method=req.method,
                        url=url,
                        headers=headers,
                        body=body,
                        path_id=site.path_id,
                        original_value=site.original_value,
                    )
                )
                result.mapping[(entry_id, variant)] = Attribution(
                    entry_id=entry_id,
                    variant=variant,
                    source_index=source_index,
                    method=req.method,
                    url=req.url,
                    path_id=site.path_id,
                    original_value=site.original_value,
                    candidate_ids=claimants,
                )

    return result
