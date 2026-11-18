"""OSS-mode candidate-to-request mapper (SPEC-OSS "Build notes", plan KTD2).

jevsec names an entry callable, never an individual HTTP field: its taint bar
treats every entry parameter as attacker-controlled. For ``route`` entries the
candidate's ``entry.detail`` carries ``"<verb> <literal path>"`` (TS
``app.get("/x")`` -> ``"get /x"``; py ``@app.route("/x")`` -> ``"ROUTE /x"`` or
``"GET /x"``; rs ``#[get("/x")]`` -> ``"get /x"``). The map to the recorded
session is: route detail -> recorded request(s) by method+path -> every
writable leaf of each match (plant.py already owns what a leaf is).

Nothing here guesses. A candidate that cannot be bound to concrete recorded
requests is recorded ``unmapable`` with a reason and skipped (SPEC-OSS:
"if the map cannot be made without guessing, skip that candidate").

Accepted limits: route details carry the registration-local path, so a
handler mounted under a prefix (``app.use("/api", router)`` with
``router.get("/x")``) lands ``unmapable`` even when ``/api/x`` was recorded;
joining prefixes is exactly the guessing the spec forbids. RPC-style
details (``post collections.add_group``), middleware (``use``), pattern
syntax, and multi-segment flask converters are likewise unmapable.
"""

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from urllib.parse import unquote

from .candidates import Candidate
from .masking import mask_route_detail
from .session import RecordedRequest

__all__ = [
    "MappedCandidate",
    "UnmappedCandidate",
    "MapResult",
    "map_candidates",
]

# Method-constraining verbs. "del" is the Express alias for DELETE.
_METHOD_VERBS = {
    "get": "GET",
    "post": "POST",
    "put": "PUT",
    "patch": "PATCH",
    "delete": "DELETE",
    "del": "DELETE",
    "options": "OPTIONS",
    "head": "HEAD",
}

# Registration verbs that carry no method constraint. ``handleFunc``/``handle``
# are Go stdlib/gin registrations and ``any`` is gin's .Any - all method-free,
# same as express ``route``/``all`` and flask ``@app.route``.
_GENERIC_VERBS = {"route", "all", "handlefunc", "handle", "any"}

# Characters that mark a route path as pattern syntax this mapper does not
# support; a path containing one is unmapable rather than matched loosely.
# ``{``/``}`` are NOT pattern chars: ``{name}`` segments are deliberate
# template syntax (FastAPI/OpenAPI params, and the ``{segN}`` wildcards the
# plant layer emits into ``path:`` ids) and must reach _segment_match.
_PATTERN_CHARS = frozenset("*()[]\\?|+^$")


@dataclass
class MappedCandidate:
    """A candidate bound to concrete recorded requests (its source requests).
    ``bind`` carries the operator-supplied binding when one was applied via
    binds.py (None for detail-derived mappings)."""

    candidate: Candidate
    request_indices: list[int]
    input_index: int
    bind: object | None = None
    # Route patterns that produced this mapping (direct plus prefix-joined),
    # used by the verdict layer to tell a param-substituted path plant (same
    # route template) from a route-jumping one.
    route_patterns: list = field(default_factory=list)


@dataclass
class UnmappedCandidate:
    """A candidate skipped because no guessing-free map exists."""

    candidate: Candidate
    reason: str
    input_index: int


@dataclass
class MapResult:
    mapped: list[MappedCandidate] = field(default_factory=list)
    unmapable: list[UnmappedCandidate] = field(default_factory=list)

    def plant_targets(self) -> dict:
        """The ``plant(targets=...)`` contract: request index -> claims, where
        each claim is ``(candidate_id, path_id_or_None)``. A None path_id
        claims every leaf of the request; a named path_id claims just that
        leaf (a bind-level restriction)."""
        targets = {}
        for m in self.mapped:
            path_id = m.bind.path_id if m.bind is not None else None
            for i in m.request_indices:
                targets.setdefault(i, []).append((m.candidate.id, path_id))
        return {i: tuple(claims) for i, claims in targets.items()}


def _parse_detail(detail: str):
    """Parse ``"<verb> <path>"`` -> (method-or-None, value, mode); None when not
    a route shape this mapper supports. ``mode`` is ``"path"`` for a literal
    path or ``"rpc"`` for a bare RPC-style name (``post collections.add_group``,
    the shape Koa-style routers register without a leading slash), which only
    method-constraining verbs may carry - a generic verb would bind it to any
    recorded request ending in that segment."""
    parts = detail.split(None, 1)
    if len(parts) != 2:
        return None
    verb, path = parts[0].lower(), parts[1].strip()
    if verb in _METHOD_VERBS:
        method = _METHOD_VERBS[verb]
    elif verb in _GENERIC_VERBS:
        method = None  # any method
    else:
        return None
    if not path.startswith("/"):
        if method is not None and "/" not in path and not any(
            c in _PATTERN_CHARS for c in path
        ):
            return method, path, "rpc"
        return None
    if any(c in _PATTERN_CHARS for c in path):
        return None
    return method, path, "path"


def _detail_path(detail: str) -> str:
    """The path token of a ``"<verb> <path>"`` detail, secret-segment masked so
    it can sit inside a reason string (R22). Single-token details are masked
    whole when they look like secrets."""
    return mask_route_detail(detail)


# Flask converter -> concrete-segment shape it accepts. ``<path:name>`` is a
# multi-segment converter this segment matcher cannot express, so it returns
# None from _segment_match and the route is unmapable rather than loose.
_FLASK_CONVERTERS = {
    "int": re.compile(r"\A[0-9]+\Z"),
    "float": re.compile(r"\A[0-9]+(\.[0-9]+)?\Z"),
    "uuid": re.compile(r"\A[0-9a-fA-F-]{32,36}\Z"),
}


def _last_segment(path: str) -> str:
    """The final non-empty path segment - where an RPC-style registration name
    sits in a mounted URL (``/api/collections.add_group``)."""
    segs = [s for s in path.split("/") if s]
    return segs[-1] if segs else ""


def _segment_match(route_seg: str, concrete_seg: str) -> bool:
    """One route segment against one concrete segment: literal equality, an
    express ``:name`` wildcard, or a flask ``<converter:name>``/``<name>``
    placeholder."""
    if route_seg == concrete_seg:
        return True
    if not concrete_seg:
        return False
    if len(route_seg) > 1 and route_seg.startswith(":"):
        return True
    if (len(route_seg) > 2 and route_seg.startswith("{")
            and route_seg.endswith("}")):
        return True  # {name} / {segN}: FastAPI/OpenAPI or plant-emitted param
    if len(route_seg) > 2 and route_seg.startswith("<") and route_seg.endswith(">"):
        inner = route_seg[1:-1]
        converter, sep, _name = inner.partition(":")
        conv = converter if sep else "string"  # "<name>" is flask's default
        if not conv:
            return False  # "<>" - degenerate, never matches
        pat = _FLASK_CONVERTERS.get(conv)
        return pat.match(concrete_seg) is not None if pat else conv == "string"
    return False


def _path_matches(route_path: str, concrete_path: str) -> bool:
    rsegs = route_path.split("/")
    csegs = concrete_path.split("/")
    if len(rsegs) != len(csegs):
        return False
    if "<path:" in route_path:
        return False  # multi-segment converter: honest unmapable
    return all(
        _segment_match(rs, cs) for rs, cs in zip(rsegs, csegs)
    )


def _norm_prefix(prefix: str) -> str:
    """Normalize an operator-supplied route prefix: leading slash, no
    trailing slash, so ``api``/``/api/`` both build ``/api/<route>``."""
    p = prefix.strip()
    if not p.startswith("/"):
        p = "/" + p
    return p.rstrip("/")


def map_candidates(
    candidates: list[Candidate],
    recorded_requests: list[RecordedRequest],
    *,
    route_prefixes=(),
) -> MapResult:
    """Bind each candidate's route entry to recorded requests.

    Every matching request maps (each is a concrete request that hits the
    source; multiple candidates may share one request). A candidate that maps
    to nothing is recorded in ``unmapable`` with its reason.
    """
    result = MapResult()
    reqs = [
        (req.method.upper(), urlsplit(req.url).path or "/")
        for req in recorded_requests
    ]
    for pos, cand in enumerate(candidates):
        if cand.entry.kind != "route":
            result.unmapable.append(
                UnmappedCandidate(
                    cand,
                    f"entry kind {cand.entry.kind!r} has no HTTP field",
                    pos,
                )
            )
            continue
        parsed = _parse_detail(cand.entry.detail)
        if parsed is None:
            result.unmapable.append(
                UnmappedCandidate(
                    cand,
                    f"unparseable route detail {_detail_path(cand.entry.detail)!r}",
                    pos,
                )
            )
            continue
        method, path, mode = parsed
        if mode == "rpc":
            indices = [
                i
                for i, (req_method, req_path) in enumerate(reqs)
                if req_method == method and _last_segment(req_path) == path
            ]
        else:
            # Operator-asserted mount prefixes: a handler registered as
            # "/x" but mounted under "/api" is matched at "/api/x" too.
            # Prefixes only ever join, never strip or discover.
            candidates_paths = [path]
            for prefix in route_prefixes:
                joined = _norm_prefix(prefix) + path
                if joined not in candidates_paths:
                    candidates_paths.append(joined)
            indices = [
                i
                for i, (req_method, req_path) in enumerate(reqs)
                if (method is None or req_method == method)
                and any(
                    _path_matches(p, req_path)
                    or _path_matches(p, unquote(req_path))
                    for p in candidates_paths
                )
            ]
        if indices:
            result.mapped.append(MappedCandidate(
                cand, indices, pos,
                route_patterns=(
                    candidates_paths if mode == "path" else []
                )))
        else:
            result.unmapable.append(
                UnmappedCandidate(
                    cand,
                    f"no recorded request matches {_detail_path(cand.entry.detail)!r}",
                    pos,
                )
            )
    return result
