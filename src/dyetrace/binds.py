"""Operator binds: explicit candidate-to-request bindings (P0-1).

jevsec emits candidates whose entry kinds carry no HTTP field (exported
functions, cli-handler, consumer, module-init). Rather than guess mappings
from names - which SPEC-OSS forbids - the operator supplies a binds file:

    { "<candidate_id>": {
        "request_index": <int>,
        "path_id":  "<optional plant leaf id>",
        "predicted": "<optional surface>"
    } }

A bound candidate plants the named recorded request, restricted to the named
leaf when ``path_id`` is set. ``predicted`` names the surface a resurfacing
tracer must reach for PROVEN: ``"plant"`` (the candidate's own executed plant
response body, the default), ``"propagate:<index>"`` (the unplanted replay of
recorded request <index>, for stored-then-reflected flows), or
``"identity:<n>"`` (any observation under identity <n>).

Everything fails closed: malformed JSON, wrong shapes, unknown candidate ids,
and out-of-range request indexes stop the run before anything is sent.
"""

import json
from dataclasses import dataclass
from pathlib import Path

from .ossmap import MappedCandidate, MapResult

__all__ = ["BindsError", "OperatorBind", "load_binds", "apply_binds"]

_MAX_BINDS_BYTES = 4 * 1024 * 1024


class BindsError(Exception):
    """A binds file failed load or merge; the run must stop."""


@dataclass
class OperatorBind:
    """One operator-supplied binding for a single candidate."""

    candidate_id: str
    request_index: int
    path_id: str | None = None
    predicted: str | None = None


def _valid_predicted(value) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if value == "plant":
        return True
    head, sep, tail = value.partition(":")
    return sep and tail.isdigit() and head in ("propagate", "identity")


def load_binds(path) -> dict:
    """Read and validate a binds JSON file into candidate_id -> OperatorBind.

    Fail-closed: anything short of the documented shape raises BindsError.
    """
    p = Path(path)
    try:
        if p.stat().st_size > _MAX_BINDS_BYTES:
            raise BindsError(f"binds file exceeds {_MAX_BINDS_BYTES} bytes")
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise BindsError(f"cannot read binds file: {p}") from exc
    except UnicodeDecodeError as exc:
        raise BindsError(f"binds file is not UTF-8: {p}") from exc
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise BindsError(f"binds file is not valid JSON: {p}") from exc
    if not isinstance(obj, dict):
        raise BindsError("binds file must be a JSON object")
    out = {}
    for cid, raw in obj.items():
        if not isinstance(cid, str) or not cid:
            raise BindsError("bind keys must be non-empty candidate ids")
        if not isinstance(raw, dict):
            raise BindsError(f"bind for {cid} must be an object")
        idx = raw.get("request_index")
        if not isinstance(idx, int) or isinstance(idx, bool) or idx < 0:
            raise BindsError(f"bind for {cid}: request_index must be a "
                             "non-negative int")
        path_id = raw.get("path_id")
        if path_id is not None and not isinstance(path_id, str):
            raise BindsError(f"bind for {cid}: path_id must be a string")
        predicted = raw.get("predicted")
        if predicted is not None and not _valid_predicted(predicted):
            raise BindsError(
                f"bind for {cid}: predicted must be 'plant', "
                "'propagate:<index>', or 'identity:<n>'")
        unknown = set(raw) - {"request_index", "path_id", "predicted"}
        if unknown:
            raise BindsError(f"bind for {cid}: unknown keys {sorted(unknown)}")
        out[cid] = OperatorBind(cid, idx, path_id, predicted)
    return out


def apply_binds(map_result: MapResult, binds: dict,
                recorded_requests: list) -> MapResult:
    """Merge operator binds into the map, in place.

    A bound candidate is mapped to its named request index even when its entry
    kind has no HTTP field; a bound route candidate's bind overrides the
    detail-derived indices (explicit operator intent wins over inference).
    Never guesses: candidates without a bind keep their map or unmapable
    status untouched.
    """
    if not binds:
        return map_result
    known = {m.candidate.id for m in map_result.mapped}
    known |= {u.candidate.id for u in map_result.unmapable}
    by_id = {}
    for m in map_result.mapped:
        by_id[m.candidate.id] = ("mapped", m)
    for u in map_result.unmapable:
        by_id[u.candidate.id] = ("unmapable", u)
    for cid, bind in binds.items():
        if cid not in known:
            raise BindsError(f"bind for unknown candidate id: {cid}")
        if bind.request_index >= len(recorded_requests):
            raise BindsError(
                f"bind for {cid}: request_index {bind.request_index} "
                f"outside recorded session ({len(recorded_requests)} requests)")
        kind, entry = by_id[cid]
        # A bind's ``path:`` id carries the route template and the wildcard
        # position ("path:/api/profiles/{seg3}/open-terminal"): threading it
        # into route_patterns lets the verdict layer credit param-substituted
        # path plants for bound candidates exactly like detail-derived ones.
        patterns = list(getattr(entry, "route_patterns", []))
        if bind.path_id is not None and bind.path_id.startswith("path:"):
            template = bind.path_id[len("path:"):]
            patterns = [template] if template not in patterns else patterns
        if kind == "mapped":
            entry.request_indices = [bind.request_index]
            entry.bind = bind
            entry.route_patterns = patterns
        else:
            map_result.unmapable.remove(entry)
            map_result.mapped.append(MappedCandidate(
                entry.candidate, [bind.request_index], entry.input_index,
                bind=bind, route_patterns=patterns))
    return map_result
