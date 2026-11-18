"""OSS-mode jevsec candidate loader (SPEC-OSS pipeline step 1).

Parses a jevsec ``candidates.json`` (schema ``version: 1``) into typed
``Candidate`` records for the OSS mapper and verdict layers. The loader binds
to the normalized JSON contract, not jevsec internals: it validates a
documented field subset (candidate id, entry kind/detail/site/node name, sink
callee/class/site, rank) and ignores everything else (hops, crossings, stats,
limits), so a forward-compatible file with extra fields still loads.

Accepts a direct path to ``candidates.json``, a single jevsec run dir
containing one, or a runs root holding exactly one run dir (the pick is
stated on stderr since it is implicit). A runs root holding zero or several
run dirs fails closed; the several case prints a numbered list so the
operator can pass one explicitly rather than guessing which run was meant.

Fail-closed on any schema violation, matching ``session.py``'s discipline:
a malformed candidate file is operator error, and the caller never falls back
to spraying every recorded input on a broken input file.
"""

import json
import sys
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "CandidatesError",
    "CandidateEntry",
    "CandidateSink",
    "Candidate",
    "load_candidates",
]

# Schema version this loader consumes. Anything else fails closed.
_VERSION = 1


class CandidatesError(Exception):
    """Every candidate-loading failure (fail-closed family)."""


@dataclass
class CandidateEntry:
    """The predicted source: an entry callable plus its registration detail."""

    kind: str
    detail: str
    site_file: str
    site_line: int
    node_name: str | None


@dataclass
class CandidateSink:
    """The predicted sink: callee, class, and call site."""

    callee: str
    sink_class: str
    site_file: str
    site_line: int


@dataclass
class Candidate:
    """One jevsec candidate path, reduced to the fields dye-OSS consumes."""

    id: str
    entry: CandidateEntry
    sink: CandidateSink
    rank: int | None


def _require_str(obj: dict, key: str, where: str) -> str:
    v = obj.get(key)
    if not isinstance(v, str):
        raise CandidatesError(f"{where}.{key} must be a string")
    return v


def _require_int(obj: dict, key: str, where: str) -> int:
    v = obj.get(key)
    if not isinstance(v, int) or isinstance(v, bool):
        raise CandidatesError(f"{where}.{key} must be an int")
    return v


def _site(obj: dict, where: str) -> tuple[str, int]:
    if not isinstance(obj, dict):
        raise CandidatesError(f"{where} must be an object")
    return (
        _require_str(obj, "file", where),
        _require_int(obj, "line", where),
    )


def _candidate(raw: object, index: int) -> Candidate:
    where = f"candidates[{index}]"
    if not isinstance(raw, dict):
        raise CandidatesError(f"{where} must be an object")
    cid = _require_str(raw, "id", where)

    entry = raw.get("entry")
    if not isinstance(entry, dict):
        raise CandidatesError(f"{where}.entry must be an object")
    kind = _require_str(entry, "kind", f"{where}.entry")
    detail = _require_str(entry, "detail", f"{where}.entry")
    efile, eline = _site(entry.get("site"), f"{where}.entry.site")
    node = entry.get("node")
    node_name = node.get("name") if isinstance(node, dict) else None
    if node_name is not None and not isinstance(node_name, str):
        raise CandidatesError(f"{where}.entry.node.name must be a string")

    sink = raw.get("sink")
    if not isinstance(sink, dict):
        raise CandidatesError(f"{where}.sink must be an object")
    callee = _require_str(sink, "callee", f"{where}.sink")
    sink_class = _require_str(sink, "sinkClass", f"{where}.sink")
    sfile, sline = _site(sink.get("site"), f"{where}.sink.site")

    rank = raw.get("rank")
    if rank is not None and (not isinstance(rank, int) or isinstance(rank, bool)):
        raise CandidatesError(f"{where}.rank must be an int")

    return Candidate(
        id=cid,
        entry=CandidateEntry(
            kind=kind,
            detail=detail,
            site_file=efile,
            site_line=eline,
            node_name=node_name,
        ),
        sink=CandidateSink(
            callee=callee,
            sink_class=sink_class,
            site_file=sfile,
            site_line=sline,
        ),
        rank=rank,
    )


# Fail-closed input bounds: a candidates file is operator-supplied but
# untrusted-shaped - cap size and count so a pathological file cannot exhaust
# memory before validation (net.py's byte-cap discipline, applied here).
_MAX_FILE_BYTES = 16 * 1024 * 1024
_MAX_CANDIDATES = 10_000


def _resolve(path: Path) -> Path:
    """Map the operator's path to a concrete candidates.json, or fail closed."""
    if path.is_file():
        return path
    if path.is_dir():
        direct = path / "candidates.json"
        if direct.is_file():
            return direct
        try:
            nested = sorted(p.parent for p in path.glob("*/candidates.json"))
        except OSError as exc:
            raise CandidatesError(
                f"cannot walk candidates dir: {path}"
            ) from exc
        if len(nested) == 1:
            # A runs root holding exactly one run dir resolves to it - the
            # pick is stated on stderr since it is implicit.
            print(f"dyetrace: using run dir {nested[0]}", file=sys.stderr)
            return nested[0] / "candidates.json"
        if nested:
            listed = "\n".join(
                f"  {i}. {d}" for i, d in enumerate(nested[:10], 1)
            )
            extra = f"\n  ... and {len(nested) - 10} more" if len(nested) > 10 else ""
            raise CandidatesError(
                f"{path} is a runs root holding {len(nested)} run dirs; "
                f"pass a single run dir:\n{listed}{extra}"
            )
        raise CandidatesError(
            f"{path} contains no candidates.json; pass a candidates.json "
            "file or a single jevsec run dir containing one"
        )
    raise CandidatesError(f"cannot read candidates path: {path}")


def load_candidates(path) -> list[Candidate]:
    """Load and validate the consumed subset of a jevsec candidates.json.

    Returns the typed candidate list; an empty ``candidates`` array loads as an
    empty list (the caller decides between fallback and verdict rendering).
    Raises CandidatesError on an unreadable path or any schema violation.
    """
    resolved = _resolve(Path(path))
    try:
        if resolved.stat().st_size > _MAX_FILE_BYTES:
            raise CandidatesError(
                f"candidates file exceeds {_MAX_FILE_BYTES} bytes: {resolved}"
            )
        text = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        raise CandidatesError(f"cannot read candidates file: {resolved}") from exc
    except UnicodeDecodeError as exc:
        raise CandidatesError(
            f"candidates file is not UTF-8: {resolved}"
        ) from exc
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise CandidatesError(f"candidates file is not valid JSON: {resolved}") from exc
    if not isinstance(obj, dict):
        raise CandidatesError("candidates file must be a JSON object")
    version = obj.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version != _VERSION:
        raise CandidatesError("candidates file version must be 1")
    cands = obj.get("candidates")
    if not isinstance(cands, list):
        raise CandidatesError("candidates must be an array")
    if len(cands) > _MAX_CANDIDATES:
        raise CandidatesError(
            f"candidates file holds {len(cands)} entries; "
            f"the cap is {_MAX_CANDIDATES}"
        )
    parsed = [_candidate(c, i) for i, c in enumerate(cands)]
    seen = set()
    for c in parsed:
        if c.id in seen:
            raise CandidatesError(f"duplicate candidate id: {c.id}")
        seen.add(c.id)
    return parsed
