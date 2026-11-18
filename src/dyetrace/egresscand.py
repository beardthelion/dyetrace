"""Egress-mode candidate contract and tool adapters (KTD4, R1).

Loads the normalized ``egress-candidates`` JSON contract (``version: 1``) into
typed ``EgressCandidate`` records for the egress mapper and verdict layers.
Like ``candidates.py`` it binds to a documented field set, not to any tool's
internals, and ignores unknown keys, so a forward-compatible file still loads.
Unknown keys never reach a record: no field can carry a command or argument
vector, so nothing a candidate file says can influence what gets spawned
(asserted again at the stdio adapter).

Two adapters convert saved tool output into the same contract:

* ``ssrf-guard-audit`` (``scan --json``): findings whose resolution is
  ``deterministic`` or ``unrecognized_guard``. The ``site`` label (a
  declaration line truncated near 80 characters) yields the symbol and
  parameter names; a cut parameter list sets ``params_truncated`` and keeps
  only complete names. Banner text before the JSON is tolerated (the real tool
  prints its semgrep banner on stderr, so a combined capture carries it).
* ``egress-plane`` (``scan --format json``): sites whose destination kind is
  ``param``, ``env``, ``expr`` or ``template``. Every one is a lead and none
  has parameter names (a ``param:N:fn`` destination gives only a position).

Adapters read saved files only. They never run the tools and never invent a
tool or argument name; the ``tool_name`` / ``arg_name`` hints exist only in
the normalized contract and are checked against the live catalog by the mapper.

Fail-closed on any violation, matching ``candidates.py``: caps of 16 MiB and
10,000 candidates, duplicate ids rejected, every string length-bounded.
"""

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "EgressCandidatesError",
    "EgressSink",
    "EgressCandidate",
    "EgressCandidateSet",
    "FORMATS",
    "load_egress_candidates",
    "to_contract",
]

_VERSION = 1
FORMATS = ("normalized", "ssrf-guard-audit", "egress-plane")

# Same caps as candidates.py.
_MAX_FILE_BYTES = 16 * 1024 * 1024
_MAX_CANDIDATES = 10_000
# String and list bounds for every field of the contract.
_MAX_ID = 256
_MAX_STR = 1024
_MAX_LIST = 1000

_SSRF_SCHEMA = "ssrf-guard-audit/v1"
_SSRF_KEEP = ("deterministic", "unrecognized_guard")
_EP_SCHEMA = 1
_EP_KEEP = ("param", "env", "expr", "template")
# Bounded scan for the JSON start when text precedes it.
_MAX_JSON_STARTS = 100


class EgressCandidatesError(Exception):
    """Every egress-candidate loading failure (fail-closed family)."""


@dataclass(frozen=True)
class EgressSink:
    """One sink location of a candidate."""

    file: str
    line: int


@dataclass(frozen=True)
class EgressCandidate:
    """One static egress candidate, reduced to the fields the prover consumes."""

    id: str
    source_tool: str
    source_version: str
    file: str
    start_line: int
    end_line: int
    symbol: str | None
    site_label: str | None
    param_names: tuple[str, ...]
    params_truncated: bool
    sinks: tuple[EgressSink, ...]
    guard_classes: tuple[str, ...]
    destination_kind: str | None
    lead: bool
    tool_name: str | None
    arg_name: str | None


@dataclass
class EgressCandidateSet:
    """The loaded candidates plus the source's coverage verdict (limits block)."""

    candidates: list[EgressCandidate]
    coverage_verdict: str | None


# --- field helpers --------------------------------------------------------


def _str(obj: dict, key: str, where: str, limit: int = _MAX_STR) -> str:
    v = obj.get(key)
    if not isinstance(v, str):
        raise EgressCandidatesError(f"{where}.{key} must be a string")
    if len(v) > limit:
        raise EgressCandidatesError(f"{where}.{key} too long (max {limit})")
    return v


def _opt_str(obj: dict, key: str, where: str, limit: int = _MAX_STR) -> str | None:
    if obj.get(key) is None:
        return None
    return _str(obj, key, where, limit)


def _int(obj: dict, key: str, where: str) -> int:
    v = obj.get(key)
    if not isinstance(v, int) or isinstance(v, bool):
        raise EgressCandidatesError(f"{where}.{key} must be an int")
    return v


def _obj(v: object, where: str) -> dict:
    if not isinstance(v, dict):
        raise EgressCandidatesError(f"{where} must be an object")
    return v


def _arr(obj: dict, key: str, where: str) -> list:
    v = obj.get(key)
    if not isinstance(v, list):
        raise EgressCandidatesError(f"{where}{key} must be an array")
    return v


def _str_list(obj: dict, key: str, where: str, limit: int) -> tuple[str, ...]:
    if obj.get(key) is None:
        return ()
    items = _arr(obj, key, f"{where}.")
    if len(items) > _MAX_LIST:
        raise EgressCandidatesError(f"{where}.{key} too long (max {_MAX_LIST})")
    out = []
    for i, s in enumerate(items):
        if not isinstance(s, str):
            raise EgressCandidatesError(f"{where}.{key}[{i}] must be a string")
        if len(s) > limit:
            raise EgressCandidatesError(f"{where}.{key}[{i}] too long (max {limit})")
        out.append(s)
    return tuple(out)


# --- normalized contract --------------------------------------------------


def _candidate(raw: object, index: int) -> EgressCandidate:
    where = f"candidates[{index}]"
    raw = _obj(raw, where)

    sinks_raw = raw.get("sinks")
    sinks: list[EgressSink] = []
    if sinks_raw is not None:
        if not isinstance(sinks_raw, list):
            raise EgressCandidatesError(f"{where}.sinks must be an array")
        if len(sinks_raw) > _MAX_LIST:
            raise EgressCandidatesError(f"{where}.sinks too long (max {_MAX_LIST})")
        for j, s in enumerate(sinks_raw):
            sw = f"{where}.sinks[{j}]"
            s = _obj(s, sw)
            sinks.append(EgressSink(_str(s, "file", sw), _int(s, "line", sw)))

    lead = raw.get("lead", False)
    if not isinstance(lead, bool):
        raise EgressCandidatesError(f"{where}.lead must be a bool")
    truncated = raw.get("params_truncated", False)
    if not isinstance(truncated, bool):
        raise EgressCandidatesError(f"{where}.params_truncated must be a bool")

    return EgressCandidate(
        id=_str(raw, "id", where, _MAX_ID),
        source_tool=_str(raw, "source_tool", where, _MAX_ID),
        source_version=_str(raw, "source_version", where, _MAX_ID),
        file=_str(raw, "file", where),
        start_line=_int(raw, "start_line", where),
        end_line=_int(raw, "end_line", where),
        symbol=_opt_str(raw, "symbol", where, _MAX_ID),
        site_label=_opt_str(raw, "site_label", where),
        param_names=_str_list(raw, "param_names", where, _MAX_ID),
        params_truncated=truncated,
        sinks=tuple(sinks),
        guard_classes=_str_list(raw, "guard_classes", where, _MAX_ID),
        destination_kind=_opt_str(raw, "destination_kind", where, _MAX_ID),
        lead=lead,
        tool_name=_opt_str(raw, "tool_name", where, _MAX_ID),
        arg_name=_opt_str(raw, "arg_name", where, _MAX_ID),
    )


def _parse_contract(obj: object) -> EgressCandidateSet:
    """Validate a contract dict (hand-written or adapter-built) into records."""
    if not isinstance(obj, dict):
        raise EgressCandidatesError("candidates file must be a JSON object")
    version = obj.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version != _VERSION:
        raise EgressCandidatesError("candidates file version must be 1")
    cands = obj.get("candidates")
    if not isinstance(cands, list):
        raise EgressCandidatesError("candidates must be an array")
    if len(cands) > _MAX_CANDIDATES:
        raise EgressCandidatesError(
            f"candidates file holds {len(cands)} entries; "
            f"the cap is {_MAX_CANDIDATES}"
        )
    parsed = [_candidate(c, i) for i, c in enumerate(cands)]
    seen = set()
    for c in parsed:
        if c.id in seen:
            raise EgressCandidatesError(f"duplicate candidate id: {c.id}")
        seen.add(c.id)
    verdict = _opt_str(obj, "coverage_verdict", "candidates file", _MAX_ID)
    return EgressCandidateSet(candidates=parsed, coverage_verdict=verdict)


def to_contract(cs: EgressCandidateSet) -> dict:
    """Render a candidate set as a normalized contract dict (round-trips)."""
    out: dict = {
        "version": _VERSION,
        "candidates": [
            {
                "id": c.id,
                "source_tool": c.source_tool,
                "source_version": c.source_version,
                "file": c.file,
                "start_line": c.start_line,
                "end_line": c.end_line,
                "symbol": c.symbol,
                "site_label": c.site_label,
                "param_names": list(c.param_names),
                "params_truncated": c.params_truncated,
                "sinks": [{"file": s.file, "line": s.line} for s in c.sinks],
                "guard_classes": list(c.guard_classes),
                "destination_kind": c.destination_kind,
                "lead": c.lead,
                "tool_name": c.tool_name,
                "arg_name": c.arg_name,
            }
            for c in cs.candidates
        ],
    }
    if cs.coverage_verdict is not None:
        out["coverage_verdict"] = cs.coverage_verdict
    return out


# --- ssrf-guard-audit adapter ---------------------------------------------

_NAME_BEFORE_PAREN = re.compile(r"([A-Za-z_$][\w$]*)\s*\(")
_PARAM_NAME = re.compile(r"[*\s]*([A-Za-z_$][\w$]*)")
_OPEN = "([{<"
_CLOSE = ")]}>"


def _parse_site_label(label: str) -> tuple[str | None, tuple[str, ...], bool]:
    """Return (symbol, complete parameter names, truncated) from a site label.

    The label is a declaration line cut near 80 characters. When the closing
    parenthesis of the parameter list is missing the list was cut, so the last
    segment (possibly partial) is dropped and only complete names are kept.
    """
    m = _NAME_BEFORE_PAREN.search(label)
    if m is None:
        return None, (), False
    symbol = m.group(1)
    segments: list[str] = []
    depth = 0
    cur: list[str] = []
    closed = False
    prev = ""
    for ch in label[m.end():]:
        if ch == ">" and prev in "-=":
            pass  # arrow, not a bracket
        elif ch in _OPEN:
            depth += 1
        elif ch in _CLOSE:
            if depth == 0:
                closed = True
                break
            depth -= 1
        elif ch == "," and depth == 0:
            segments.append("".join(cur))
            cur = []
            prev = ch
            continue
        cur.append(ch)
        prev = ch
    if closed:
        segments.append("".join(cur))
    # else: the pending segment in `cur` is partial and is never added
    names = []
    for seg in segments:
        pm = _PARAM_NAME.match(seg)
        if pm and pm.group(1) not in ("self", "cls"):
            names.append(pm.group(1))
    return symbol, tuple(names), not closed


def _find_json_object(text: str, what: str) -> dict:
    """Decode the first JSON object in ``text``, skipping any text before it."""
    dec = json.JSONDecoder()
    starts = 0
    pos = 0
    while pos <= len(text) and starts < _MAX_JSON_STARTS:
        if text.startswith("{", pos):
            starts += 1
            try:
                obj, _ = dec.raw_decode(text, pos)
            except (json.JSONDecodeError, RecursionError):
                obj = None
            if isinstance(obj, dict):
                return obj
        nl = text.find("\n", pos)
        if nl < 0:
            break
        pos = nl + 1
    raise EgressCandidatesError(f"{what} holds no JSON object")


def _hash_id(prefix: str, *parts: object) -> str:
    h = hashlib.sha256(":".join(str(p) for p in parts).encode("utf-8")).hexdigest()
    return f"{prefix}-{h[:16]}"


def _from_ssrf_guard_audit(text: str) -> dict:
    root = _find_json_object(text, "ssrf-guard-audit output")
    if root.get("schema_version") != _SSRF_SCHEMA:
        raise EgressCandidatesError(
            f"ssrf-guard-audit schema_version must be {_SSRF_SCHEMA}"
        )
    findings = _arr(root, "findings", "")
    version = _str(root, "ruleset_version", "ssrf-guard-audit", _MAX_ID)
    cov = root.get("coverage")
    verdict = cov.get("verdict") if isinstance(cov, dict) else None
    if verdict is not None and not isinstance(verdict, str):
        raise EgressCandidatesError("ssrf-guard-audit coverage.verdict must be a string")

    cands = []
    for i, f in enumerate(findings):
        where = f"findings[{i}]"
        f = _obj(f, where)
        if f.get("resolution") not in _SSRF_KEEP:
            continue
        path = _str(f, "path", where)
        start = _int(f, "start_line", where)
        end = _int(f, "end_line", where)
        label = _opt_str(f, "site", where)
        symbol, params, truncated = (
            _parse_site_label(label) if label is not None else (None, (), False)
        )
        sinks_raw = f.get("sinks")
        if sinks_raw is None:
            sinks_raw = []
        if not isinstance(sinks_raw, list):
            raise EgressCandidatesError(f"{where}.sinks must be an array")
        sinks = []
        for j, s in enumerate(sinks_raw):
            sw = f"{where}.sinks[{j}]"
            s = _obj(s, sw)
            sinks.append({"file": _str(s, "path", sw), "line": _int(s, "line", sw)})
        cands.append(
            {
                "id": _hash_id("sga", path, start, end),
                "source_tool": "ssrf-guard-audit",
                "source_version": version,
                "file": path,
                "start_line": start,
                "end_line": end,
                "symbol": symbol,
                "site_label": label,
                "param_names": list(params),
                "params_truncated": truncated,
                "sinks": sinks,
                "guard_classes": f.get("classes") if f.get("classes") is not None else [],
                "destination_kind": None,
                "lead": False,
            }
        )
    out = {"version": _VERSION, "candidates": cands}
    if verdict is not None:
        out["coverage_verdict"] = verdict
    return out


# --- egress-plane adapter -------------------------------------------------


def _from_egress_plane(text: str) -> dict:
    try:
        root = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise EgressCandidatesError("egress-plane output is not valid JSON") from exc
    if not isinstance(root, dict):
        raise EgressCandidatesError("egress-plane output must be a JSON object")
    sv = root.get("schema_version")
    if not isinstance(sv, int) or isinstance(sv, bool) or sv != _EP_SCHEMA:
        raise EgressCandidatesError("egress-plane schema_version must be 1")
    sites = _arr(root, "sites", "")
    tool = root.get("tool")
    version = _str(tool if isinstance(tool, dict) else {}, "version", "egress-plane.tool", _MAX_ID)
    comp = root.get("completeness")
    state = comp.get("state") if isinstance(comp, dict) else None
    if state is not None and not isinstance(state, str):
        raise EgressCandidatesError("egress-plane completeness.state must be a string")

    cands = []
    for i, s in enumerate(sites):
        where = f"sites[{i}]"
        s = _obj(s, where)
        dest = _obj(s.get("destination"), f"{where}.destination")
        kind = _str(dest, "kind", f"{where}.destination", _MAX_ID)
        if kind not in _EP_KEEP:
            continue
        sid = _str(s, "id", where, _MAX_ID - 3)
        file = _str(s, "file", where)
        loc = _obj(s.get("location"), f"{where}.location")
        line = _int(loc, "line", f"{where}.location")
        cands.append(
            {
                "id": f"ep-{sid}",
                "source_tool": "egress-plane",
                "source_version": version,
                "file": file,
                "start_line": line,
                "end_line": line,
                "symbol": _opt_str(s, "symbol", where, _MAX_ID),
                "param_names": [],
                "params_truncated": False,
                "sinks": [{"file": file, "line": line}],
                "guard_classes": [],
                "destination_kind": kind,
                "lead": True,
            }
        )
    out = {"version": _VERSION, "candidates": cands}
    if state is not None:
        out["coverage_verdict"] = state
    return out


# --- entry point ----------------------------------------------------------


def _read_text(path: Path) -> str:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            raise EgressCandidatesError(
                f"candidates file exceeds {_MAX_FILE_BYTES} bytes: {path}"
            )
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise EgressCandidatesError(f"cannot read candidates file: {path}") from exc
    except UnicodeDecodeError as exc:
        raise EgressCandidatesError(f"candidates file is not UTF-8: {path}") from exc


def load_egress_candidates(path, fmt: str = "normalized") -> EgressCandidateSet:
    """Load a saved candidates file in ``fmt`` into typed records.

    ``fmt`` is ``normalized`` (the default), ``ssrf-guard-audit`` or
    ``egress-plane``. Adapter output passes through the same validation as a
    hand-written contract. Raises EgressCandidatesError on any violation.
    """
    if fmt not in FORMATS:
        raise EgressCandidatesError(f"unknown candidates format: {fmt}")
    text = _read_text(Path(path))
    if fmt == "ssrf-guard-audit":
        obj = _from_ssrf_guard_audit(text)
    elif fmt == "egress-plane":
        obj = _from_egress_plane(text)
    else:
        try:
            obj = json.loads(text)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise EgressCandidatesError(
                f"candidates file is not valid JSON: {path}"
            ) from exc
    return _parse_contract(obj)
