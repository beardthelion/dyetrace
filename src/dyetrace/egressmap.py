"""Egress-mode tool catalog, guess-free mapper and operator binds (KTD4, R2).

A candidate names a function and its parameters; an MCP server exposes tools
with string-typed properties. This module joins the two without guessing:

* ``build_catalog`` turns a ``tools/list`` result into a ``ToolCatalog``.
* ``map_egress`` auto-maps a candidate only when exactly one tool name equals
  the candidate symbol AND exactly one string-typed property of that tool
  matches a candidate parameter name. A ``tool_name`` / ``arg_name`` hint from
  the contract never bypasses this: it must still resolve in the live catalog.
  Everything else is ``unmapable`` with one distinct reason code
  (``no_tool_match``, ``ambiguous_tool``, ``no_param_match``,
  ``ambiguous_param``, ``no_param_names``, ``hint_not_in_catalog``,
  ``required_args_unsatisfied``); the operator supplies a bind.
* Operator binds (candidate id -> tool, argument, optional static
  ``arguments``) are the normal path and override the auto map. A bind that
  names an unknown candidate, a tool or argument absent from the live catalog,
  or a non-string argument raises ``EgressBindsError`` before anything is sent.
* Mapped candidates are grouped into ``SendPlan`` records keyed by
  (tool, argument, static arguments); candidates sharing a key share one send
  and are co-attributed (KTD10).

Property types count as string only when the schema type is exactly
``"string"``. Matching is exact and case-sensitive; a tool whose name merely
contains the symbol never matches. All failures are fail-closed.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

from .egresscand import EgressCandidate

__all__ = [
    "EgressCatalogError",
    "EgressBindsError",
    "ToolInfo",
    "ToolCatalog",
    "EgressBind",
    "MappedEgress",
    "UnmappedEgress",
    "SendPlan",
    "EgressMapResult",
    "UNMAPABLE_REASONS",
    "build_catalog",
    "load_egress_binds",
    "map_egress",
]

_MAX_BINDS_BYTES = 4 * 1024 * 1024
_MAX_TOOLS = 10_000
_MAX_DETAIL = 256

UNMAPABLE_REASONS = (
    "no_tool_match",
    "ambiguous_tool",
    "no_param_match",
    "ambiguous_param",
    "no_param_names",
    "hint_not_in_catalog",
    "required_args_unsatisfied",
)


class EgressCatalogError(Exception):
    """A tools/list result was malformed; the run must stop."""


class EgressBindsError(Exception):
    """A binds file failed load or merge; the run must stop."""


@dataclass(frozen=True)
class ToolInfo:
    name: str
    properties: tuple[str, ...]
    string_properties: tuple[str, ...]
    required: tuple[str, ...]


@dataclass(frozen=True)
class ToolCatalog:
    tools: tuple[ToolInfo, ...]
    _by_name: dict = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        index: dict = {}
        for t in self.tools:
            index.setdefault(t.name, []).append(t)
        object.__setattr__(self, "_by_name", index)

    def named(self, name: str) -> list[ToolInfo]:
        return list(self._by_name.get(name, ()))


@dataclass(frozen=True)
class EgressBind:
    candidate_id: str
    tool: str
    argument: str
    arguments: dict = field(default_factory=dict)
    # Template bind: argument is the recorded leaf path of the {url}
    # placeholder inside arguments (for example action.endpoint), not a
    # top-level property name.
    template: bool = False


_URL_PLACEHOLDER = "{url}"


def _placeholder_paths(obj, path=""):
    """Dotted paths of every string leaf containing the {url} placeholder."""
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += _placeholder_paths(v, path + "." + k if path else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out += _placeholder_paths(v, f"{path}[{i}]")
    elif isinstance(obj, str) and _URL_PLACEHOLDER in obj:
        out.append(path)
    return out


@dataclass
class MappedEgress:
    candidate: EgressCandidate
    tool: str
    argument: str
    arguments: dict
    via: str  # "auto", "hint" or "bind"
    input_index: int


@dataclass
class UnmappedEgress:
    candidate: EgressCandidate
    reason: str  # one of UNMAPABLE_REASONS
    input_index: int
    detail: str = ""  # bounded, printable; e.g. the missing property names


@dataclass
class SendPlan:
    tool: str
    argument: str
    arguments: dict
    candidate_ids: tuple[str, ...]


@dataclass
class EgressMapResult:
    mapped: list[MappedEgress] = field(default_factory=list)
    unmapable: list[UnmappedEgress] = field(default_factory=list)
    plans: list[SendPlan] = field(default_factory=list)


# --- catalog ---------------------------------------------------------------


def build_catalog(tools) -> ToolCatalog:
    """Build a catalog from ``tools/list`` entries (dicts with ``name`` and an
    optional ``inputSchema``). Duplicate names are kept so the mapper can call
    them ambiguous."""
    if not isinstance(tools, (list, tuple)):
        raise EgressCatalogError("tools list must be an array")
    if len(tools) > _MAX_TOOLS:
        raise EgressCatalogError(f"too many tools (max {_MAX_TOOLS})")
    out = []
    for i, raw in enumerate(tools):
        where = f"tools[{i}]"
        if not isinstance(raw, dict):
            raise EgressCatalogError(f"{where} must be an object")
        name = raw.get("name")
        if not isinstance(name, str) or not name:
            raise EgressCatalogError(f"{where}.name must be a non-empty string")
        schema = raw.get("inputSchema")
        if schema is None:
            schema = {}
        if not isinstance(schema, dict):
            raise EgressCatalogError(f"{where}.inputSchema must be an object")
        props = schema.get("properties")
        if props is None:
            props = {}
        if not isinstance(props, dict):
            raise EgressCatalogError(f"{where}.inputSchema.properties must be an object")
        required = schema.get("required")
        if required is None:
            required = []
        if not isinstance(required, list) or not all(
                isinstance(r, str) for r in required):
            raise EgressCatalogError(
                f"{where}.inputSchema.required must be an array of strings")
        strings = tuple(
            p for p, spec in props.items()
            if isinstance(spec, dict) and spec.get("type") == "string")
        out.append(ToolInfo(name, tuple(props), strings, tuple(required)))
    return ToolCatalog(tuple(out))


# --- binds -----------------------------------------------------------------


def load_egress_binds(path) -> dict:
    """Read a binds JSON file into candidate_id -> EgressBind (fail-closed)."""
    p = Path(path)
    try:
        if p.stat().st_size > _MAX_BINDS_BYTES:
            raise EgressBindsError(f"binds file exceeds {_MAX_BINDS_BYTES} bytes")
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise EgressBindsError(f"cannot read binds file: {p}") from exc
    except UnicodeDecodeError as exc:
        raise EgressBindsError(f"binds file is not UTF-8: {p}") from exc
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise EgressBindsError(f"binds file is not valid JSON: {p}") from exc
    if not isinstance(obj, dict):
        raise EgressBindsError("binds file must be a JSON object")
    out = {}
    for cid, raw in obj.items():
        if not cid:
            raise EgressBindsError("bind keys must be non-empty candidate ids")
        if not isinstance(raw, dict):
            raise EgressBindsError(f"bind for {cid} must be an object")
        unknown = set(raw) - {"tool", "argument", "arguments"}
        if unknown:
            raise EgressBindsError(f"bind for {cid}: unknown keys {sorted(unknown)}")
        tool_v = raw.get("tool")
        if not isinstance(tool_v, str) or not tool_v:
            raise EgressBindsError(f"bind for {cid}: tool must be a non-empty string")
        static = raw.get("arguments", {})
        if not isinstance(static, dict):
            raise EgressBindsError(f"bind for {cid}: arguments must be an object")
        paths = _placeholder_paths(static)
        arg = raw.get("argument")
        if arg is None:
            if len(paths) != 1:
                raise EgressBindsError(
                    f"bind for {cid}: without an argument, arguments must "
                    "contain exactly one {url} placeholder")
            template = True
            arg = paths[0]
        else:
            if not isinstance(arg, str) or not arg:
                raise EgressBindsError(
                    f"bind for {cid}: argument must be a non-empty string")
            if paths:
                raise EgressBindsError(
                    f"bind for {cid}: {{url}} placeholder is not allowed "
                    "when an argument is given")
            if arg in static:
                raise EgressBindsError(
                    f"bind for {cid}: arguments must not contain the argument key")
            template = False
        out[cid] = EgressBind(cid, tool_v, arg, static, template)
    return out


def _check_bind(bind: EgressBind, catalog: ToolCatalog) -> None:
    tools = catalog.named(bind.tool)
    if not tools:
        raise EgressBindsError(
            f"bind for {bind.candidate_id}: tool not in live catalog")
    if len(tools) > 1:
        raise EgressBindsError(
            f"bind for {bind.candidate_id}: tool name is ambiguous in live catalog")
    tool = tools[0]
    if bind.template:
        return  # a nested leaf; union-typed args cannot be shape-checked here
    if bind.argument not in tool.properties:
        raise EgressBindsError(
            f"bind for {bind.candidate_id}: argument not in tool's properties")
    if bind.argument not in tool.string_properties:
        raise EgressBindsError(
            f"bind for {bind.candidate_id}: argument is not string-typed")


# --- mapper ----------------------------------------------------------------


def _detail(text: str) -> str:
    clean = "".join(c if c.isprintable() else "?" for c in text)
    return clean[:_MAX_DETAIL]


def _auto(cand: EgressCandidate, catalog: ToolCatalog):
    """Resolve (tool, argument, via) or (reason, None, None)."""
    hinted = cand.tool_name is not None or cand.arg_name is not None
    name = cand.tool_name if cand.tool_name is not None else cand.symbol
    tools = catalog.named(name) if name else []
    if cand.tool_name is not None and len(tools) == 0:
        return "hint_not_in_catalog", None, None
    if not tools:
        return "no_tool_match", None, None
    if len(tools) > 1:
        return "ambiguous_tool", None, None
    tool = tools[0]
    if cand.arg_name is not None:
        if cand.arg_name not in tool.string_properties:
            return "hint_not_in_catalog", None, None
        return tool, cand.arg_name, "hint"
    if not cand.param_names:
        return "no_param_names", None, None
    wanted = set(cand.param_names)
    matches = [p for p in tool.string_properties if p in wanted]
    if not matches:
        return "no_param_match", None, None
    if len(matches) > 1:
        return "ambiguous_param", None, None
    return tool, matches[0], "hint" if hinted else "auto"


def map_egress(candidates, catalog: ToolCatalog, binds=None) -> EgressMapResult:
    """Map each candidate to a (tool, argument) or record why it cannot be."""
    binds = binds or {}
    known = {c.id for c in candidates}
    for cid in binds:
        if cid not in known:
            raise EgressBindsError(f"bind for unknown candidate id: {cid}")
    for bind in binds.values():
        _check_bind(bind, catalog)

    result = EgressMapResult()
    for pos, cand in enumerate(candidates):
        bind = binds.get(cand.id)
        if bind is not None:
            tool = catalog.named(bind.tool)[0]
            argument, static, via = bind.argument, bind.arguments, "bind"
        else:
            tool, argument, via = _auto(cand, catalog)
            static = {}
            if argument is None:
                result.unmapable.append(UnmappedEgress(cand, tool, pos))
                continue
        missing = [r for r in tool.required
                   if r != argument and r not in static]
        if missing:
            result.unmapable.append(UnmappedEgress(
                cand, "required_args_unsatisfied", pos,
                _detail(", ".join(missing))))
            continue
        result.mapped.append(MappedEgress(
            cand, tool.name, argument, json.loads(json.dumps(static)), via, pos))

    groups: dict = {}
    ids: dict = {}
    for m in result.mapped:
        key = (m.tool, m.argument, json.dumps(m.arguments, sort_keys=True))
        if key not in groups:
            groups[key] = SendPlan(m.tool, m.argument,
                                   json.loads(json.dumps(m.arguments)), ())
        ids.setdefault(key, []).append(m.candidate.id)
    for key, plan in groups.items():
        plan.candidate_ids = tuple(ids[key])
    result.plans = list(groups.values())
    return result
