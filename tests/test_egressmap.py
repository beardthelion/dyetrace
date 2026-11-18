"""U3: egress tool catalog, guess-free mapper, egress binds (KTD4)."""

import json

import pytest

from dyetrace import egressmap
from dyetrace.egresscand import EgressCandidate
from dyetrace.egressmap import (
    EgressBindsError,
    EgressCatalogError,
    build_catalog,
    load_egress_binds,
    map_egress,
)


def _tool(name, props=None, required=()):
    props = props if props is not None else {"url": {"type": "string"}}
    schema = {"type": "object", "properties": props}
    if required:
        schema["required"] = list(required)
    return {"name": name, "inputSchema": schema}


def _cand(cid="c1", symbol="fetch", params=("url",), truncated=False,
          lead=False, tool_name=None, arg_name=None):
    return EgressCandidate(
        id=cid, source_tool="t", source_version="1", file="a.py",
        start_line=1, end_line=2, symbol=symbol, site_label=None,
        param_names=tuple(params), params_truncated=truncated, sinks=(),
        guard_classes=(), destination_kind=None, lead=lead,
        tool_name=tool_name, arg_name=arg_name)


def _bind(tmp_path, obj):
    p = tmp_path / "binds.json"
    p.write_text(json.dumps(obj) if not isinstance(obj, str) else obj)
    return p


def _reason(res, cid="c1"):
    return {u.candidate.id: u.reason for u in res.unmapable}[cid]


# --- catalog -------------------------------------------------------------

def test_catalog_records_string_props_and_required():
    cat = build_catalog([_tool(
        "fetch", {"url": {"type": "string"}, "n": {"type": "integer"}},
        required=["url"])])
    (t,) = cat.tools
    assert t.name == "fetch"
    assert t.properties == ("url", "n")
    assert t.string_properties == ("url",)
    assert t.required == ("url",)


@pytest.mark.parametrize("bad", [
    [{"inputSchema": {}}],
    [{"name": 3}],
    ["fetch"],
    [{"name": "x", "inputSchema": {"properties": []}}],
    [{"name": "x", "inputSchema": {"required": "url"}}],
    "notalist",
])
def test_catalog_malformed_fails_closed(bad):
    with pytest.raises(EgressCatalogError):
        build_catalog(bad)


def test_catalog_without_schema_has_no_properties():
    (t,) = build_catalog([{"name": "x"}]).tools
    assert t.properties == () and t.string_properties == ()


# --- auto map ------------------------------------------------------------

def test_auto_map_happy():
    res = map_egress([_cand()], build_catalog([_tool("fetch")]))
    (m,) = res.mapped
    assert (m.tool, m.argument, m.via, m.arguments) == (
        "fetch", "url", "auto", {})
    assert res.unmapable == []


def test_no_tool_match():
    res = map_egress([_cand()], build_catalog([_tool("other")]))
    assert _reason(res) == "no_tool_match"


def test_must_not_substring_tool_name_matches():
    res = map_egress([_cand()], build_catalog(
        [_tool("fetch_url"), _tool("prefetch"), _tool("Fetch")]))
    assert res.mapped == []
    assert _reason(res) == "no_tool_match"


def test_ambiguous_tool():
    res = map_egress([_cand()], build_catalog([_tool("fetch"), _tool("fetch")]))
    assert _reason(res) == "ambiguous_tool"


def test_ambiguous_param():
    cat = build_catalog([_tool("fetch", {"url": {"type": "string"},
                                         "uri": {"type": "string"}})])
    res = map_egress([_cand(params=("url", "uri"))], cat)
    assert _reason(res) == "ambiguous_param"


def test_non_string_param_not_eligible():
    cat = build_catalog([_tool("fetch", {"url": {"type": "integer"}})])
    res = map_egress([_cand()], cat)
    assert _reason(res) == "no_param_match"


def test_truncated_params_without_match():
    cat = build_catalog([_tool("fetch", {"target": {"type": "string"}})])
    res = map_egress([_cand(params=("url",), truncated=True)], cat)
    assert _reason(res) == "no_param_match"


def test_lead_without_param_names():
    res = map_egress([_cand(params=(), lead=True)],
                     build_catalog([_tool("fetch")]))
    assert _reason(res) == "no_param_names"


def test_candidate_without_symbol_is_no_tool_match():
    res = map_egress([_cand(symbol=None)], build_catalog([_tool("fetch")]))
    assert _reason(res) == "no_tool_match"


# --- hints ---------------------------------------------------------------

def test_hint_valid_maps_via_hint():
    cat = build_catalog([_tool("get_page", {"link": {"type": "string"}})])
    res = map_egress([_cand(symbol=None, params=(), tool_name="get_page",
                            arg_name="link")], cat)
    (m,) = res.mapped
    assert (m.tool, m.argument, m.via) == ("get_page", "link", "hint")


@pytest.mark.parametrize("kw", [
    {"tool_name": "ghost", "arg_name": "url"},
    {"tool_name": "fetch", "arg_name": "ghost"},
    {"tool_name": "fetch", "arg_name": "n"},  # present but integer
])
def test_hint_absent_from_catalog_never_maps(kw):
    cat = build_catalog([_tool("fetch", {"url": {"type": "string"},
                                         "n": {"type": "integer"}})])
    res = map_egress([_cand(**kw)], cat)
    assert res.mapped == []
    assert _reason(res) == "hint_not_in_catalog"


# --- binds ---------------------------------------------------------------

def test_bind_maps_what_no_rule_matches(tmp_path):
    cat = build_catalog([_tool("get_page", {"link": {"type": "string"}})])
    binds = load_egress_binds(_bind(tmp_path, {
        "c1": {"tool": "get_page", "argument": "link"}}))
    res = map_egress([_cand()], cat, binds)
    (m,) = res.mapped
    assert (m.tool, m.argument, m.via) == ("get_page", "link", "bind")
    assert res.unmapable == []


def test_bind_wins_over_auto(tmp_path):
    cat = build_catalog([
        _tool("fetch"), _tool("other", {"u": {"type": "string"}})])
    binds = load_egress_binds(_bind(tmp_path, {
        "c1": {"tool": "other", "argument": "u"}}))
    (m,) = map_egress([_cand()], cat, binds).mapped
    assert (m.tool, m.argument, m.via) == ("other", "u", "bind")


def test_bind_static_arguments_merged(tmp_path):
    cat = build_catalog([_tool("fetch", {"url": {"type": "string"},
                                         "mode": {"type": "string"}},
                               required=["url", "mode"])])
    binds = load_egress_binds(_bind(tmp_path, {
        "c1": {"tool": "fetch", "argument": "url",
               "arguments": {"mode": "fast"}}}))
    (m,) = map_egress([_cand()], cat, binds).mapped
    assert m.arguments == {"mode": "fast"}


@pytest.mark.parametrize("binds,why", [
    ({"nope": {"tool": "fetch", "argument": "url"}}, "unknown candidate"),
    ({"c1": {"tool": "ghost", "argument": "url"}}, "tool"),
    ({"c1": {"tool": "fetch", "argument": "ghost"}}, "argument"),
    ({"c1": {"tool": "fetch", "argument": "n"}}, "non-string argument"),
    ({"c1": {"tool": "dup", "argument": "url"}}, "ambiguous tool name"),
])
def test_bind_against_catalog_stops(tmp_path, binds, why):
    cat = build_catalog([_tool("fetch", {"url": {"type": "string"},
                                         "n": {"type": "integer"}}),
                         _tool("dup"), _tool("dup")])
    loaded = load_egress_binds(_bind(tmp_path, binds))
    with pytest.raises(EgressBindsError):
        map_egress([_cand()], cat, loaded)


@pytest.mark.parametrize("obj", [
    "not json",
    "[]",
    {"c1": []},
    {"c1": {"tool": "fetch"}},
    {"c1": {"tool": "", "argument": "url"}},
    {"c1": {"tool": "fetch", "argument": 3}},
    {"c1": {"tool": "fetch", "argument": "url", "extra": 1}},
    {"c1": {"tool": "fetch", "argument": "url", "arguments": []}},
    {"c1": {"tool": "fetch", "argument": "url", "arguments": {"url": "x"}}},
    {"": {"tool": "fetch", "argument": "url"}},
])
def test_bad_binds_file_stops(tmp_path, obj):
    with pytest.raises(EgressBindsError):
        load_egress_binds(_bind(tmp_path, obj))


def test_binds_oversize_and_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(egressmap, "_MAX_BINDS_BYTES", 10)
    with pytest.raises(EgressBindsError):
        load_egress_binds(_bind(tmp_path, {"c1": {"tool": "fetch",
                                                  "argument": "url"}}))
    with pytest.raises(EgressBindsError):
        load_egress_binds(tmp_path / "absent.json")


# --- required args -------------------------------------------------------

def test_required_property_uncovered_is_unmapable_and_named():
    cat = build_catalog([_tool(
        "fetch", {"url": {"type": "string"}, "token": {"type": "string"}},
        required=["url", "token"])])
    res = map_egress([_cand()], cat)
    assert res.mapped == []
    assert _reason(res) == "required_args_unsatisfied"
    assert "token" in res.unmapable[0].detail
    assert "url" not in res.unmapable[0].detail


def test_required_covered_by_bind_arguments(tmp_path):
    cat = build_catalog([_tool(
        "fetch", {"url": {"type": "string"}, "token": {"type": "string"}},
        required=["url", "token"])])
    binds = load_egress_binds(_bind(tmp_path, {"c1": {
        "tool": "fetch", "argument": "url", "arguments": {"token": "x"}}}))
    assert len(map_egress([_cand()], cat, binds).mapped) == 1


# --- send plans ----------------------------------------------------------

def test_same_key_shares_one_plan_differing_static_args_split(tmp_path):
    cat = build_catalog([_tool("fetch", {"url": {"type": "string"},
                                         "mode": {"type": "string"}})])
    res = map_egress([_cand("a"), _cand("b")], cat)
    (plan,) = res.plans
    assert plan.candidate_ids == ("a", "b")
    assert (plan.tool, plan.argument, plan.arguments) == ("fetch", "url", {})

    binds = load_egress_binds(_bind(tmp_path, {
        "a": {"tool": "fetch", "argument": "url", "arguments": {"mode": "x"}},
        "b": {"tool": "fetch", "argument": "url", "arguments": {"mode": "y"}},
    }))
    res = map_egress([_cand("a"), _cand("b")], cat, binds)
    assert [p.candidate_ids for p in res.plans] == [("a",), ("b",)]
    # key order of static arguments does not split a plan
    binds = load_egress_binds(_bind(tmp_path, {
        "a": {"tool": "fetch", "argument": "url",
              "arguments": {"mode": "x", "k": 1}},
        "b": {"tool": "fetch", "argument": "url",
              "arguments": {"k": 1, "mode": "x"}},
    }))
    cat2 = build_catalog([_tool("fetch", {"url": {"type": "string"}})])
    res = map_egress([_cand("a"), _cand("b")], cat2, binds)
    assert len(res.plans) == 1


def test_unmapable_candidates_join_no_plan():
    res = map_egress([_cand()], build_catalog([_tool("zzz")]))
    assert res.plans == []


def test_plan_arguments_do_not_alias_bind(tmp_path):
    cat = build_catalog([_tool("fetch", {"url": {"type": "string"}})])
    binds = load_egress_binds(_bind(tmp_path, {"c1": {
        "tool": "fetch", "argument": "url", "arguments": {"k": [1]}}}))
    res = map_egress([_cand()], cat, binds)
    res.plans[0].arguments["k"].append(2)
    assert binds["c1"].arguments == {"k": [1]}


def test_catalog_named_keeps_duplicates_in_order():
    cat = egressmap.build_catalog([
        {"name": "a", "inputSchema": {"properties": {"x": {"type": "string"}}}},
        {"name": "b"},
        {"name": "a", "inputSchema": {"properties": {"y": {"type": "string"}}}},
    ])
    got = cat.named("a")
    assert [t.string_properties for t in got] == [("x",), ("y",)]
    assert got == [t for t in cat.tools if t.name == "a"]
    assert cat.named("zzz") == []
    got.clear()
    assert len(cat.named("a")) == 2
    direct = egressmap.ToolCatalog(cat.tools)
    assert direct == cat and direct.named("a") == cat.named("a")


# ------------------------------------------------------- template binds ({url})

def _write_binds(tmp_path, obj):
    import json
    p = tmp_path / "binds.json"
    p.write_text(json.dumps(obj))
    return p


def test_template_bind_records_placeholder_path(tmp_path):
    from dyetrace.egressmap import load_egress_binds
    p = _write_binds(tmp_path, {"c1": {"tool": "graphql", "arguments": {
        "action": {"type": "introspect", "endpoint": "{url}"}}}})
    binds = load_egress_binds(p)
    b = binds["c1"]
    assert b.template is True
    assert b.argument == "action.endpoint"
    assert b.tool == "graphql"


def test_template_bind_requires_exactly_one_placeholder(tmp_path):
    import pytest
    from dyetrace.egressmap import load_egress_binds, EgressBindsError
    p = _write_binds(tmp_path, {"c1": {"tool": "t", "arguments": {"a": "{url}", "b": "{url}"}}})
    with pytest.raises(EgressBindsError):
        load_egress_binds(p)
    p = _write_binds(tmp_path, {"c1": {"tool": "t", "arguments": {"a": "x"}}})
    with pytest.raises(EgressBindsError):
        load_egress_binds(p)


def test_argument_and_placeholder_cannot_mix(tmp_path):
    import pytest
    from dyetrace.egressmap import load_egress_binds, EgressBindsError
    p = _write_binds(tmp_path, {"c1": {"tool": "t", "argument": "url",
                                     "arguments": {"a": "{url}"}}})
    with pytest.raises(EgressBindsError):
        load_egress_binds(p)


def test_inject_url_substitutes_nested_leaf_only():
    from dyetrace.egressdrive import _inject_url
    out = _inject_url({"action": {"type": "x", "endpoint": "{url}"}, "n": 1},
                      "http://h/T")
    assert out == {"action": {"type": "x", "endpoint": "http://h/T"}, "n": 1}
    assert _inject_url({"a": "nope"}, "http://h/T") is None
    deep = _inject_url({"l": [{"v": "{url}"}]}, "http://h/T")
    assert deep == {"l": [{"v": "http://h/T"}]}
