"""U2: egress-candidates v1 contract loader and tool adapters."""

import copy
import json
import os
import subprocess
from pathlib import Path

import pytest

from dyetrace import egresscand
from dyetrace.egresscand import (
    EgressCandidate,
    EgressCandidatesError,
    load_egress_candidates,
)

FIX = Path(__file__).parent / "fixtures"
SGA = FIX / "ssrf_guard_audit_scan.json"
SGA_BANNER = FIX / "ssrf_guard_audit_scan_banner.txt"
EP = FIX / "egress_plane_scan.json"


def _contract(cands=None, **extra):
    obj = {"version": 1, "candidates": cands if cands is not None else []}
    obj.update(extra)
    return obj


def _cand(cid="c1", **over):
    c = {
        "id": cid,
        "source_tool": "t",
        "source_version": "1",
        "file": "a.py",
        "start_line": 3,
        "end_line": 9,
        "symbol": "fetch",
        "param_names": ["url"],
        "sinks": [{"file": "a.py", "line": 5}],
        "guard_classes": ["G8"],
        "destination_kind": "param",
        "lead": False,
    }
    c.update(over)
    return c


def _write(tmp_path, obj, name="c.json"):
    p = tmp_path / name
    p.write_text(obj if isinstance(obj, str) else json.dumps(obj), encoding="utf-8")
    return p


# --- normalized contract -------------------------------------------------


def test_valid_contract_loads_typed(tmp_path):
    p = _write(tmp_path, _contract([_cand(tool_name="fetch", arg_name="url")]))
    cs = load_egress_candidates(p)
    assert len(cs.candidates) == 1
    c = cs.candidates[0]
    assert isinstance(c, EgressCandidate)
    assert c.id == "c1"
    assert c.file == "a.py"
    assert (c.start_line, c.end_line) == (3, 9)
    assert c.symbol == "fetch"
    assert c.param_names == ("url",)
    assert c.params_truncated is False
    assert c.sinks[0].file == "a.py" and c.sinks[0].line == 5
    assert c.guard_classes == ("G8",)
    assert c.destination_kind == "param"
    assert c.lead is False
    assert c.tool_name == "fetch" and c.arg_name == "url"


def test_empty_candidate_list_loads_empty(tmp_path):
    assert load_egress_candidates(_write(tmp_path, _contract())).candidates == []


def test_optional_fields_default(tmp_path):
    minimal = {
        "id": "m",
        "source_tool": "t",
        "source_version": "1",
        "file": "a.py",
        "start_line": 1,
        "end_line": 1,
    }
    c = load_egress_candidates(_write(tmp_path, _contract([minimal]))).candidates[0]
    assert c.symbol is None and c.site_label is None
    assert c.param_names == () and c.sinks == () and c.guard_classes == ()
    assert c.lead is False and c.tool_name is None and c.arg_name is None


def test_unknown_keys_ignored_and_no_spawn_field(tmp_path):
    cand = _cand(command="rm -rf /", args=["x"])
    obj = _contract([cand], command="evil", args=["y"])
    cs = load_egress_candidates(_write(tmp_path, obj))
    c = cs.candidates[0]
    fields = set(c.__dataclass_fields__)
    assert "command" not in fields and "args" not in fields
    assert not hasattr(c, "command") and not hasattr(c, "args")


@pytest.mark.parametrize(
    "mutate, msg",
    [
        (lambda o: o.update(version=2), "version must be 1"),
        (lambda o: o.update(version="1"), "version must be 1"),
        (lambda o: o.update(version=True), "version must be 1"),
        (lambda o: o.pop("version"), "version must be 1"),
        (lambda o: o.update(candidates={}), "candidates must be an array"),
        (lambda o: o["candidates"].append("x"), "must be an object"),
        (lambda o: o["candidates"][0].pop("id"), "id must be a string"),
        (lambda o: o["candidates"][0].update(start_line="3"), "start_line must be an int"),
        (lambda o: o["candidates"][0].update(lead="yes"), "lead must be a bool"),
        (lambda o: o["candidates"][0].update(param_names="url"), "param_names must be an array"),
        (lambda o: o["candidates"][0].update(sinks=[{"file": "a"}]), "line must be an int"),
        (lambda o: o["candidates"][0].update(id="x" * 300), "too long"),
        (lambda o: o["candidates"][0].update(file="f" * 5000), "too long"),
        (lambda o: o["candidates"][0].update(tool_name="t" * 300), "too long"),
        (lambda o: o["candidates"][0].update(param_names=["p" * 300]), "too long"),
    ],
)
def test_contract_errors(tmp_path, mutate, msg):
    obj = _contract([_cand()])
    mutate(obj)
    with pytest.raises(EgressCandidatesError) as ei:
        load_egress_candidates(_write(tmp_path, obj))
    assert msg in str(ei.value)


def test_non_object_root(tmp_path):
    with pytest.raises(EgressCandidatesError, match="must be a JSON object"):
        load_egress_candidates(_write(tmp_path, "[1]"))


def test_not_json(tmp_path):
    with pytest.raises(EgressCandidatesError, match="not valid JSON"):
        load_egress_candidates(_write(tmp_path, "nope"))


def test_duplicate_id(tmp_path):
    obj = _contract([_cand("d"), _cand("d")])
    with pytest.raises(EgressCandidatesError, match="duplicate candidate id: d"):
        load_egress_candidates(_write(tmp_path, obj))


def test_over_candidate_cap(tmp_path):
    cands = [_cand(f"c{i}") for i in range(10_001)]
    with pytest.raises(EgressCandidatesError, match="the cap is 10000"):
        load_egress_candidates(_write(tmp_path, _contract(cands)))


def test_exactly_cap_loads(tmp_path):
    cands = [_cand(f"c{i}") for i in range(10_000)]
    cs = load_egress_candidates(_write(tmp_path, _contract(cands)))
    assert len(cs.candidates) == 10_000


def test_file_over_size_cap(tmp_path, monkeypatch):
    p = _write(tmp_path, _contract([_cand()]))
    monkeypatch.setattr(egresscand, "_MAX_FILE_BYTES", 10)
    with pytest.raises(EgressCandidatesError, match="exceeds 10 bytes"):
        load_egress_candidates(p)


def test_non_utf8(tmp_path):
    p = tmp_path / "c.json"
    p.write_bytes(b'{"version": 1, "candidates": [], "x": "\xff\xfe"}')
    with pytest.raises(EgressCandidatesError, match="not UTF-8"):
        load_egress_candidates(p)


def test_missing_file(tmp_path):
    with pytest.raises(EgressCandidatesError, match="cannot read"):
        load_egress_candidates(tmp_path / "nope.json")


def test_unknown_format(tmp_path):
    with pytest.raises(EgressCandidatesError, match="unknown candidates format"):
        load_egress_candidates(_write(tmp_path, _contract()), fmt="bogus")


# --- ssrf-guard-audit adapter -------------------------------------------


def _sga(path=SGA):
    return load_egress_candidates(path, fmt="ssrf-guard-audit")


def test_sga_real_shape_converts():
    cs = _sga()
    assert [c.symbol for c in cs.candidates] == [
        "check_may_autonomously_fetch_url",
        "fetch_url",
    ]
    c = cs.candidates[1]
    assert c.source_tool == "ssrf-guard-audit"
    assert c.source_version == "0.1.0"
    assert c.file.endswith("mcp_server_fetch/server.py")
    assert (c.start_line, c.end_line) == (111, 148)
    assert c.site_label == "async def fetch_url("
    assert c.guard_classes == ("G8",)
    assert len(c.sinks) == 2 and all(s.file == c.file for s in c.sinks)
    assert c.destination_kind is None and c.lead is False
    assert c.tool_name is None and c.arg_name is None
    assert cs.coverage_verdict == "surface_detected"


def test_sga_ids_stable_and_distinct():
    a, b = _sga().candidates, _sga().candidates
    assert [c.id for c in a] == [c.id for c in b]
    assert a[0].id != a[1].id
    assert all(c.id.startswith("sga-") for c in a)


def test_sga_truncated_label_keeps_complete_params_only():
    c = _sga().candidates[0]
    assert c.site_label == (
        "async def check_may_autonomously_fetch_url(url: str, user_agent: str, proxy_url:"
    )
    assert c.params_truncated is True
    assert c.param_names == ("url", "user_agent")


def test_sga_complete_label_not_truncated(tmp_path):
    raw = json.loads(SGA.read_text())
    raw["findings"][0]["site"] = "def forward(self, query: str, filter_year: int | None = None) -> str:"
    c = _sga(_write(tmp_path, raw)).candidates[0]
    assert c.symbol == "forward"
    assert c.params_truncated is False
    assert c.param_names == ("query", "filter_year")


def test_sga_bracketed_defaults_do_not_split(tmp_path):
    raw = json.loads(SGA.read_text())
    raw["findings"][0]["site"] = "def f(a: Dict[str, int], *args, b=(1, 2), **kw):"
    c = _sga(_write(tmp_path, raw)).candidates[0]
    assert c.param_names == ("a", "args", "b", "kw")


def test_sga_ts_label(tmp_path):
    raw = json.loads(SGA.read_text())
    raw["findings"][0]["site"] = "async processPageContent(page: any, url: string): Promise<FetchResult> {"
    c = _sga(_write(tmp_path, raw)).candidates[0]
    assert c.symbol == "processPageContent"
    assert c.param_names == ("page", "url")
    assert c.params_truncated is False


def test_sga_label_without_parens(tmp_path):
    raw = json.loads(SGA.read_text())
    raw["findings"][0]["site"] = "class Foo"
    c = _sga(_write(tmp_path, raw)).candidates[0]
    assert c.symbol is None and c.param_names == ()


def test_sga_banner_text_before_json_tolerated():
    text = SGA_BANNER.read_text()
    assert not text.lstrip().startswith("{")
    banner = _sga(SGA_BANNER).candidates
    plain = _sga().candidates
    assert [c.id for c in banner] == [c.id for c in plain]


def test_sga_banner_with_brace_noise(tmp_path):
    text = "{not json\n[warn] x {y}\n" + SGA.read_text()
    assert len(_sga(_write(tmp_path, text)).candidates) == 2


def test_sga_resolution_filter(tmp_path):
    raw = json.loads(SGA.read_text())
    base = raw["findings"][0]
    for i, res in enumerate(
        ["recognized_complete", "unrecognized_guard", "source_no_sink"]
    ):
        f = copy.deepcopy(base)
        f["start_line"] = 500 + i
        f["resolution"] = res
        raw["findings"].append(f)
    cs = _sga(_write(tmp_path, raw))
    lines = sorted(c.start_line for c in cs.candidates)
    assert 500 not in lines and 502 not in lines and 501 in lines
    assert len(cs.candidates) == 3


def test_sga_findings_empty(tmp_path):
    raw = json.loads(SGA.read_text())
    raw["findings"] = []
    assert _sga(_write(tmp_path, raw)).candidates == []


@pytest.mark.parametrize(
    "mutate, msg",
    [
        (lambda o: o.update(schema_version="ssrf-guard-audit/v2"), "schema_version"),
        (lambda o: o.pop("schema_version"), "schema_version"),
        (lambda o: o.update(findings={}), "findings must be an array"),
        (lambda o: o["findings"].append(5), "must be an object"),
        (lambda o: o["findings"][0].pop("path"), "path must be a string"),
        (lambda o: o["findings"][0].update(start_line="1"), "start_line must be an int"),
        (lambda o: o["findings"][0].update(site="s" * 5000), "too long"),
    ],
)
def test_sga_errors(tmp_path, mutate, msg):
    raw = json.loads(SGA.read_text())
    mutate(raw)
    with pytest.raises(EgressCandidatesError) as ei:
        _sga(_write(tmp_path, raw))
    assert msg in str(ei.value)


def test_sga_no_json_at_all(tmp_path):
    with pytest.raises(EgressCandidatesError, match="no JSON object"):
        _sga(_write(tmp_path, "only a banner\n"))


def test_sga_non_object_root(tmp_path):
    with pytest.raises(EgressCandidatesError):
        _sga(_write(tmp_path, "[1]"))


def test_sga_duplicate_finding_rejected(tmp_path):
    raw = json.loads(SGA.read_text())
    raw["findings"].append(copy.deepcopy(raw["findings"][0]))
    with pytest.raises(EgressCandidatesError, match="duplicate candidate id"):
        _sga(_write(tmp_path, raw))


# --- egress-plane adapter ------------------------------------------------


def _ep(path=EP):
    return load_egress_candidates(path, fmt="egress-plane")


def test_ep_real_shape_converts_to_leads():
    cs = _ep()
    kinds = sorted(c.destination_kind for c in cs.candidates)
    # fixture holds 3 literal sites (dropped) plus expr, expr, param
    assert kinds == ["expr", "expr", "param"]
    for c in cs.candidates:
        assert c.lead is True
        assert c.param_names == ()
        assert c.id.startswith("ep-")
        assert c.source_tool == "egress-plane" and c.source_version == "0.1.0"
        assert c.start_line == c.end_line
        assert c.tool_name is None and c.arg_name is None
        assert len(c.sinks) == 1 and c.sinks[0].file == c.file
    p = next(c for c in cs.candidates if c.destination_kind == "param")
    assert p.symbol == "FetchPageTool.forward" and p.start_line == 528
    assert cs.coverage_verdict == "complete"


def test_ep_kind_filter(tmp_path):
    raw = json.loads(EP.read_text())
    base = raw["sites"][0]
    raw["sites"] = []
    for i, kind in enumerate(
        ["param", "env", "expr", "template", "literal", "exec", "other"]
    ):
        s = copy.deepcopy(base)
        s["id"] = f"id{i}"
        s["destination"]["kind"] = kind
        raw["sites"].append(s)
    cs = _ep(_write(tmp_path, raw))
    assert [c.destination_kind for c in cs.candidates] == [
        "param", "env", "expr", "template",
    ]
    assert [c.id for c in cs.candidates] == ["ep-id0", "ep-id1", "ep-id2", "ep-id3"]


def test_ep_empty_sites(tmp_path):
    raw = json.loads(EP.read_text())
    raw["sites"] = []
    assert _ep(_write(tmp_path, raw)).candidates == []


@pytest.mark.parametrize(
    "mutate, msg",
    [
        (lambda o: o.update(schema_version=2), "schema_version"),
        (lambda o: o.update(schema_version="1"), "schema_version"),
        (lambda o: o.update(sites=None), "sites must be an array"),
        (lambda o: o["sites"][0].pop("id"), "id must be a string"),
        (lambda o: o["sites"][0].update(destination=3), "destination must be an object"),
        (lambda o: o["sites"][0].update(location={}), "line must be an int"),
        (lambda o: o["sites"][0].update(id="i" * 300), "too long"),
    ],
)
def test_ep_errors(tmp_path, mutate, msg):
    raw = json.loads(EP.read_text())
    # make site 0 a kept kind so the mutation is reached
    raw["sites"][0]["destination"]["kind"] = "expr"
    mutate(raw)
    with pytest.raises(EgressCandidatesError) as ei:
        _ep(_write(tmp_path, raw))
    assert msg in str(ei.value)


def test_ep_duplicate_site_id(tmp_path):
    raw = json.loads(EP.read_text())
    for s in raw["sites"]:
        s["id"] = "same"
        s["destination"]["kind"] = "expr"
    with pytest.raises(EgressCandidatesError, match="duplicate candidate id"):
        _ep(_write(tmp_path, raw))


# --- round trip and must-not ---------------------------------------------


@pytest.mark.parametrize("fmt, path", [("ssrf-guard-audit", SGA), ("egress-plane", EP)])
def test_adapter_round_trips_to_loadable_contract(tmp_path, fmt, path):
    cs = load_egress_candidates(path, fmt=fmt)
    out = _write(tmp_path, egresscand.to_contract(cs))
    again = load_egress_candidates(out)
    assert again.candidates == cs.candidates
    assert again.coverage_verdict == cs.coverage_verdict


def test_adapters_never_spawn_a_process(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("process spawn attempted")

    for name in ("run", "Popen", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, boom)
    for name in ("system", "popen", "execv", "execvp", "spawnv", "posix_spawn"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, boom)
    assert len(_sga().candidates) == 2
    assert len(_sga(SGA_BANNER).candidates) == 2
    assert len(_ep().candidates) == 3


def test_module_does_not_import_subprocess():
    src = (Path(egresscand.__file__)).read_text()
    assert "subprocess" not in src and "os.system" not in src
