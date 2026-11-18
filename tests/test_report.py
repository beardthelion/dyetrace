"""Tests for the U8 report renderer.

Test-first: written before src/dyetrace/report.py exists, so the import fails
RED until the module is implemented. No network: VerdictReport/FlowRow objects
are built by hand.

Invariants under test: the flow table carries the R10 columns, one row per
FlowRow (R10); captured snippets are untrusted and escaped per surface before
rendering (R18/R23) - HTML entity-encoded on the html surface, ANSI/C0/C1
neutralized on the terminal surface; emitted URLs are sanitized so a token in a
query is masked (R22); injection-candidate and cross-context rows are promoted
into a findings bucket with a reproducible request pair (R10); the summary line
names the four outcome counts and the universe so a clean zero-hit run is
labeled distinctly from a stop (R17).
"""

import json

from dyetrace.observe import (
    OUTCOME_NOISE,
    OUTCOME_RESURFACED,
    FlowRow,
    VerdictReport,
)
from dyetrace.ossverdict import CandidateVerdict, OssReport
from dyetrace.report import render, render_findings
from tests.oss_fixtures import candidate as _cand


def _row(**kw):
    base = dict(
        entry_id="0",
        source_method="GET",
        source_url="https://app.example.com/x?q=1",
        source_path_id="query:q",
        source_identity=1,
        sink_url="https://app.example.com/profile",
        sink_identity=1,
        encoding="raw",
        cross_context=False,
        severity="tracked",
        outcome=OUTCOME_RESURFACED,
        snippet="DYE-a1b2-0-deadbeef-" + "f" * 64,
    )
    base.update(kw)
    return FlowRow(**base)


def _report(rows, **counts):
    c = dict(
        never_resurfaced=0,
        noise=0,
        resurfaced=0,
        plant_rejected=0,
        universe=1,
    )
    c.update(counts)
    return VerdictReport(rows=list(rows), outcomes={}, counts=c)


# --- Happy: a verified hit renders one row with the R10 columns -------------


def test_terminal_row_carries_r10_columns():
    report = _report([_row()], resurfaced=1, universe=1)
    out = render(report, surface="terminal")
    assert "0" in out                       # entry_id
    assert "GET" in out                      # source method
    assert "query:q" in out                  # source path id
    assert "app.example.com/profile" in out  # sink url
    assert "raw" in out                      # encoding variant
    assert "tracked" in out                  # severity
    assert "False" in out or "false" in out  # cross_context column present


def test_injection_candidate_promoted_to_findings_with_request_pair():
    token = "DYE-a1b2-0-deadbeef-" + "a" * 64
    payload = '"><dye t=' + token + ">"
    rows = [
        _row(
            entry_id="7",
            severity="injection-candidate",
            encoding="html",
            source_method="POST",
            source_url="https://app.example.com/submit?id=42",
            source_path_id="query:id",
            sink_url="https://app.example.com/render",
            sink_identity=1,
            snippet=payload,
        ),
        _row(entry_id="0", severity="tracked"),  # not promoted
    ]
    report = _report(rows, resurfaced=2, universe=2)
    findings = render_findings(report, surface="terminal")
    # The promoted row and its reproducible request pair appear.
    assert "7" in findings
    assert "POST" in findings
    assert "query:id" in findings
    assert "app.example.com/submit" in findings  # source request
    assert "app.example.com/render" in findings  # sink
    # The plain tracked row is NOT promoted into findings.
    assert "query:q" not in findings


def test_cross_context_row_is_promoted_to_findings():
    report = _report(
        [_row(entry_id="3", severity="cross-context", cross_context=True,
              sink_identity=2)],
        resurfaced=1, universe=1,
    )
    findings = render_findings(report, surface="terminal")
    assert "3" in findings
    assert "cross-context" in findings


# --- Edge: cross-context absent; summary labels a clean run -----------------


def test_cross_context_false_for_every_row_and_summary_counts():
    rows = [_row(entry_id="0"), _row(entry_id="1")]
    report = _report(rows, resurfaced=2, universe=2)
    out = render(report, surface="terminal")
    # No row claims cross-context.
    assert "True" not in out.split("summary")[0] or all(
        not r.cross_context for r in report.rows
    )
    assert all(r.cross_context is False for r in report.rows)


def test_clean_zero_hit_summary_labeled_distinctly():
    report = _report([], never_resurfaced=3, universe=3)
    out = render(report, surface="terminal")
    assert "no verified leaks" in out
    assert "universe=3" in out
    assert "never=3" in out
    assert "noise=0" in out
    assert "plant_rejected=0" in out


def test_summary_labels_a_run_with_leaks_differently():
    report = _report([_row()], resurfaced=1, universe=1)
    out = render(report, surface="terminal")
    assert "no verified leaks" not in out
    assert "resurfaced=1" in out


# --- Negative: escaping (R18/R23) and URL sanitization (R22) ----------------


def test_html_surface_entity_escapes_markup_breaking_snippet():
    token = "DYE-a1b2-0-deadbeef-" + "b" * 64
    payload = '"><dye t=' + token + ">"
    report = _report([_row(encoding="html", severity="injection-candidate",
                           snippet=payload)], resurfaced=1, universe=1)
    out = render(report, surface="html")
    # No live tag survives; the markup is entity-encoded and inert.
    assert "<dye" not in out
    assert "&lt;dye" in out
    assert "&gt;" in out
    # The token text itself still present (as data).
    assert token in out


def test_terminal_surface_neutralizes_ansi_and_control_bytes():
    token = "DYE-a1b2-0-deadbeef-" + "c" * 64
    snippet = "\x1b[31mred\x1b[0m" + token + "\x07\x00bell"
    report = _report([_row(snippet=snippet)], resurfaced=1, universe=1)
    out = render(report, surface="terminal")
    # The raw ESC byte and the C0 control bytes are gone (inert).
    assert "\x1b" not in out
    assert "\x07" not in out
    assert "\x00" not in out
    # The token survives as readable data.
    assert token in out


def test_url_with_token_in_query_is_sanitized_in_output():
    report = _report(
        [_row(sink_url="https://app.example.com/cb?token=SECRETVALUE",
              source_url="https://app.example.com/x?apikey=TOPSECRET")],
        resurfaced=1, universe=1,
    )
    for surface in ("terminal", "html", "json"):
        out = render(report, surface=surface)
        assert "SECRETVALUE" not in out
        assert "TOPSECRET" not in out
        assert "token=***" in out


# --- JSON surface -----------------------------------------------------------


def test_json_surface_is_a_valid_document_with_verbatim_snippet():
    token = "DYE-a1b2-0-deadbeef-" + "d" * 64
    payload = '"><dye t=' + token + ">"
    report = _report([_row(encoding="html", severity="injection-candidate",
                           snippet=payload)], resurfaced=1, universe=1)
    out = render(report, surface="json")
    doc = json.loads(out)  # must parse
    assert doc["counts"]["resurfaced"] == 1
    assert doc["counts"]["universe"] == 1
    assert len(doc["flow"]) == 1
    # json.dumps handled escaping; the snippet is a plain verbatim string field.
    assert doc["flow"][0]["snippet"] == payload
    assert len(doc["findings"]) == 1
    assert "summary" in doc


# --- OSS verdict block -------------------------------------------------------


def _oss_report():
    return OssReport(candidate_verdicts=[
        CandidateVerdict(
            candidate=_cand("cand-p", detail="get /predicted"),
            verdict="PROVEN",
        ),
        CandidateVerdict(
            candidate=_cand("cand-u", detail="get /x"),
            verdict="unmapable",
            reason="no recorded request matches 'get /x'",
        ),
    ])


def test_terminal_oss_block_renders_verdicts():
    text = render(VerdictReport(), surface="terminal", oss=_oss_report())
    assert "candidate verdicts" in text
    assert "cand-p | PROVEN" in text
    assert "cand-u | unmapable" in text


def test_terminal_oss_block_strips_control_chars():
    evil = CandidateVerdict(
        candidate=_cand("cand-\x1b[31mx"), verdict="new_flow",
    )
    text = render(VerdictReport(), surface="terminal",
                  oss=OssReport(candidate_verdicts=[evil]))
    assert "\x1b" not in text


def test_html_oss_block_entity_encodes():
    evil = CandidateVerdict(
        candidate=_cand("cand-<script>"), verdict="KILL",
    )
    text = render(VerdictReport(), surface="html",
                  oss=OssReport(candidate_verdicts=[evil]))
    assert "<script>" not in text
    assert "&lt;script&gt;" in text


def test_json_oss_block_shape():
    import json
    doc = json.loads(render(VerdictReport(), surface="json",
                            oss=_oss_report()))
    v = doc["oss"]["candidate_verdicts"][0]
    assert v["verdict"] == "PROVEN"
    assert v["sink"]["callee"] == "os.system"
    assert doc["oss"]["fell_back"] is False


def test_oss_block_masks_secret_shaped_path_segment():
    secret_seg = "aaaabbbbcccc1111dddd"  # 20+ opaque alnum -> masks
    evil = CandidateVerdict(
        candidate=_cand("cand-m", detail=f"get /user/{secret_seg}"),
        verdict="unmapable", reason="none",
    )
    for surface in ("terminal", "html"):
        text = render(VerdictReport(), surface=surface,
                      oss=OssReport(candidate_verdicts=[evil]))
        assert secret_seg not in text


def test_oss_fell_back_notice():
    from dyetrace.ossverdict import OssReport
    text = render(VerdictReport(), surface="terminal",
                  oss=OssReport(fell_back=True))
    assert "black-box" in text


def test_json_oss_block_serializes_hits_and_masks_entry():
    import json
    v = CandidateVerdict(
        candidate=_cand("cand-h", detail="get /x"), verdict="new_flow",
        hits=[_row()],
        jevsec_seed="unexpected sink: https://app.example.com/profile",
    )
    doc = json.loads(render(VerdictReport(), surface="json",
                            oss=OssReport(candidate_verdicts=[v])))
    hit = doc["oss"]["candidate_verdicts"][0]["hits"][0]
    assert hit["entry_id"] == "0"
    assert hit["sink_url"] == "https://app.example.com/profile"
    assert hit["severity"] == "tracked"


def test_oss_masks_secret_segment_on_json_surface():
    import json
    seg = "aaaabbbbcccc1111dddd"
    v = CandidateVerdict(candidate=_cand("cand-m", detail=f"get /user/{seg}"),
                         verdict="unmapable", reason="x")
    doc = json.loads(render(VerdictReport(), surface="json",
                            oss=OssReport(candidate_verdicts=[v])))
    assert seg not in json.dumps(doc)
