"""U8 report renderer.

Turns a U7 ``VerdictReport`` into a human- or machine-readable surface. Three
hard rules, all per-surface at render time (R18, R22, R23, KTD12):

- Captured snippets are UNTRUSTED. They are held verbatim in the FlowRow and
  escaped only here, once, for the chosen surface: HTML entity-encoding for
  html, ANSI + C0/C1 control-byte neutralization for a terminal, and json's own
  string escaping for json.
- Emitted URLs are sanitized with ``masking.sanitize_url`` so a token in a
  query string, a path segment, or a userinfo credential never reaches the
  output (R22). The same masking the loader already trusts is reused, not
  re-derived.
- A flow table (one row per resurfacing, R10), a findings bucket (the
  injection-candidate and cross-context rows promoted with a reproducible
  request pair), and a summary line that names the four outcome counts and the
  universe, so a clean zero-hit run is clearly labeled and visibly different
  from a fail-closed stop (R17).
"""

import html
import json

from .observe import (
    OUTCOME_NEVER,
    OUTCOME_NOISE,
    OUTCOME_PLANT_REJECTED,
    OUTCOME_RESURFACED,
    SEVERITY_CROSS_CONTEXT,
    SEVERITY_INJECTION,
)
from .masking import mask_path, mask_route_detail, sanitize_url, terminal_safe

__all__ = ["render", "render_findings"]

# Severities promoted into the findings bucket (R10): a markup-breaking variant
# that surfaced unescaped, or any cross-identity surfacing.
_PROMOTED = frozenset({SEVERITY_INJECTION, SEVERITY_CROSS_CONTEXT})

_terminal_safe = terminal_safe


def _summary_line(counts):
    """The one-line verdict. A clean zero-hit run is labeled distinctly from a
    stop; a run with verified leaks is labeled differently again (R17)."""
    never = counts.get(OUTCOME_NEVER, 0)
    noise = counts.get(OUTCOME_NOISE, 0)
    rejected = counts.get(OUTCOME_PLANT_REJECTED, 0)
    resurfaced = counts.get(OUTCOME_RESURFACED, 0)
    universe = counts.get("universe", 0)
    prop_failures = counts.get("propagation_failures", 0)
    tail = (
        f"universe={universe}, never={never}, noise={noise}, "
        f"plant_rejected={rejected}"
    )
    if resurfaced:
        return f"verified leaks found: resurfaced={resurfaced}, {tail}"
    if prop_failures:
        # A no-leak result over failed surfaces is inconclusive, not clean.
        return (
            f"inconclusive: no verified leaks but {prop_failures} propagation "
            f"surface(s) failed, results incomplete: {tail}"
        )
    return f"no verified leaks: {tail}"


def _row_cells(row, escape):
    """The R10 columns for one row, URLs sanitized and the snippet escaped by
    the per-surface ``escape`` callable. Every untrusted cell is escaped."""
    return {
        "entry_id": escape(str(row.entry_id)),
        "source_method": escape(str(row.source_method)),
        "source_url": escape(sanitize_url(row.source_url) if row.source_url else ""),
        "source_path_id": escape(str(row.source_path_id)),
        "source_identity": row.source_identity,
        "sink_url": escape(sanitize_url(row.sink_url) if row.sink_url else ""),
        "sink_identity": row.sink_identity,
        "encoding": escape(str(row.encoding)),
        "cross_context": row.cross_context,
        "severity": escape(str(row.severity)),
        "snippet": escape(row.snippet),
    }


def _findings_rows(report):
    return [r for r in report.rows if r.severity in _PROMOTED]


# --- terminal ---------------------------------------------------------------


def _masked_entry(detail):
    return mask_route_detail(detail)


def _oss_cells(v, escape):
    """Per-surface-escaped verdict cells. Candidate-derived strings (jevsec
    route details, sink sites, seed notes) are untrusted input and get the same
    masking as recorded URLs before escaping."""
    cand = v.candidate
    seed = v.jevsec_seed or ""
    return {
        "id": escape(cand.id),
        "verdict": escape(v.verdict),
        "entry": escape(_masked_entry(cand.entry.detail)),
        "entry_site": escape(mask_path(cand.entry.site_file)),
        "sink": escape(
            f"{cand.sink.callee} [{cand.sink.sink_class}] "
            f"at {mask_path(cand.sink.site_file)}:{cand.sink.site_line}"
        ),
        "reason": escape(v.reason or ""),
        "seed": escape(seed),
        "predicted": escape(v.predicted),
        "bind": escape(_bind_str(v.bind)),
    }


def _bind_str(bind):
    if bind is None:
        return ""
    out = f"req:{bind.request_index}"
    if bind.path_id:
        out += f" leaf:{bind.path_id}"
    return out


def _render_oss_terminal(oss):
    lines = ["candidate verdicts (OSS mode):"]
    if oss.fell_back:
        lines.append(
            "  (candidates file held zero candidates; ran black-box mode)"
        )
        return "\n".join(lines)
    if not oss.candidate_verdicts:
        lines.append("  (none)")
        return "\n".join(lines)
    for v in oss.candidate_verdicts:
        c = _oss_cells(v, _terminal_safe)
        line = (f"  {c['id']} | {c['verdict']} | {c['entry']} | {c['sink']}"
                f" | predicted: {c['predicted']}")
        if c["bind"]:
            line += f" | bind: {c['bind']}"
        if c["reason"]:
            line += f" | reason: {c['reason']}"
        if c["seed"]:
            line += f" | {c['seed']}"
        lines.append(line)
    return "\n".join(lines)


def _render_oss_html(oss):
    parts = ["<h2>candidate verdicts</h2>"]
    if oss.fell_back:
        parts.append(
            "<p>(candidates file held zero candidates; ran black-box mode)</p>"
        )
        return "\n".join(parts)
    if not oss.candidate_verdicts:
        parts.append("<p>(none)</p>")
        return "\n".join(parts)
    parts.append(
        "<table><tr><th>candidate</th><th>verdict</th><th>entry</th>"
        "<th>sink</th><th>reason</th><th>seed</th></tr>"
    )
    for v in oss.candidate_verdicts:
        c = _oss_cells(v, html.escape)
        parts.append(
            "<tr>"
            f"<td>{c['id']}</td><td>{c['verdict']}</td><td>{c['entry']}</td>"
            f"<td>{c['sink']}</td><td>{c['reason']}</td><td>{c['seed']}</td>"
            "</tr>"
        )
    parts.append("</table>")
    return "\n".join(parts)


def _render_terminal(report, oss=None):
    lines = ["dyetrace flow table"]
    header = (
        "entry_id | source | sink_url | sink_identity | encoding | "
        "cross_context | severity | snippet"
    )
    lines.append(header)
    for row in report.rows:
        c = _row_cells(row, _terminal_safe)
        source = f"{c['source_method']} {c['source_url']} [{c['source_path_id']}]"
        lines.append(
            " | ".join(
                [
                    c["entry_id"],
                    source,
                    c["sink_url"],
                    str(c["sink_identity"]),
                    c["encoding"],
                    str(c["cross_context"]),
                    c["severity"],
                    c["snippet"],
                ]
            )
        )
    lines.append("")
    lines.append(_render_findings_terminal(report))
    if oss is not None:
        lines.append("")
        lines.append(_render_oss_terminal(oss))
    lines.append("")
    lines.append("summary: " + _summary_line(report.counts))
    return "\n".join(lines)


def _render_findings_terminal(report):
    rows = _findings_rows(report)
    lines = ["findings (promoted injection-candidate / cross-context hits):"]
    if not rows:
        lines.append("  (none)")
        return "\n".join(lines)
    for row in rows:
        c = _row_cells(row, _terminal_safe)
        lines.append(
            f"  entry {c['entry_id']} [{c['severity']}] "
            f"source: {c['source_method']} {c['source_url']} [{c['source_path_id']}]"
            f"  ->  sink: {c['sink_url']} (identity {c['sink_identity']})"
        )
        lines.append(f"    snippet: {c['snippet']}")
    return "\n".join(lines)


# --- html -------------------------------------------------------------------


def _render_html(report, oss=None):
    parts = ["<h1>dyetrace flow table</h1>", "<table>"]
    parts.append(
        "<tr><th>entry_id</th><th>source</th><th>sink_url</th>"
        "<th>sink_identity</th><th>encoding</th><th>cross_context</th>"
        "<th>severity</th><th>snippet</th></tr>"
    )
    for row in report.rows:
        c = _row_cells(row, html.escape)
        source = f"{c['source_method']} {c['source_url']} [{c['source_path_id']}]"
        parts.append(
            "<tr>"
            f"<td>{c['entry_id']}</td>"
            f"<td>{source}</td>"
            f"<td>{c['sink_url']}</td>"
            f"<td>{c['sink_identity']}</td>"
            f"<td>{c['encoding']}</td>"
            f"<td>{c['cross_context']}</td>"
            f"<td>{c['severity']}</td>"
            f"<td>{c['snippet']}</td>"
            "</tr>"
        )
    parts.append("</table>")
    parts.append(_render_findings_html(report))
    if oss is not None:
        parts.append(_render_oss_html(oss))
    parts.append(f"<p>summary: {html.escape(_summary_line(report.counts))}</p>")
    return "\n".join(parts)


def _render_findings_html(report):
    rows = _findings_rows(report)
    parts = ["<h2>findings</h2>"]
    if not rows:
        parts.append("<p>(none)</p>")
        return "\n".join(parts)
    parts.append("<ul>")
    for row in rows:
        c = _row_cells(row, html.escape)
        parts.append(
            "<li>"
            f"entry {c['entry_id']} [{c['severity']}] "
            f"source: {c['source_method']} {c['source_url']} [{c['source_path_id']}]"
            f" -&gt; sink: {c['sink_url']} (identity {c['sink_identity']})"
            f"<br>snippet: {c['snippet']}"
            "</li>"
        )
    parts.append("</ul>")
    return "\n".join(parts)


# --- json -------------------------------------------------------------------


def _json_row(row):
    """A row as plain data; json.dumps owns the escaping. The snippet is a
    verbatim string field (KTD12), URLs are sanitized."""
    return {
        "entry_id": row.entry_id,
        "source_method": row.source_method,
        "source_url": sanitize_url(row.source_url) if row.source_url else None,
        "source_path_id": row.source_path_id,
        "source_identity": row.source_identity,
        "sink_url": sanitize_url(row.sink_url) if row.sink_url else None,
        "sink_identity": row.sink_identity,
        "encoding": row.encoding,
        "cross_context": row.cross_context,
        "severity": row.severity,
        "snippet": row.snippet,
    }


def _finding_pair(row):
    """A promoted row's reproducible request pair, no raw credentials."""
    return {
        "entry_id": row.entry_id,
        "severity": row.severity,
        "source": {
            "method": row.source_method,
            "url": sanitize_url(row.source_url) if row.source_url else None,
            "path_id": row.source_path_id,
        },
        "sink": {
            "url": sanitize_url(row.sink_url) if row.sink_url else None,
            "identity": row.sink_identity,
        },
        "snippet": row.snippet,
    }


def _oss_json(v):
    cand = v.candidate
    return {
        "candidate_id": cand.id,
        "verdict": v.verdict,
        "entry": _masked_entry(cand.entry.detail),
        "sink": {
            "callee": cand.sink.callee,
            "class": cand.sink.sink_class,
            "site": f"{mask_path(cand.sink.site_file)}:{cand.sink.site_line}",
        },
        "entry_site": mask_path(v.candidate.entry.site_file)
                      + f":{v.candidate.entry.site_line}",
        "reason": v.reason,
        "predicted": v.predicted,
        "bind": (
            {
                "request_index": v.bind.request_index,
                "path_id": v.bind.path_id,
            }
            if v.bind is not None else None
        ),
        "jevsec_seed": v.jevsec_seed,
        "hits": [
            {
                "entry_id": r.entry_id,
                "sink_url": sanitize_url(r.sink_url),
                "sink_identity": r.sink_identity,
                "severity": r.severity,
            }
            for r in v.hits
        ],
    }


def _render_json(report, oss=None):
    doc = {
        "flow": [_json_row(r) for r in report.rows],
        "findings": [_finding_pair(r) for r in _findings_rows(report)],
        "counts": dict(report.counts),
        "summary": _summary_line(report.counts),
    }
    if oss is not None:
        doc["oss"] = {
            "fell_back": oss.fell_back,
            "candidate_verdicts": [
                _oss_json(v) for v in oss.candidate_verdicts
            ],
        }
    return json.dumps(doc, indent=2)


_SURFACES = {
    "terminal": _render_terminal,
    "html": _render_html,
    "json": _render_json,
}


def render(report, *, surface="terminal", oss=None):
    """Render a VerdictReport to the chosen surface (terminal, html, or json).

    The flow table, the findings bucket, and the summary line are produced
    together. Every snippet and untrusted cell is escaped per surface; every
    emitted URL is sanitized (R18, R22, R23). ``oss`` is the optional
    ``ossverdict.OssReport``: when present, a candidate-verdict block is
    appended on every surface (SPEC-OSS output shape).
    """
    try:
        renderer = _SURFACES[surface]
    except KeyError:
        raise ValueError(f"unknown surface: {surface!r}")
    return renderer(report, oss)


def render_findings(report, *, surface="terminal"):
    """Render only the findings bucket for the chosen surface."""
    if surface == "terminal":
        return _render_findings_terminal(report)
    if surface == "html":
        return _render_findings_html(report)
    if surface == "json":
        return json.dumps(
            [_finding_pair(r) for r in _findings_rows(report)], indent=2
        )
    raise ValueError(f"unknown surface: {surface!r}")
