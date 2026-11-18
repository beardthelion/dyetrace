"""Egress report and evidence pack (plan U8, R12, KTD3, KTD5, KTD12).

Renders an ``egressverdict.EgressVerdictReport`` on three surfaces (terminal,
html, json). Same discipline as ``report``: strings are held verbatim in the
model and escaped once, at render, for the chosen surface (``terminal_safe``
for a terminal, ``html.escape`` for html, json's own string escaping for json).
Request paths, header values, tool result text, candidate ids, file paths,
symbol and site labels, reasons and the attestation note are all untrusted.

Content: a verdict table; a machine-readable ``coverage`` block (counts per
verdict and the fraction of candidates exercised, derived from the same
verdicts as the table); per PROVEN path an evidence pack (tool, argument,
reproduction call, token, arrivals); the flat verified-hit list; anomalies;
noise and refused-connection counts; an INCOMPLETE banner; and the reporting
block (spec 6.5): version, source tools, target commit, advertised and bind
addresses, settle and drain, the attestation labeled operator-asserted and
unverified with the advertised host:port and bound port beside it, adapter
limits, the http-only limits note, and "A path not reported is not cleared."

Masking. Candidate-derived strings (ids, files, symbols, site labels, reasons)
and every generic URL keep the existing ``masking`` rules. The single
deliberate exception is the PROVEN evidence field: the token and the request
path of each arrival are shown unmasked (escaped per surface, never masked),
because an evidence pack needs the full token (spec 7). The reproduction call
shows only the tracer-bearing argument in full; every static bind value goes
through the existing masking. The same token in any other field (the verdict
row's url, the flat hit list, anomalies) stays masked.
"""

import html
import json
from datetime import datetime, timezone

from . import __version__
from .egressnet import format_hostport
from .egressverdict import (
    ATTESTATION_LABEL,
    VERDICT_KILL,
    VERDICT_NEW_FLOW,
    VERDICT_PROVEN,
    VERDICT_UNEXERCISED,
    VERDICT_UNMAPABLE,
)
from .masking import MASK, is_sensitive_header, mask_path, mask_text, sanitize_url, terminal_safe

__all__ = ["render", "coverage", "NOT_CLEARED", "LIMITS_NOTE", "REPLAY_CAVEAT"]

NOT_CLEARED = "A path not reported is not cleared."
LIMITS_NOTE = (
    "Verdicts are over http only: the listener has no TLS, so tools that "
    "require https are untested. KILL means no arrival was observed in this "
    "harness, not that the flow is absent."
)
REPLAY_CAVEAT = (
    "A network observer of the tracer URL could replay it during the run; "
    "each arrival records source address, time and order, with no "
    "token-to-source binding."
)

_EXERCISED = frozenset((VERDICT_PROVEN, VERDICT_NEW_FLOW, VERDICT_KILL))
_VERDICT_ORDER = (
    VERDICT_PROVEN, VERDICT_NEW_FLOW, VERDICT_KILL, VERDICT_UNEXERCISED, VERDICT_UNMAPABLE,
)


# --- masking helpers ---------------------------------------------------------


def _m(text):
    """Candidate-derived string: existing segment masking, applied per word so
    a secret inside free text (a reason, a note) is caught too."""
    return mask_text("" if text is None else str(text))


def _url(text):
    return sanitize_url(text) if text else ""


def _mask_value(value):
    if isinstance(value, str):
        return mask_text(value)
    if isinstance(value, dict):
        return {mask_text(str(k)): _mask_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_mask_value(v) for v in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return mask_text(str(value))


def _reproduction(send):
    """Reproduction call: only the tracer-bearing argument in full."""
    args = {}
    for k, v in (send.arguments or {}).items():
        if k == send.argument and isinstance(v, str):
            args[k] = v
        else:
            args[mask_text(str(k))] = _mask_value(v)
    return {"tool": send.tool, "arguments": args}


def _source(src):
    try:
        if len(src) >= 2:
            return "%s:%s" % (src[0], src[1])
    except TypeError:
        pass
    return str(src)


def _when(wall):
    try:
        return datetime.fromtimestamp(wall, timezone.utc).isoformat()
    except (OverflowError, ValueError, OSError, TypeError):
        return str(wall)


def _att(a):
    if a is None:
        return None
    return {
        "label": a.label or ATTESTATION_LABEL,
        "note": a.note,
        "advertised": format_hostport(a.advertised_host, a.advertised_port),
        "bound_port": a.bound_port,
    }


# --- model -------------------------------------------------------------------


def coverage(report):
    """Counts per verdict and the fraction of candidates exercised.

    ``exercised`` counts candidates whose verdict is PROVEN, new_flow or KILL
    (the same rule as the CLI exit code); unexercised and unmapable ones do not,
    whatever happened to their send. The counts sum to ``total`` and match the
    verdict table.
    """
    counts = {name: 0 for name in _VERDICT_ORDER}
    exercised = 0
    for v in report.verdicts:
        counts[v.verdict] = counts.get(v.verdict, 0) + 1
        if v.verdict in _EXERCISED:
            exercised += 1
    total = len(report.verdicts)
    return {
        "counts": counts,
        "total": total,
        "exercised": exercised,
        "fraction_exercised": (exercised / total) if total else 0.0,
    }


def _summary(report, cov):
    counts = cov["counts"]
    tail = ", ".join("%s=%d" % (n, counts.get(n, 0)) for n in _VERDICT_ORDER)
    tail += ", exercised=%d/%d" % (cov["exercised"], cov["total"])
    if not report.complete:
        return "INCOMPLETE RUN, not a clean result: %s" % tail
    proven = counts.get(VERDICT_PROVEN, 0)
    if proven:
        return "completed, %d exit path(s) proven: %s" % (proven, tail)
    return "completed, no exit path proven: %s" % tail


def _banner(report):
    if report.complete:
        return ""
    parts = ["INCOMPLETE: %s" % (report.incomplete_reason or "run incomplete")]
    if report.stop_reason:
        parts.append("stop reason: %s" % report.stop_reason)
    if report.stop_detail:
        parts.append(report.stop_detail)
    return "; ".join(parts)


def _hit_row(h, credited_to):
    return {
        "entry_id": h.entry_id,
        "token": _m(h.token),
        "method": h.method,
        "target": _url(h.target),
        "source": _source(h.source),
        "time": _when(h.wall),
        "offset": h.offset,
        "arrival_order": h.arrival_index,
        "via_redirect": getattr(h, "via_redirect", False),
        "credited_to": credited_to,
    }


def _verdict_row(v):
    s = v.send
    c = v.candidate
    return {
        "id": _m(c.id),
        "verdict": v.verdict,
        "reason": _m(v.reason) if v.reason else None,
        "note": _m(v.note) if v.note else None,
        "tool": s.tool if s else None,
        "argument": s.argument if s else None,
        "source_tool": c.source_tool,
        "file": _m(c.file),
        "symbol": _m(c.symbol) if c.symbol else None,
        "site_label": _m(c.site_label) if c.site_label else None,
        "url": _url(s.url) if s and s.url else None,
        "outcome": s.outcome if s else None,
        "attestation": _att(v.attestation),
    }


def _pack(v):
    s = v.send
    arrivals = []
    for h in v.credited_hits:
        arrivals.append({
            "method": h.method,
            "request_path": h.target,  # evidence field: escaped, never masked
            "headers": [[n, MASK if is_sensitive_header(n) else val] for n, val in h.headers],
            "source": _source(h.source),
            "time": _when(h.wall),
            "offset": h.offset,
            "arrival_order": h.arrival_index,
            "via_redirect": getattr(h, "via_redirect", False),
        })
    return {
        "candidate_id": _m(v.candidate.id),
        "tool": s.tool,
        "argument": s.argument,
        "reproduction": _reproduction(s),
        "evidence": {"token": s.token, "arrivals": arrivals},
        "replay_caveat": REPLAY_CAVEAT,
    }


def _noise(snapshot):
    if snapshot is None:
        return None
    return {
        "noise_count": snapshot.noise_count,
        "refused_count": snapshot.refused_count,
        "deadline_close_count": snapshot.deadline_close_count,
        "unattributed_count": snapshot.unattributed_count,
        "oversize_closed": snapshot.oversize_closed,
        "malformed_closed": snapshot.malformed_closed,
        "verified_dropped": snapshot.verified_dropped,
        "redirected_count": getattr(snapshot, "redirected_count", 0),
        "listener_health": snapshot.health,
    }


def _model(report, snapshot, advertised, bind_addr, target_commit, adapter_limits,
           redirect_hop=None):
    cov = coverage(report)
    cred = {}
    for v in report.verdicts:
        if v.send is not None and v.send.entry_id is not None:
            cred.setdefault(v.send.entry_id, []).append(_m(v.candidate.id))
    hits = [_hit_row(h, cred.get(h.entry_id, [])) for h in report.hits]
    anomalies = [_hit_row(h, []) for h in report.anomalies]
    return {
        "report": "dyetrace-egress",
        "schema": 1,
        "status": "complete" if report.complete else "incomplete",
        "complete": report.complete,
        "incomplete_reason": report.incomplete_reason,
        "stop_reason": report.stop_reason,
        "stop_detail": report.stop_detail,
        "banner": _banner(report),
        "summary": _summary(report, cov),
        "coverage": cov,
        "verdicts": [_verdict_row(v) for v in report.verdicts],
        "evidence": [_pack(v) for v in report.verdicts
                     if v.verdict == VERDICT_PROVEN and v.send is not None],
        "hits": hits,
        "anomalies": anomalies,
        "noise": _noise(snapshot),
        "reporting": {
            "dyetrace_version": __version__,
            "source_tools": [{"tool": t, "version": ver} for t, ver in report.source_tools],
            "target_commit": target_commit,
            "advertised": _url(advertised) if advertised else None,
            "bind": bind_addr,
            "redirect_hop": _url(redirect_hop) if redirect_hop else None,
            "settle": report.settle,
            "drain": report.drain,
            "attestation": _att(report.attestation),
            "adapter_limits": [str(x) for x in adapter_limits],
            "limits": LIMITS_NOTE,
            "replay_caveat": REPLAY_CAVEAT,
        },
        "not_cleared": NOT_CLEARED,
    }


# --- terminal ----------------------------------------------------------------


def _att_text(a):
    if a is None:
        return ""
    return "%s: %s [advertised %s, bound port %s]" % (
        a["label"], a["note"], a["advertised"], a["bound_port"])


def _render_terminal(m):
    e = lambda x: terminal_safe(str(x))  # noqa: E731
    out = []
    if m["banner"]:
        out += [e(m["banner"]), ""]
    out += ["dyetrace egress report", e(m["summary"]), "", "coverage:"]
    cov = m["coverage"]
    for name, n in cov["counts"].items():
        out.append("  %s: %d" % (name, n))
    out.append("  exercised: %d of %d (%.2f)" % (
        cov["exercised"], cov["total"], cov["fraction_exercised"]))
    out += ["", "candidate verdicts:"]
    if not m["verdicts"]:
        out.append("  (none)")
    for r in m["verdicts"]:
        line = "  %s | %s | %s/%s | %s:%s" % (
            e(r["id"]), e(r["verdict"]), e(r["tool"] or "-"), e(r["argument"] or "-"),
            e(r["file"]), e(r["symbol"] or "-"))
        if r["site_label"]:
            line += " | site: " + e(r["site_label"])
        if r["reason"]:
            line += " | reason: " + e(r["reason"])
        if r["note"]:
            line += " | " + e(r["note"])
        if r["url"]:
            line += " | url: " + e(r["url"])
        if r["attestation"]:
            line += " | uses attestation (%s)" % e(r["attestation"]["label"])
        out.append(line)
    out += ["", "evidence packs (PROVEN):"]
    if not m["evidence"]:
        out.append("  (none)")
    for p in m["evidence"]:
        out.append("  candidate %s | tool %s | argument %s" % (
            e(p["candidate_id"]), e(p["tool"]), e(p["argument"])))
        out.append("    reproduction: %s %s" % (
            e(p["reproduction"]["tool"]), e(json.dumps(p["reproduction"]["arguments"]))))
        out.append("    token: " + e(p["evidence"]["token"]))
        for a in p["evidence"]["arrivals"]:
            hdrs = "; ".join("%s: %s" % (n, v) for n, v in a["headers"])
            out.append("    arrival #%s %s %s from %s at %s (+%ss)%s headers: %s" % (
                e(a["arrival_order"]), e(a["method"]), e(a["request_path"]),
                e(a["source"]), e(a["time"]), e(a["offset"]),
                " via redirect" if a.get("via_redirect") else "", e(hdrs)))
        out.append("    " + e(p["replay_caveat"]))
    out += ["", "verified hits:"]
    if not m["hits"]:
        out.append("  (none)")
    for h in m["hits"]:
        out.append("  #%s %s %s %s from %s%s credited to: %s" % (
            e(h["arrival_order"]), e(h["method"]), e(h["target"]), e(h["token"]),
            e(h["source"]), " via redirect" if h.get("via_redirect") else "",
            e(", ".join(h["credited_to"]) or "-")))
    if m["anomalies"]:
        out += ["", "anomalies (verified token with no matching send, not credited):"]
        for h in m["anomalies"]:
            out.append("  #%s %s %s %s from %s" % (
                e(h["arrival_order"]), e(h["method"]), e(h["target"]), e(h["token"]),
                e(h["source"])))
    n = m["noise"]
    out += ["", "listener counts:"]
    if n is None:
        out.append("  (not available)")
    else:
        out.append("  " + ", ".join("%s=%s" % (k, e(v)) for k, v in n.items()))
    r = m["reporting"]
    out += ["", "reporting:",
            "  dyetrace version: " + e(r["dyetrace_version"]),
            "  candidate sources: " + e(", ".join(
                "%s %s" % (s["tool"], s["version"]) for s in r["source_tools"]) or "-"),
            "  target commit: " + e(r["target_commit"]),
            "  advertised: " + e(r["advertised"] or "-") + "   bind: " + e(r["bind"] or "-"),
            "  settle: %ss   drain: %ss" % (e(r["settle"]), e(r["drain"]))]
    out.append("  attestation: " + (e(_att_text(r["attestation"])) if r["attestation"]
                                    else "none"))
    out.append("  adapter limits: " + e(", ".join(r["adapter_limits"]) or "none"))
    out += ["  " + e(r["limits"]), "  " + e(r["replay_caveat"]), "", e(m["not_cleared"])]
    return "\n".join(out)


# --- html --------------------------------------------------------------------


def _render_html(m):
    e = lambda x: html.escape(str(x))  # noqa: E731
    p = []
    if m["banner"]:
        p.append("<p><strong>%s</strong></p>" % e(m["banner"]))
    p.append("<h1>dyetrace egress report</h1>")
    p.append("<p>%s</p>" % e(m["summary"]))
    cov = m["coverage"]
    p.append("<h2>coverage</h2><ul>")
    for name, n in cov["counts"].items():
        p.append("<li>%s: %d</li>" % (e(name), n))
    p.append("<li>exercised: %d of %d (%.2f)</li></ul>" % (
        cov["exercised"], cov["total"], cov["fraction_exercised"]))
    p.append("<h2>candidate verdicts</h2>")
    if not m["verdicts"]:
        p.append("<p>(none)</p>")
    else:
        p.append("<table><tr><th>candidate</th><th>verdict</th><th>tool/argument</th>"
                 "<th>source</th><th>reason</th><th>url</th><th>attestation</th></tr>")
        for r in m["verdicts"]:
            reason = " ".join(x for x in (r["reason"], r["note"]) if x)
            att = ("uses attestation (%s)" % r["attestation"]["label"]) if r["attestation"] else ""
            p.append("<tr><td>%s</td><td>%s</td><td>%s/%s</td><td>%s:%s %s</td>"
                     "<td>%s</td><td>%s</td><td>%s</td></tr>" % (
                         e(r["id"]), e(r["verdict"]), e(r["tool"] or "-"),
                         e(r["argument"] or "-"), e(r["file"]), e(r["symbol"] or "-"),
                         e(r["site_label"] or ""), e(reason), e(r["url"] or ""), e(att)))
        p.append("</table>")
    p.append("<h2>evidence packs (PROVEN)</h2>")
    if not m["evidence"]:
        p.append("<p>(none)</p>")
    for pk in m["evidence"]:
        p.append("<h3>candidate %s</h3><ul>" % e(pk["candidate_id"]))
        p.append("<li>tool: %s, argument: %s</li>" % (e(pk["tool"]), e(pk["argument"])))
        p.append("<li>reproduction: <code>%s %s</code></li>" % (
            e(pk["reproduction"]["tool"]), e(json.dumps(pk["reproduction"]["arguments"]))))
        p.append("<li>token: <code>%s</code></li>" % e(pk["evidence"]["token"]))
        for a in pk["evidence"]["arrivals"]:
            hdrs = "; ".join("%s: %s" % (n, v) for n, v in a["headers"])
            p.append("<li>arrival #%s %s <code>%s</code> from %s at %s (+%ss)%s, "
                     "headers: %s</li>" % (
                         e(a["arrival_order"]), e(a["method"]), e(a["request_path"]),
                         e(a["source"]), e(a["time"]), e(a["offset"]),
                         " via redirect" if a.get("via_redirect") else "", e(hdrs)))
        p.append("<li>%s</li></ul>" % e(pk["replay_caveat"]))
    p.append("<h2>verified hits</h2>")
    if not m["hits"]:
        p.append("<p>(none)</p>")
    else:
        p.append("<table><tr><th>#</th><th>method</th><th>target</th><th>token</th>"
                 "<th>source</th><th>credited to</th></tr>")
        for h in m["hits"]:
            p.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
                     "<td>%s</td></tr>" % (
                         e(h["arrival_order"]), e(h["method"]), e(h["target"]),
                         e(h["token"]), e(h["source"]), e(", ".join(h["credited_to"]))))
        p.append("</table>")
    if m["anomalies"]:
        p.append("<h2>anomalies (verified token with no matching send, not credited)</h2><ul>")
        for h in m["anomalies"]:
            p.append("<li>#%s %s %s %s from %s</li>" % (
                e(h["arrival_order"]), e(h["method"]), e(h["target"]), e(h["token"]),
                e(h["source"])))
        p.append("</ul>")
    p.append("<h2>listener counts</h2>")
    n = m["noise"]
    p.append("<p>%s</p>" % (e(", ".join("%s=%s" % kv for kv in n.items()))
                            if n else "(not available)"))
    r = m["reporting"]
    p.append("<h2>reporting</h2><ul>")
    p.append("<li>dyetrace version: %s</li>" % e(r["dyetrace_version"]))
    p.append("<li>candidate sources: %s</li>" % e(", ".join(
        "%s %s" % (s["tool"], s["version"]) for s in r["source_tools"]) or "-"))
    p.append("<li>target commit: %s</li>" % e(r["target_commit"]))
    p.append("<li>advertised: %s, bind: %s</li>" % (e(r["advertised"] or "-"), e(r["bind"] or "-")))
    p.append("<li>settle: %ss, drain: %ss</li>" % (e(r["settle"]), e(r["drain"])))
    p.append("<li>attestation: %s</li>" % (
        e(_att_text(r["attestation"])) if r["attestation"] else "none"))
    p.append("<li>adapter limits: %s</li>" % e(", ".join(r["adapter_limits"]) or "none"))
    p.append("<li>%s</li><li>%s</li></ul>" % (e(r["limits"]), e(r["replay_caveat"])))
    p.append("<p>%s</p>" % e(m["not_cleared"]))
    return "\n".join(p)


def _render_json(m):
    return json.dumps(m, indent=2)


_RENDERERS = {"terminal": _render_terminal, "html": _render_html, "json": _render_json}


def render(report, *, surface="terminal", snapshot=None, advertised=None, bind_addr=None,
           target_commit="", adapter_limits=(), redirect_hop=None):
    """Render an ``EgressVerdictReport`` to terminal, html or json.

    ``snapshot`` is the listener's ``ListenerSnapshot`` (noise and refused
    counts; omitted means "not available"). ``advertised`` and ``bind_addr``
    are the operator-facing endpoints, ``target_commit`` the verbatim
    ``--target-commit`` text and ``adapter_limits`` strings such as
    ``analysis_incomplete``. ``redirect_hop`` is the configured
    ``--redirect-hop`` base URL, when the run used redirect mode. Exit-code
    inputs come from ``coverage(report)`` and ``report.complete``.
    """
    try:
        renderer = _RENDERERS[surface]
    except KeyError:
        raise ValueError("unknown surface: %r" % (surface,))
    model = _model(report, snapshot, advertised, bind_addr, target_commit,
                   adapter_limits, redirect_hop)
    return renderer(model)
