"""Egress per-candidate verdicts (plan U7, R10, R11, KTD5, KTD10, KTD12).

Folds the driver's send records and the listener's verified hits into one
verdict per candidate, using the five names from ``ossverdict`` with egress
definitions.

Evidence bar. Exactly one thing proves a flow: a listener-received request
whose PATH contains a token that (a) passes HMAC and run-id verification at the
listener and (b) maps, through the driver's own send record (entry_id and the
full token must both match), to the candidate's send. Status codes, tool result text
(including a token echoed in it), a "success" result, unverified
requests, forged or other-run tokens, and a token in a header or query never
count. A verified token with no matching send record is an anomaly: listed,
never credited, and it marks the run incomplete.

Decision table (rows top to bottom; unexercised reasons combine with ``+``):
unmapable passes through; a verified hit from the candidate's own send is
PROVEN; a verified hit from a send on the same tool but a different argument is
new_flow (the note names the fetched argument); an incomplete run (listener
failed or overflowed, driver stopped, anomaly) is unexercised with
``listener_failed`` or ``run_incomplete``; a send never made is ``not_called``;
a call that ended in tool_error, transport_error, timeout or an invalid-params
error is unexercised with that cause. A non-error call with no hit is KILL
only when ALL of these hold: a settle window of at least 2 s; an operator
reachability attestation; a healthy listener; no interference (no connection
refused by the cap or closed at the head deadline, no unattributed arrival,
and no cut offset list, inside the send's settle window or the final drain
window); and a PUBLIC-class advertised URL. Otherwise the reasons that failed
combine: ``settle_window_too_short``, ``listener_reachability_unconfirmed``,
``listener_saturated``, ``unattributed_arrival``,
``local_class_only_no_arrival`` (loopback or private class: a guard that
refuses local targets but fetches public ones is the common SSRF fix, so a
silent local probe clears nothing).

Independently of windows, any head closed silently as oversize or malformed, and
any unverified arrival or bad head carrying this run's ``DYE-<run_id>`` prefix,
anywhere in the run, makes every would-be KILL ``unattributed_arrival``.

The attestation is operator-asserted and unverified; it is recorded verbatim
with the advertised host:port and the bound port so a stale note is visible.
KILL means no arrival was observed in this harness (http only), not that the
flow is absent. Interference that refuses or deadline-closes a connection
marks the run incomplete, so no send in that run can KILL; the sends it did
not touch are reported ``run_incomplete``. Unattributed arrivals alone do not
mark the run incomplete.
"""

from dataclasses import dataclass, field

from .egressdrive import (
    OUTCOME_NOT_CALLED,
    DriveResult,
    SendRecord,
)
from .ossverdict import (
    VERDICT_KILL,
    VERDICT_NEW_FLOW,
    VERDICT_PROVEN,
    VERDICT_UNEXERCISED,
    VERDICT_UNMAPABLE,
)

__all__ = [
    "VERDICT_PROVEN",
    "VERDICT_NEW_FLOW",
    "VERDICT_KILL",
    "VERDICT_UNEXERCISED",
    "VERDICT_UNMAPABLE",
    "MIN_SETTLE_FOR_KILL",
    "ATTESTATION_LABEL",
    "REASON_LISTENER_FAILED",
    "REASON_RUN_INCOMPLETE",
    "REASON_NOT_CALLED",
    "REASON_SETTLE_TOO_SHORT",
    "REASON_UNCONFIRMED",
    "REASON_SATURATED",
    "REASON_UNATTRIBUTED",
    "REASON_LOCAL_CLASS",
    "REASON_CLASS_UNKNOWN",
    "REASON_NO_ARRIVAL",
    "Attestation",
    "EgressVerdict",
    "EgressVerdictReport",
    "egress_verdicts",
]

MIN_SETTLE_FOR_KILL = 2.0
ATTESTATION_LABEL = "operator-asserted, unverified"

REASON_LISTENER_FAILED = "listener_failed"
REASON_RUN_INCOMPLETE = "run_incomplete"
REASON_NOT_CALLED = "not_called"
REASON_SETTLE_TOO_SHORT = "settle_window_too_short"
REASON_UNCONFIRMED = "listener_reachability_unconfirmed"
REASON_SATURATED = "listener_saturated"
REASON_UNATTRIBUTED = "unattributed_arrival"
REASON_LOCAL_CLASS = "local_class_only_no_arrival"
REASON_CLASS_UNKNOWN = "address_class_unknown"
REASON_NO_ARRIVAL = "no_arrival_observed"

_OUTCOME_REASON = {
    "tool_error": "tool_error",
    "transport_error": "transport_error",
    "timeout": "timeout",
    "invalid_params": "server_rejected_input",
}


@dataclass(frozen=True)
class Attestation:
    """The operator's reachability note, verbatim, with the endpoint it was
    used against. Always labeled operator-asserted and unverified."""

    note: str
    advertised_host: str | None
    advertised_port: int | None
    bound_port: int | None
    label: str = ATTESTATION_LABEL
    operator_asserted_unverified: bool = True


@dataclass
class EgressVerdict:
    """One candidate's outcome and evidence. ``reason`` is a stable token or
    ``+``-joined set (free text for unmapable); ``note`` is new_flow's naming of
    the fetched argument; ``attestation`` is set on verdicts that used it."""

    candidate: object
    verdict: str
    reason: str | None = None
    note: str | None = None
    credited_hits: tuple = ()
    send: SendRecord | None = None
    attestation: Attestation | None = None
    input_index: int = -1


@dataclass
class EgressVerdictReport:
    verdicts: list = field(default_factory=list)
    complete: bool = True
    incomplete_reason: str | None = None
    counts: dict = field(default_factory=dict)
    hits: tuple = ()          # flat list of every verified hit, credited or not
    anomalies: tuple = ()     # verified hits with no matching send record
    attestation: Attestation | None = None
    settle: float = 0.0
    drain: float = 0.0
    source_tools: tuple = ()  # sorted unique (source_tool, source_version)
    stop_reason: str | None = None
    stop_detail: str = ""


def _in_any(offsets, windows) -> bool:
    return any(lo <= o <= hi for o in offsets for lo, hi in windows)


def _windows(rec: SendRecord, drive: DriveResult) -> list:
    out = []
    if rec.window_start is not None and rec.window_end is not None:
        out.append((rec.window_start, rec.window_end))
    if drive.drain_start is not None and drive.drain_end is not None:
        out.append((drive.drain_start, drive.drain_end))
    return out


def _interference(rec, drive, snap) -> list:
    """Interference reasons for this send: refused/deadline-closed connections
    and unattributed arrivals inside its settle window or the drain window. A
    cut offset list cannot be compared, so it counts as interference."""
    wins = _windows(rec, drive)
    sat = unattr = False
    if snap.refused_count or snap.deadline_close_count:
        sat = _in_any(snap.refused_offsets, wins) or _in_any(snap.deadline_close_offsets, wins)
    if snap.unattributed_count:
        unattr = _in_any(snap.unattributed_offsets, wins)
    if snap.offsets_truncated:
        sat = sat or bool(snap.refused_count or snap.deadline_close_count)
        unattr = unattr or bool(snap.unattributed_count)
    reasons = []
    if sat:
        reasons.append(REASON_SATURATED)
    if unattr:
        reasons.append(REASON_UNATTRIBUTED)
    return reasons


def egress_verdicts(map_result, drive: DriveResult, listener, *,
                    attestation: str | None = None,
                    bound_port: int | None = None) -> EgressVerdictReport:
    """Fold a map result, the driver's result and the listener into verdicts.

    ``listener`` needs ``snapshot()`` and ``hits_for(entry_id)``; hits are
    credited via ``hits_for`` and never from anything on the send record.
    ``attestation`` is the operator's note (blank counts as none).
    """
    snap = listener.snapshot()
    note = attestation.strip() if isinstance(attestation, str) else ""
    sends = list(drive.sends)

    by_cand: dict[str, SendRecord] = {}
    for rec in sends:
        for cid in rec.candidate_ids:
            by_cand[cid] = rec

    # Credit by entry_id, then require the full token to match the record.
    credited: dict[int, tuple] = {}
    for rec in sends:
        if rec.entry_id is None or rec.token is None:
            continue
        credited[rec.index] = tuple(
            h for h in listener.hits_for(rec.entry_id) if h.token == rec.token)
    credited_all = {c for hs in credited.values() for c in hs}
    anomalies = tuple(h for h in snap.verified_hits if h not in credited_all)

    hard = []
    if snap.health != "ok":
        hard.append("listener_%s" % snap.health)
    if snap.verified_dropped:
        hard.append("verified_hits_dropped")
    if not drive.complete:
        hard.append(drive.stop_reason or "driver_stopped")
    if anomalies:
        hard.append("anomalous_verified_token")
    listener_bad = snap.health != "ok" or bool(snap.verified_dropped)
    hard_reason = REASON_LISTENER_FAILED if listener_bad else REASON_RUN_INCOMPLETE

    interfered = {}
    for rec in sends:
        if rec.outcome == OUTCOME_NOT_CALLED:
            continue
        r = _interference(rec, drive, snap)
        if r:
            interfered[rec.index] = r
    saturated = any(REASON_SATURATED in r for r in interfered.values())

    # A head the listener closed silently (oversize, malformed or truncated), an
    # unverified arrival carrying this run's prefix, or a connection still being
    # served at fold time, at ANY offset, could be the target's fetch: no KILL
    # may stand. Denies a KILL, never creates one.
    global_unattr = bool(snap.oversize_closed or snap.malformed_closed
                         or snap.prefixed_count or snap.active_connections)

    def att_for(rec):
        if not note:
            return None
        return Attestation(note, rec.advertised_host, rec.advertised_port, bound_port)

    with_credit = [(r, credited[r.index]) for r in sends if credited.get(r.index)]

    out = []
    for m in map_result.mapped:
        rec = by_cand.get(m.candidate.id)
        if rec is None:
            raise ValueError("mapped candidate %r has no send record" % m.candidate.id)
        v = EgressVerdict(candidate=m.candidate, verdict=VERDICT_UNEXERCISED,
                          send=rec, input_index=m.input_index)
        own = credited.get(rec.index, ())
        if own:
            v.verdict, v.credited_hits = VERDICT_PROVEN, own
            out.append(v)
            continue
        other = [(r, hs) for r, hs in with_credit
                 if r.index != rec.index and r.tool == rec.tool
                 and r.argument != rec.argument]
        if other:
            args = sorted({r.argument for r, _ in other})
            v.verdict = VERDICT_NEW_FLOW
            v.credited_hits = tuple(h for _, hs in other for h in hs)
            v.note = "fetched argument: %s (predicted %s)" % (", ".join(args), rec.argument)
            out.append(v)
            continue
        if hard:
            v.reason = hard_reason
        elif rec.outcome == OUTCOME_NOT_CALLED:
            v.reason = REASON_NOT_CALLED
        elif rec.outcome != "result":
            v.reason = _OUTCOME_REASON.get(rec.outcome, "transport_error")
        else:
            reasons = []
            if drive.settle < MIN_SETTLE_FOR_KILL:
                reasons.append(REASON_SETTLE_TOO_SHORT)
            if not note:
                reasons.append(REASON_UNCONFIRMED)
            reasons += interfered.get(rec.index, [])
            if global_unattr and REASON_UNATTRIBUTED not in reasons:
                reasons.append(REASON_UNATTRIBUTED)
            if rec.address_class in ("loopback", "private"):
                reasons.append(REASON_LOCAL_CLASS)
            elif rec.address_class != "public":
                reasons.append(REASON_CLASS_UNKNOWN)
            v.attestation = att_for(rec)
            if reasons:
                v.reason = "+".join(reasons)
            elif saturated:
                # Interference elsewhere marked the run incomplete: no KILL.
                v.reason = REASON_RUN_INCOMPLETE
            else:
                v.verdict, v.reason = VERDICT_KILL, REASON_NO_ARRIVAL
        out.append(v)

    for u in map_result.unmapable:
        out.append(EgressVerdict(candidate=u.candidate, verdict=VERDICT_UNMAPABLE,
                                 reason=u.reason, input_index=u.input_index))
    out.sort(key=lambda v: v.input_index)

    incomplete = list(hard)
    if saturated:
        incomplete.append(REASON_SATURATED)
    counts: dict = {}
    for v in out:
        counts[v.verdict] = counts.get(v.verdict, 0) + 1
    tools = sorted({(v.candidate.source_tool, v.candidate.source_version)
                    for v in out})
    first = next((r for r in sends if r.advertised_host is not None), None)
    top = (Attestation(note, first.advertised_host if first else None,
                       first.advertised_port if first else None, bound_port)
           if note else None)
    return EgressVerdictReport(
        verdicts=out, complete=not incomplete,
        incomplete_reason="+".join(incomplete) if incomplete else None,
        counts=counts, hits=tuple(snap.verified_hits), anomalies=anomalies,
        attestation=top, settle=drive.settle, drain=drive.drain,
        source_tools=tuple(tools), stop_reason=drive.stop_reason,
        stop_detail=drive.stop_detail,
    )
