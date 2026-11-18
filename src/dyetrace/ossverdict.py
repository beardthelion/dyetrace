"""OSS-mode per-candidate verdicts (SPEC-OSS pipeline step 6, plan KTD4/KTD5).

Layers the PROVEN / new_flow / KILL / unexercised / unmapable framing over the
observer's four tracer outcomes; the observer itself is unchanged.

Predicted sink surface: the code-level sink is not directly observable over
HTTP, so the honest proxy is the response of the request that drives its
handler - the candidate's own plant observations. On the default ``plant``
surface any received response body counts: a verified tracer echoed in a 4xx
body proves the flow ran (the common error-based bounty shape). Named
``propagate:``/``identity:`` surfaces still require an executed (2xx, no
transport error) observation.

Priority per candidate: PROVEN (verified hit in an executed predicted
response) outranks new_flow (verified hits only off-predicted), which both
outrank the no-hit verdicts: unexercised when nothing reached the handler,
KILL when at least one plant executed and no verified hit exists anywhere.
Unmapable candidates were never planted and pass through with their reason.
"""

from dataclasses import dataclass, field

from .masking import sanitize_url
from .observe import OUTCOME_RESURFACED, VerdictReport
from urllib.parse import urlsplit

from .ossmap import MapResult, _path_matches
from .propagate import Observation

__all__ = [
    "VERDICT_PROVEN",
    "VERDICT_NEW_FLOW",
    "VERDICT_KILL",
    "VERDICT_UNEXERCISED",
    "VERDICT_UNMAPABLE",
    "CandidateVerdict",
    "OssReport",
    "verdicts",
]

VERDICT_PROVEN = "PROVEN"
VERDICT_NEW_FLOW = "new_flow"
VERDICT_KILL = "KILL"
VERDICT_UNEXERCISED = "unexercised"
VERDICT_UNMAPABLE = "unmapable"


@dataclass
class CandidateVerdict:
    """One candidate's run outcome plus the evidence behind it. ``candidate``
    is the loaded jevsec record the verdict describes; ``reason`` is a stable
    token (or ``+``-joined set) for unexercised and free text for unmapable."""

    candidate: object
    verdict: str
    reason: str | None = None
    hits: list = field(default_factory=list)   # FlowRow list
    jevsec_seed: str | None = None
    input_index: int = -1  # position in the candidates file (ordering only)
    bind: object | None = None    # OperatorBind when operator-bound
    predicted: str = "plant"      # resolved predicted-surface spec


@dataclass
class OssReport:
    """The OSS run's verdict payload for the report layer."""

    candidate_verdicts: list = field(default_factory=list)
    fell_back: bool = False  # zero-candidate file: ran black-box instead


def _on_route(obs, patterns) -> bool:
    """True when a path-substituted plant URL still matches the candidate's
    route template - the plant swapped a param, not the handler."""
    return any(
        _path_matches(p, urlsplit(obs.url).path or "/") for p in patterns
    )


def _executed(obs: Observation) -> bool:
    """True when the plant actually reached a handler: a real 2xx response,
    no transport error. Redirects and rejections are non-executing.

    Accepted limit: HTTP status alone cannot prove a handler ran. A 200
    block/login/maintenance page that swallows the tracer reads as executed,
    so KILL means "executed by this bar and no observed resurfacing" - it is
    not proof the sink never ran. Narrowing further would need response-shape
    comparison against the unplanted replay, which is a larger contract than
    this layer owns."""
    return (
        obs.error is None
        and obs.status is not None
        and 200 <= obs.status < 300
    )


def _site_str(candidate) -> str:
    return f"{candidate.sink.site_file}:{candidate.sink.site_line}"


def _unexercised_reason(mapped, plant_obs, skipped):
    """Why nothing executed, as a ``+``-joined set of the failure classes
    present: gate-skips, leafless requests, transport errors, redirects, and
    server rejections."""
    reasons = []
    if plant_obs:
        if any(o.error is not None for o in plant_obs):
            reasons.append("transport_error")
        if any(
            o.error is None
            and o.status is not None and 300 <= o.status < 400
            for o in plant_obs
        ):
            reasons.append("redirected")
        if any(
            o.error is None and (o.status is None or o.status >= 400)
            for o in plant_obs
        ):
            reasons.append("server_rejected")
        return "+".join(reasons) if reasons else "server_rejected"
    skipped_idx = {s.source_index for s in skipped}
    mapped_idx = set(mapped.request_indices)
    if mapped_idx & skipped_idx:
        reasons.append("mutating_gate")
    if mapped_idx - skipped_idx:
        reasons.append("no_leaves")
    return "+".join(reasons) if reasons else "no_leaves"


def _kill_reason(mapped, cand_plant_idx, observations):
    """Evidence-strength label for a KILL: did the executed plant response
    differ from the unplanted replay of the same recorded request? A response
    identical to the tracer-free baseline cannot distinguish "handler ran and
    swallowed the tracer" from "the input never reached a handler" - the
    verdict stays KILL (the 2xx bar was met) but the reason says the evidence
    is thin."""
    replays = [
        o for o in observations
        if o.kind == "propagate" and o.source is not None
        and o.source.index in set(mapped.request_indices)
        and o.error is None and o.status is not None
    ]
    if not replays:
        return "no_baseline"
    baseline = {(o.status, o.body) for o in replays}
    differing = any(
        (observations[i].status, observations[i].body) not in baseline
        for i in cand_plant_idx
        if _executed(observations[i])
    )
    return "differing_response" if differing else "identical_response"


def _predicted_hit(row, observations, spec, cand_plant_set):
    """Whether a resurfaced row sits on this candidate's predicted surface.
    ``plant``: the body of a plant response on the candidate's own mapped
    requests where a response was actually received - any status counts, a
    verified tracer echoed in a 4xx body is the common bounty shape.
    ``propagate:<index>``: the body of an unplanted replay of recorded
    request <index> (stored-then-reflected flows). ``identity:<n>``: the body
    of any observation under identity <n>. Header echoes never count as
    predicted hits on any surface - they are weaker evidence than a body
    echo and a soft-2xx header bounce must not prove a flow."""
    if row.sink_context != "body":
        return False
    if not (0 <= row.sink_obs_index < len(observations)):
        return False
    obs = observations[row.sink_obs_index]
    if obs.error is not None or obs.status is None:
        return False
    kind, _, tail = spec.partition(":")
    if kind == "plant":
        return row.sink_obs_index in cand_plant_set
    if kind == "propagate":
        return (
            _executed(obs) and obs.source is not None
            and obs.source.index == int(tail)
        )
    if kind == "identity":
        return _executed(obs) and obs.identity == int(tail)
    return False


def verdicts(report: VerdictReport, observations: list[Observation],
             plant_result, map_result: MapResult,
             predicted_default: str = "plant") -> list[CandidateVerdict]:
    """Fold the observer output into one verdict per candidate.

    ``report`` is the ordinary observe() VerdictReport; ``observations`` are
    the same list the observer consumed (rows reference it by
    ``sink_obs_index``); ``plant_result`` carries the candidate-tagged
    attribution; ``map_result`` carries the U2 mapped/unmapable split.
    """
    # entry_id -> its request index, and candidate id -> entry ids it claimed.
    entry_to_index: dict[str, int] = {}
    cand_to_entries: dict[str, set] = {}
    for (entry_id, _variant), attr in plant_result.mapping.items():
        entry_to_index.setdefault(entry_id, attr.source_index)
        for cid in attr.candidate_ids:
            cand_to_entries.setdefault(cid, set()).add(entry_id)

    # obs index -> the request index a plant observation drove, inverted to
    # request index -> plant obs indexes.
    plant_obs_by_req: dict[int, list] = {}
    for i, obs in enumerate(observations):
        if obs.kind == "plant" and obs.source is not None:
            src = entry_to_index.get(obs.source.entry_id)
            if src is not None:
                plant_obs_by_req.setdefault(src, []).append(i)

    # entry_id -> resurfaced rows mentioning it, preserving row order.
    hits_by_entry: dict[str, list] = {}
    for row in report.rows:
        if row.outcome == OUTCOME_RESURFACED:
            hits_by_entry.setdefault(row.entry_id, []).append(row)

    skipped = list(plant_result.skipped)

    out = []
    for mapped in map_result.mapped:
        cand = mapped.candidate
        cindices = set(mapped.request_indices)
        # A path-segment plant rewrites the URL; it still counts when the
        # substituted segment sits in the route template's param position
        # (the same handler runs - the segment IS the tainted field) but not
        # when it changes which route matches.
        patterns = list(mapped.route_patterns)
        cand_plant_idx = sorted(
            i for idx in cindices for i in plant_obs_by_req.get(idx, [])
            if not observations[i].source.path_id.startswith("path:")
            or _on_route(observations[i], patterns)
        )
        cand_plant_obs = [observations[i] for i in cand_plant_idx]
        cand_plant_set = set(cand_plant_idx)
        hits = [
            r
            for eid in cand_to_entries.get(cand.id, ())
            for r in hits_by_entry.get(eid, [])
        ]
        hits.sort(key=lambda r: r.sink_obs_index)
        # The predicted surface is the candidate's bind-level "predicted"
        # when bound, else the run default (--predicted-surface).
        predicted_spec = (
            mapped.bind.predicted
            if mapped.bind is not None and mapped.bind.predicted
            else predicted_default
        )
        predicted_hits = [
            r for r in hits
            if _predicted_hit(r, observations, predicted_spec, cand_plant_set)
        ]

        verdict, reason, seed = None, None, None
        if predicted_hits:
            verdict = VERDICT_PROVEN
        elif hits:
            verdict = VERDICT_NEW_FLOW
            seed = (
                f"unexpected sink: {sanitize_url(hits[0].sink_url)} "
                f"(predicted {cand.sink.callee} at {_site_str(cand)})"
            )
        elif not any(_executed(o) for o in cand_plant_obs):
            verdict = VERDICT_UNEXERCISED
            # Plants existed but every one was a route-jumping path
            # substitution: leaves were present, just not creditable ones.
            if (not cand_plant_idx
                    and any(plant_obs_by_req.get(idx) for idx in cindices)):
                reason = "path_only"
            else:
                reason = _unexercised_reason(
                    mapped, cand_plant_obs, skipped)
        else:
            kreason = _kill_reason(mapped, cand_plant_idx, observations)
            if kreason == "identical_response":
                # A plant response byte-identical to the unplanted replay
                # cannot distinguish "handler ran and swallowed the tracer"
                # from "input never reached a handler": the 2xx bar was met
                # but no execution evidence exists, so this is unexercised.
                verdict = VERDICT_UNEXERCISED
                reason = kreason
            else:
                verdict = VERDICT_KILL
                reason = kreason
        out.append(CandidateVerdict(
            candidate=cand, verdict=verdict, reason=reason,
            jevsec_seed=seed, hits=hits, input_index=mapped.input_index,
            bind=mapped.bind, predicted=predicted_spec,
        ))

    for unmapped in map_result.unmapable:
        out.append(CandidateVerdict(
            candidate=unmapped.candidate, verdict=VERDICT_UNMAPABLE,
            reason=unmapped.reason, input_index=unmapped.input_index,
        ))

    out.sort(key=lambda v: v.input_index)
    return out
