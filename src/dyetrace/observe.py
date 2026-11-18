"""U7 observe and verdict classifier.

Greps every response body and header VALUE for canonical tracers, authenticates
each candidate by HMAC recomputation (never by narration, R4/KTD2/KTD3), resolves
its encoding variant, and classifies every planted tracer into exactly one of the
four R5 outcomes, kept distinct and never collapsed (KTD11):

    never_resurfaced  (a) planted, plant succeeded, never seen again
    noise             (b) a DYE-shaped string that failed HMAC verify
    resurfaced        (c) parsed, verified, and present in a watched context
    plant_rejected    (d) the plant itself was rejected or failed, so a later
                          "never resurfaced" says nothing (KTD16/KTD17)

Watched sink context (R4/KTD18): the response body bytes and the header VALUES of
every plant and propagate Observation. A tracer is "in a watched context" when
its canonical token (or a full variant payload) appears verbatim in one of those.

``re`` is used only to locate DYE-shaped candidate substrings; it is never the
authenticator. Every candidate is run through ``marker.verify`` with the per-run
key before it is believed. The matched snippet is held VERBATIM for U8 to escape;
nothing here renders or escapes it.
"""

import re
from dataclasses import dataclass, field

from . import marker

__all__ = [
    "OUTCOME_NEVER",
    "OUTCOME_NOISE",
    "OUTCOME_RESURFACED",
    "OUTCOME_PLANT_REJECTED",
    "SEVERITY_INJECTION",
    "SEVERITY_CROSS_CONTEXT",
    "SEVERITY_TRACKED",
    "SEVERITY_NOISE",
    "FlowRow",
    "VerdictReport",
    "observe",
]

# The four R5 outcomes, as distinct string constants so no two can be folded.
OUTCOME_NEVER = "never_resurfaced"        # (a)
OUTCOME_NOISE = "noise"                   # (b)
OUTCOME_RESURFACED = "resurfaced"         # (c)
OUTCOME_PLANT_REJECTED = "plant_rejected"  # (d)

# Row severities (the producer owns these; report imports them, not literals).
SEVERITY_INJECTION = "injection-candidate"
SEVERITY_CROSS_CONTEXT = "cross-context"
SEVERITY_TRACKED = "tracked"
SEVERITY_NOISE = "noise"

# Canonical token shape: DYE-<hex>-<hex>-<hex>-<64 hex>. The trailing lookahead
# keeps the 64-hex MAC from being clipped when more hex immediately follows.
_TOKEN_RE = re.compile(
    r"DYE-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+-[0-9a-f]{64}(?![0-9a-f])"
)

# Every v1 plant is driven as identity 1 (propagate.drive, Phase 1).
_SOURCE_IDENTITY = 1


@dataclass
class FlowRow:
    """One row per resurfacing (R10), or one per forged-noise sink hit.

    For a verified hit the source_* fields attribute it back to the planted site
    (from the plant mapping Attribution); for a noise row they are None. The
    snippet is the verbatim matched text, NOT escaped or rendered: U8 escapes it.
    """

    entry_id: str | None
    source_method: str | None
    source_url: str | None
    source_path_id: str | None
    source_identity: int | None
    sink_url: str
    sink_identity: int
    encoding: str | None   # resolved variant for a hit; None for noise
    cross_context: bool
    severity: str          # injection-candidate | cross-context | tracked | noise
    outcome: str           # OUTCOME_RESURFACED or OUTCOME_NOISE
    snippet: str           # verbatim matched payload/token, unescaped
    sink_obs_index: int = -1  # which observation produced this row (-1: unset)
    sink_context: str = "body"  # "body" or "header" - which surface echoed it


@dataclass
class VerdictReport:
    """What U8 consumes: the flow rows, the per-entry outcome, and the counts."""

    rows: list = field(default_factory=list)
    outcomes: dict = field(default_factory=dict)   # entry_id -> OUTCOME_* (a/c/d)
    counts: dict = field(default_factory=dict)      # OUTCOME_* + "universe" -> int


def _decode(data):
    """Defensive latin-1 decode for matching: every byte maps to one char and
    the ASCII tracer/wrapper bytes survive unchanged, so substring matching of a
    variant payload against the decoded text is exact."""
    if isinstance(data, bytes):
        return data.decode("latin-1")
    return data if isinstance(data, str) else ""


def _search_targets(obs):
    """The watched contexts of one Observation: the body plus each header
    VALUE. Yields (context, text) pairs so a hit knows which kind of surface
    produced it."""
    yield "body", _decode(obs.body)
    for _name, value in obs.headers:
        yield "header", _decode(value)


def _variant_payloads(key, parsed, cache):
    """The four variant payloads for a tracer, memoized per (entry_id, nonce).

    build_variants is pure and the run key is fixed, so caching avoids rebuilding
    an identical payload set (and recomputing its HMAC) for every occurrence of
    the same tracer across bodies and identities.
    """
    cache_key = (parsed["entry_id"], parsed["nonce"])
    payloads = cache.get(cache_key)
    if payloads is None:
        records = marker.build_variants(
            key, parsed["run_id"], parsed["entry_id"], parsed["nonce"]
        )
        payloads = {r["variant"]: r["payload"] for r in records}
        cache[cache_key] = payloads
    return payloads


def _resolve_variant(payloads, text):
    """Return (variant, payload): the most specific variant whose FULL payload
    appears verbatim in ``text``. A markup-breaking wrapper means the token
    surfaced unescaped; otherwise it fell back to the bare canonical token (raw).
    """
    for variant in marker.VARIANTS:
        if variant == "raw":
            continue
        if payloads[variant] in text:
            return variant, payloads[variant]
    return "raw", payloads["raw"]


def _plant_status(observations):
    """entry_ids whose plant was rejected or failed (KTD16/KTD17): any plant
    Observation with plant_rejected, a typed error, or no status is not a clean
    miss for that tracer."""
    rejected = set()
    for obs in observations:
        if obs.kind != "plant":
            continue
        if obs.plant_rejected or obs.error is not None or obs.status is None:
            rejected.add(obs.source.entry_id)
    return rejected


def observe(observations, plant_result, key, run_id):
    """Classify every planted tracer and emit one flow row per resurfacing.

    ``observations`` are the uniform Observations from U6; ``plant_result.mapping``
    (keyed by (entry_id, variant)) is the watched universe; ``key`` and ``run_id``
    are the per-run secret and id. Returns a VerdictReport.
    """
    # Universe of planted tracers, keyed by entry_id, with a representative
    # Attribution for source attribution (all variants of an entry share a site).
    universe = {}
    for (entry_id, _variant), attribution in plant_result.mapping.items():
        universe.setdefault(entry_id, attribution)

    rejected = _plant_status(observations)
    resurfaced = set()
    rows = []
    payload_cache = {}

    for obs_index, obs in enumerate(observations):
        for sink_context, text in _search_targets(obs):
            for match in _TOKEN_RE.finditer(text):
                candidate = match.group(0)
                if not marker.verify(candidate, key):
                    # (b) DYE-shaped but not ours: sink-attributed noise.
                    rows.append(
                        FlowRow(
                            entry_id=None,
                            source_method=None,
                            source_url=None,
                            source_path_id=None,
                            source_identity=None,
                            sink_url=obs.url,
                            sink_identity=obs.identity,
                            encoding=None,
                            cross_context=False,
                            severity=SEVERITY_NOISE,
                            outcome=OUTCOME_NOISE,
                            snippet=candidate,
                            sink_obs_index=obs_index,
                            sink_context=sink_context,
                        )
                    )
                    continue

                parsed = marker.parse(candidate)
                entry_id = parsed["entry_id"]
                attribution = universe.get(entry_id)
                payloads = _variant_payloads(key, parsed, payload_cache)
                variant, payload = _resolve_variant(payloads, text)
                cross_context = obs.identity != _SOURCE_IDENTITY
                if variant != "raw":
                    severity = SEVERITY_INJECTION
                elif cross_context:
                    severity = SEVERITY_CROSS_CONTEXT
                else:
                    severity = SEVERITY_TRACKED

                rows.append(
                    FlowRow(
                        entry_id=entry_id,
                        source_method=attribution.method if attribution else None,
                        source_url=attribution.url if attribution else None,
                        source_path_id=attribution.path_id if attribution else None,
                        source_identity=_SOURCE_IDENTITY,
                        sink_url=obs.url,
                        sink_identity=obs.identity,
                        encoding=variant,
                        cross_context=cross_context,
                        severity=severity,
                        outcome=OUTCOME_RESURFACED,
                        snippet=payload,
                        sink_obs_index=obs_index,
                        sink_context=sink_context,
                    )
                )
                resurfaced.add(entry_id)

    # Per-entry R5 outcome: resurfaced wins; else a rejected/failed plant is (d);
    # else a clean (a) miss.
    outcomes = {}
    for entry_id in universe:
        if entry_id in resurfaced:
            outcomes[entry_id] = OUTCOME_RESURFACED
        elif entry_id in rejected:
            outcomes[entry_id] = OUTCOME_PLANT_REJECTED
        else:
            outcomes[entry_id] = OUTCOME_NEVER

    # A propagate observation that errored, never got a status, or returned a
    # non-success did not actually read its surface. A tracer that then never
    # resurfaces is inconclusive for that surface, not a proven clean miss, so
    # the count lets the report label an incomplete run instead of "no leaks".
    propagation_failures = sum(
        1
        for obs in observations
        if obs.kind == "propagate"
        and (obs.error is not None or obs.status is None or obs.status >= 400)
    )

    counts = {
        OUTCOME_NEVER: sum(1 for o in outcomes.values() if o == OUTCOME_NEVER),
        OUTCOME_RESURFACED: sum(
            1 for o in outcomes.values() if o == OUTCOME_RESURFACED
        ),
        OUTCOME_PLANT_REJECTED: sum(
            1 for o in outcomes.values() if o == OUTCOME_PLANT_REJECTED
        ),
        OUTCOME_NOISE: sum(1 for r in rows if r.outcome == OUTCOME_NOISE),
        "propagation_failures": propagation_failures,
        "universe": len(universe),
    }

    return VerdictReport(rows=rows, outcomes=outcomes, counts=counts)
