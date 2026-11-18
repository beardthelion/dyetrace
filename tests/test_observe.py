"""Tests for the U7 observe-and-verdict stage.

Test-first: written before src/dyetrace/observe.py exists, so the import fails
RED until the module is implemented. No real network: every Observation is hand
built, and every tracer is minted with the real marker core, so each scenario is
deterministic.

Invariants under test: a hit is proven only by HMAC recomputation plus presence
in a watched context (R4/KTD2/KTD3); the four R5 outcomes stay distinct and are
never collapsed into one "no finding" (R5/KTD11); a markup-breaking variant whose
FULL payload surfaces unescaped is an injection candidate, while the same tracer
surfacing only as the bare (escaped) token is a tracked raw leak (KTD18); a
cross-identity surfacing flags cross_context (R10); a plant-rejected or failed
plant is not a clean miss (KTD16/KTD17).
"""

from dyetrace import marker
from dyetrace.plant import Attribution, PlantResult
from dyetrace.propagate import Observation, PlantSource, PropagateSource
from dyetrace.observe import (
    OUTCOME_NEVER,
    OUTCOME_NOISE,
    OUTCOME_PLANT_REJECTED,
    OUTCOME_RESURFACED,
    FlowRow,
    VerdictReport,
    observe,
)

RUN_ID = "a1b2"


def _attr(entry_id, variant, *, method="GET", url="https://app.example.com/x?q=1",
          path_id="query:q", source_index=0, original_value="1"):
    return Attribution(
        entry_id=entry_id,
        variant=variant,
        source_index=source_index,
        method=method,
        url=url,
        path_id=path_id,
        original_value=original_value,
    )


def _plant_obs(entry_id, variant, *, status=200, error=None, plant_rejected=False):
    return Observation(
        identity=1,
        kind="plant",
        url="https://app.example.com/x?q=1",
        status=status,
        body=b"",
        headers=[],
        source=PlantSource(entry_id=entry_id, variant=variant, path_id="query:q"),
        error=error,
        plant_rejected=plant_rejected,
    )


def _propagate_obs(identity, body, *, index=0, url="https://app.example.com/profile",
                   headers=None):
    return Observation(
        identity=identity,
        kind="propagate",
        url=url,
        status=200,
        body=body,
        headers=headers if headers is not None else [],
        source=PropagateSource(index=index),
        error=None,
    )


def _token(key, entry_id, nonce):
    return marker.build_token(key, RUN_ID, entry_id, nonce)


def test_raw_token_reflected_is_a_tracked_leak():
    """Happy: a raw canonical token reflected in a propagate body verifies and
    produces one tracked-leak row attributed to the raw variant, identity 1."""
    key = marker.mint_key()
    nonce = marker.new_nonce()
    token = _token(key, "0", nonce)

    plant_result = PlantResult(mapping={("0", "raw"): _attr("0", "raw")})
    observations = [
        _plant_obs("0", "raw"),
        _propagate_obs(1, ("prefix " + token + " suffix").encode("utf-8")),
    ]

    report = observe(observations, plant_result, key, RUN_ID)

    hits = [r for r in report.rows if r.outcome == OUTCOME_RESURFACED]
    assert len(hits) == 1
    row = hits[0]
    assert row.entry_id == "0"
    assert row.encoding == "raw"
    assert row.severity == "tracked"
    assert row.cross_context is False
    assert row.source_identity == 1
    assert row.sink_identity == 1
    assert row.sink_url == "https://app.example.com/profile"
    assert row.source_method == "GET"
    assert row.source_path_id == "query:q"
    assert token in row.snippet  # verbatim, not escaped/rendered
    assert report.outcomes["0"] == OUTCOME_RESURFACED


def test_token_in_header_value_counts_as_watched_context():
    """R9: header VALUES are a watched sink context, not only the body."""
    key = marker.mint_key()
    nonce = marker.new_nonce()
    token = _token(key, "0", nonce)

    plant_result = PlantResult(mapping={("0", "raw"): _attr("0", "raw")})
    observations = [
        _plant_obs("0", "raw"),
        _propagate_obs(1, b"", headers=[("x-echo", "see " + token)]),
    ]

    report = observe(observations, plant_result, key, RUN_ID)
    hits = [r for r in report.rows if r.outcome == OUTCOME_RESURFACED]
    assert len(hits) == 1
    assert hits[0].entry_id == "0"


def test_unescaped_html_variant_is_injection_candidate_escaped_is_raw():
    """Edge/KTD18: the FULL html-breaking payload reflected unescaped is an
    injection candidate (encoding html); the SAME tracer surfacing only as the
    bare token (breaking chars escaped) is a tracked raw hit, not injection."""
    key = marker.mint_key()
    nonce = marker.new_nonce()
    variants = {r["variant"]: r["payload"]
                for r in marker.build_variants(key, RUN_ID, "0", nonce)}
    token = variants["raw"]
    html_payload = variants["html"]
    assert html_payload != token  # the wrapper really does break markup

    plant_result = PlantResult(mapping={
        ("0", "raw"): _attr("0", "raw"),
        ("0", "html"): _attr("0", "html"),
    })

    # Unescaped full html payload in the body -> injection candidate.
    unescaped = [
        _plant_obs("0", "raw"),
        _propagate_obs(1, ("<p>" + html_payload + "</p>").encode("utf-8")),
    ]
    report = observe(unescaped, plant_result, key, RUN_ID)
    hits = [r for r in report.rows if r.outcome == OUTCOME_RESURFACED]
    assert len(hits) == 1
    assert hits[0].encoding == "html"
    assert hits[0].severity == "injection-candidate"
    assert hits[0].snippet == html_payload  # held verbatim for U8 to escape

    # Same tracer, breaking chars HTML-escaped so only the bare token survives.
    escaped_body = ("&quot;&gt;&lt;dye t=" + token + "&gt;").encode("utf-8")
    escaped = [
        _plant_obs("0", "raw"),
        _propagate_obs(1, escaped_body),
    ]
    report2 = observe(escaped, plant_result, key, RUN_ID)
    hits2 = [r for r in report2.rows if r.outcome == OUTCOME_RESURFACED]
    assert len(hits2) == 1
    assert hits2[0].encoding == "raw"
    assert hits2[0].severity == "tracked"


def test_cross_identity_surfacing_flags_cross_context():
    """Edge: a tracer planted by identity 1 that surfaces in an identity-2
    propagate Observation flags cross_context True (R10)."""
    key = marker.mint_key()
    nonce = marker.new_nonce()
    token = _token(key, "0", nonce)

    plant_result = PlantResult(mapping={("0", "raw"): _attr("0", "raw")})
    observations = [
        _plant_obs("0", "raw"),
        _propagate_obs(2, ("leaked " + token).encode("utf-8")),
    ]

    report = observe(observations, plant_result, key, RUN_ID)
    hits = [r for r in report.rows if r.outcome == OUTCOME_RESURFACED]
    assert len(hits) == 1
    assert hits[0].cross_context is True
    assert hits[0].source_identity == 1
    assert hits[0].sink_identity == 2
    assert hits[0].severity == "cross-context"


def test_four_outcomes_are_distinct():
    """Negative: a bad-MAC DYE string is noise (b), not a leak; a planted tracer
    that appears nowhere with a successful plant is (a); a planted tracer whose
    plant was rejected and never resurfaced is (d), not (a). The four outcomes
    are separately represented and counted, never folded into one."""
    key = marker.mint_key()
    wrong_key = marker.mint_key()

    # (a) planted, plant ok, never resurfaces.
    nonce_a = marker.new_nonce()
    # (d) planted, plant rejected, never resurfaces.
    nonce_d = marker.new_nonce()
    # (b) a DYE-shaped string MAC'd under the wrong key: parses, fails verify.
    forged = marker.build_token(wrong_key, RUN_ID, "9", marker.new_nonce())
    assert marker.parse(forged) is not None
    assert marker.verify(forged, key) is False

    plant_result = PlantResult(mapping={
        ("a", "raw"): _attr("a", "raw"),
        ("d", "raw"): _attr("d", "raw"),
    })
    observations = [
        _plant_obs("a", "raw", status=200),
        _plant_obs("d", "raw", status=403, plant_rejected=True),
        _propagate_obs(1, ("echo " + forged).encode("utf-8")),
    ]

    report = observe(observations, plant_result, key, RUN_ID)

    assert report.outcomes["a"] == OUTCOME_NEVER
    assert report.outcomes["d"] == OUTCOME_PLANT_REJECTED

    noise = [r for r in report.rows if r.outcome == OUTCOME_NOISE]
    assert len(noise) == 1
    assert noise[0].severity == "noise"
    # The forged string must NOT be counted as a verified leak.
    assert all(r.outcome != OUTCOME_RESURFACED for r in report.rows)

    # The three outcomes are distinct values and separately counted.
    assert len({OUTCOME_NEVER, OUTCOME_NOISE, OUTCOME_PLANT_REJECTED}) == 3
    assert report.counts[OUTCOME_NEVER] == 1
    assert report.counts[OUTCOME_PLANT_REJECTED] == 1
    assert report.counts[OUTCOME_NOISE] == 1
    assert report.counts[OUTCOME_RESURFACED] == 0
    assert report.counts["universe"] == 2


def test_failed_plant_is_not_a_clean_miss():
    """KTD17: a plant Observation that failed first (status None, typed error)
    is treated like a rejected plant, not a clean (a) miss."""
    key = marker.mint_key()
    plant_result = PlantResult(mapping={("f", "raw"): _attr("f", "raw")})
    observations = [
        _plant_obs("f", "raw", status=None, error="timeout"),
    ]
    report = observe(observations, plant_result, key, RUN_ID)
    assert report.outcomes["f"] == OUTCOME_PLANT_REJECTED


def test_resurfaced_wins_over_plant_rejected():
    """If a tracer both had a rejected plant and still resurfaced verified, the
    verified resurfacing wins (it is evidence; the rejection no longer gates)."""
    key = marker.mint_key()
    nonce = marker.new_nonce()
    token = _token(key, "0", nonce)
    plant_result = PlantResult(mapping={("0", "raw"): _attr("0", "raw")})
    observations = [
        _plant_obs("0", "raw", status=403, plant_rejected=True),
        _propagate_obs(1, token.encode("utf-8")),
    ]
    report = observe(observations, plant_result, key, RUN_ID)
    assert report.outcomes["0"] == OUTCOME_RESURFACED


def test_report_types():
    """The output contract U8 consumes is stable."""
    key = marker.mint_key()
    plant_result = PlantResult(mapping={("a", "raw"): _attr("a", "raw")})
    report = observe([_plant_obs("a", "raw")], plant_result, key, RUN_ID)
    assert isinstance(report, VerdictReport)
    assert isinstance(report.rows, list)
    assert isinstance(report.outcomes, dict)
    assert isinstance(report.counts, dict)
    assert all(isinstance(r, FlowRow) for r in report.rows)


def test_failed_propagation_surface_is_counted_not_a_clean_miss():
    # A planted tracer that never resurfaces, where the propagation surface that
    # should have shown it actually failed, must register a propagation failure so
    # the report labels the run inconclusive rather than a clean "no leaks".
    key = marker.mint_key()
    run_id = "0a"
    token = marker.build_token(key, run_id, "01", "0f")
    plant_result = PlantResult(
        planted=[], mapping={("01", "raw"): Attribution(
            entry_id="01", variant="raw", source_index=0, method="GET",
            url="https://app.example.com/x", path_id="query:q", original_value="v")},
        skipped=[],
    )
    # One propagate observation that failed (timeout), reflecting nothing.
    obs = [Observation(identity=1, kind="propagate", url="https://app.example.com/x",
                       status=None, body=b"", headers=[], source=PropagateSource(0),
                       error="timeout")]
    report = observe(obs, plant_result, key, run_id)
    assert report.counts["propagation_failures"] == 1
    assert report.counts[OUTCOME_RESURFACED] == 0


def test_rows_record_the_producing_observation_index():
    """U4/OSS: each row names which observation produced it, so the OSS verdict
    layer can tell predicted-surface hits from off-predicted ones."""
    key = marker.mint_key()
    nonce = marker.new_nonce()
    token = _token(key, "0", nonce)
    forged = "DYE-" + RUN_ID + "-0-" + nonce + "-" + "0" * 64

    plant_result = PlantResult(mapping={("0", "raw"): _attr("0", "raw")})
    observations = [
        _plant_obs("0", "raw"),                                    # index 0
        _propagate_obs(1, b"noise: " + forged.encode()),           # index 1
        _propagate_obs(1, ("echo " + token).encode()),             # index 2
    ]
    report = observe(observations, plant_result, key, RUN_ID)

    hit = next(r for r in report.rows if r.outcome == OUTCOME_RESURFACED)
    assert hit.sink_obs_index == 2
    noise = next(r for r in report.rows if r.outcome == OUTCOME_NOISE)
    assert noise.sink_obs_index == 1
