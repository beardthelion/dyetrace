"""Tests for U5: per-candidate OSS verdicts (ossverdict)."""

from dyetrace import marker
from dyetrace.ossmap import map_candidates
from dyetrace.ossverdict import (
    VERDICT_KILL,
    VERDICT_NEW_FLOW,
    VERDICT_PROVEN,
    VERDICT_UNEXERCISED,
    VERDICT_UNMAPABLE,
    verdicts,
)
from dyetrace.observe import observe
from dyetrace.plant import Attribution, PlantResult, SkippedRequest
from dyetrace.propagate import Observation, PlantSource, PropagateSource
from dyetrace.session import RecordedRequest
from tests.oss_fixtures import candidate as _cand

RUN_ID = "a1b2"
BASE = "https://app.example.com"


def _req(url=BASE + "/x?q=1", method="GET"):
    return RecordedRequest(method=method, url=url, headers=[], body=None)


def _attr(entry_id, variant, source_index, candidate_ids):
    return Attribution(
        entry_id=entry_id, variant=variant, source_index=source_index,
        method="GET", url=BASE + "/x?q=1", path_id="query:q",
        original_value="1", candidate_ids=candidate_ids,
    )


def _plant_obs(entry_id, variant, *, status=200, body=b"", error=None,
               url=BASE + "/x?q=1"):
    return Observation(
        identity=1, kind="plant", url=url, status=status, body=body,
        headers=[],
        source=PlantSource(entry_id=entry_id, variant=variant,
                           path_id="query:q"),
        error=error, plant_rejected=status is not None and status >= 400,
    )


def _prop_obs(body=b"", *, index=0, url=BASE + "/profile"):
    return Observation(
        identity=1, kind="propagate", url=url, status=200, body=body,
        headers=[], source=PropagateSource(index=index), error=None,
    )


def _token(key, entry_id):
    return marker.build_token(key, RUN_ID, entry_id, marker.new_nonce())


def _run(candidates, requests, plant_result, observations, key, skipped=()):
    """Real observe() over the observations, then the verdict layer."""
    mr = map_candidates(candidates, requests)
    plant_result.skipped.extend(skipped)
    report = observe(observations, plant_result, key, RUN_ID)
    return verdicts(report, observations, plant_result, mr)


def _mk_plant(key, eid="0", cids=("cand-1",), source_index=0):
    """A one-site/raw-variant PlantResult for entry eid."""
    return PlantResult(
        mapping={(eid, "raw"): _attr(eid, "raw", source_index, cids)}
    )


class TestProven:
    def test_tracer_in_executed_plant_response_is_proven(self):
        key = marker.mint_key()
        token = _token(key, "0")
        vs = _run(
            [_cand("cand-1")], [_req()],
            _mk_plant(key),
            [_plant_obs("0", "raw", body=("ok " + token).encode())],
            key,
        )
        assert vs[0].verdict == VERDICT_PROVEN
        assert vs[0].candidate.id == "cand-1"

    def test_proven_outranks_new_flow(self):
        key = marker.mint_key()
        token = _token(key, "0")
        vs = _run(
            [_cand("cand-1")], [_req()],
            _mk_plant(key),
            [
                _plant_obs("0", "raw", body=("ok " + token).encode()),
                _prop_obs(("also " + token).encode()),
            ],
            key,
        )
        assert vs[0].verdict == VERDICT_PROVEN

    def test_shared_route_credits_every_mapped_candidate(self):
        key = marker.mint_key()
        token = _token(key, "0")
        vs = _run(
            [_cand("cand-a"), _cand("cand-b")], [_req()],
            _mk_plant(key, cids=("cand-a", "cand-b")),
            [_plant_obs("0", "raw", body=("ok " + token).encode())],
            key,
        )
        assert all(v.verdict == VERDICT_PROVEN for v in vs)


class TestNewFlow:
    def test_hit_only_off_predicted_is_new_flow(self):
        key = marker.mint_key()
        token = _token(key, "0")
        vs = _run(
            [_cand("cand-1")], [_req()],
            _mk_plant(key),
            [
                _plant_obs("0", "raw"),
                _prop_obs(("stored " + token).encode()),
            ],
            key,
        )
        assert vs[0].verdict == VERDICT_NEW_FLOW
        assert vs[0].jevsec_seed

    def test_tracer_in_rejected_plant_response_is_proven(self):
        """A verified tracer echoed in a >=400 body IS predicted evidence: a
        received response that reflects the input proves the flow ran - the
        common error-based bounty shape."""
        key = marker.mint_key()
        token = _token(key, "0")
        vs = _run(
            [_cand("cand-1")], [_req()],
            _mk_plant(key),
            [_plant_obs("0", "raw", status=404,
                        body=("Cannot GET " + token).encode())],
            key,
        )
        assert vs[0].verdict == VERDICT_PROVEN

    def test_rejected_plant_response_without_tracer_is_not_proven(self):
        """A >=400 response carrying no verified tracer never proves anything:
        error pages are only evidence when the tracer itself surfaces."""
        key = marker.mint_key()
        vs = _run(
            [_cand("cand-1")], [_req()],
            _mk_plant(key),
            [_plant_obs("0", "raw", status=404, body=b"Cannot GET /x")],
            key,
        )
        assert vs[0].verdict != VERDICT_PROVEN

    def test_hit_in_another_candidates_response_is_new_flow(self):
        key = marker.mint_key()
        token = _token(key, "0")
        vs = _run(
            [_cand("cand-1", detail="get /x"), _cand("cand-2", detail="get /y")],
            [_req(), _req(BASE + "/y?q=1")],
            PlantResult(mapping={
                ("0", "raw"): _attr("0", "raw", 0, ("cand-1",)),
                ("1", "raw"): _attr("1", "raw", 1, ("cand-2",)),
            }),
            [
                _plant_obs("0", "raw"),                        # cand-1, no echo
                _plant_obs("1", "raw",
                           body=("leak " + token).encode()),   # cand-2 echoes c1's tracer
            ],
            key,
        )
        by_id = {v.candidate.id: v for v in vs}
        assert by_id["cand-1"].verdict == VERDICT_NEW_FLOW
        assert by_id["cand-2"].verdict == VERDICT_KILL


class TestKill:
    def test_executed_no_hit_is_kill(self):
        key = marker.mint_key()
        vs = _run(
            [_cand("cand-1")], [_req()],
            _mk_plant(key),
            [_plant_obs("0", "raw")],
            key,
        )
        assert vs[0].verdict == VERDICT_KILL

    def test_partial_execution_no_hit_is_kill(self):
        key = marker.mint_key()
        vs = _run(
            [_cand("cand-1")], [_req()],
            _mk_plant(key),
            [
                _plant_obs("0", "raw", status=404),
                _plant_obs("0", "raw", status=200),
            ],
            key,
        )
        assert vs[0].verdict == VERDICT_KILL

    def test_forged_dye_string_is_noise_not_proven(self):
        key = marker.mint_key()
        forged = "DYE-" + RUN_ID + "-0-" + "ab" + "-" + "0" * 64
        vs = _run(
            [_cand("cand-1")], [_req()],
            _mk_plant(key),
            [_plant_obs("0", "raw", body=("x " + forged).encode())],
            key,
        )
        assert vs[0].verdict == VERDICT_KILL


class TestUnexercised:
    def test_all_rejected_is_unexercised(self):
        key = marker.mint_key()
        vs = _run(
            [_cand("cand-1")], [_req()],
            _mk_plant(key),
            [_plant_obs("0", "raw", status=500)],
            key,
        )
        assert vs[0].verdict == VERDICT_UNEXERCISED
        assert vs[0].reason == "server_rejected"

    def test_all_redirected_is_unexercised(self):
        key = marker.mint_key()
        vs = _run(
            [_cand("cand-1")], [_req()],
            _mk_plant(key),
            [_plant_obs("0", "raw", status=302)],
            key,
        )
        assert vs[0].verdict == VERDICT_UNEXERCISED
        assert vs[0].reason == "redirected"

    def test_mutating_gate_skip_is_unexercised(self):
        key = marker.mint_key()
        vs = _run(
            [_cand("cand-1", detail="route /x")], [_req(method="POST")],
            _mk_plant(key),
            [],
            key,
            skipped=[SkippedRequest("POST", BASE + "/x?q=1", 0)],
        )
        assert vs[0].verdict == VERDICT_UNEXERCISED
        assert vs[0].reason == "mutating_gate"

    def test_leafless_request_is_unexercised_no_leaves(self):
        key = marker.mint_key()
        vs = _run(
            [_cand("cand-1", detail="get /")], [_req(url=BASE + "/")],
            _mk_plant(key),
            [],
            key,
        )
        assert vs[0].verdict == VERDICT_UNEXERCISED
        assert vs[0].reason == "no_leaves"


class TestUnmapable:
    def test_unmapable_passthrough(self):
        key = marker.mint_key()
        vs = _run(
            [_cand("cand-1", kind="exported")], [_req()],
            _mk_plant(key, cids=()),
            [],
            key,
        )
        assert vs[0].verdict == VERDICT_UNMAPABLE
        assert vs[0].reason


class TestUnexercisedReasons:
    def test_transport_error_reason(self):
        key = marker.mint_key()
        vs = _run(
            [_cand("cand-1")], [_req()],
            _mk_plant(key),
            [_plant_obs("0", "raw", status=None, error="connection")],
            key,
        )
        assert vs[0].verdict == VERDICT_UNEXERCISED
        assert vs[0].reason == "transport_error"

    def test_mixed_failures_report_compound_reason(self):
        key = marker.mint_key()
        vs = _run(
            [_cand("cand-1")], [_req()],
            _mk_plant(key),
            [
                _plant_obs("0", "raw", status=None, error="timeout"),
                _plant_obs("0", "raw", status=500),
            ],
            key,
        )
        assert vs[0].verdict == VERDICT_UNEXERCISED
        assert vs[0].reason == "transport_error+server_rejected"


class TestPredictedSurfaceBoundaries:
    def test_same_route_propagate_replay_hit_is_new_flow_not_proven(self):
        """A stored tracer echoed by the UNPLANTED replay of the candidate's
        own route is off-predicted: predicted surfaces are the plant responses
        themselves."""
        key = marker.mint_key()
        token = _token(key, "0")
        vs = _run(
            [_cand("cand-1")], [_req()],
            _mk_plant(key),
            [
                _plant_obs("0", "raw"),                       # plant: no echo
                Observation(
                    identity=1, kind="propagate",
                    url=BASE + "/x?q=1", status=200,
                    body=("stored " + token).encode(),
                    headers=[], source=PropagateSource(index=0),
                    error=None,
                ),
            ],
            key,
        )
        assert vs[0].verdict == VERDICT_NEW_FLOW

    def test_header_only_hit_on_executed_plant_is_new_flow_not_proven(self):
        """A tracer echoed in a response HEADER of the predicted plant (200)
        is weaker evidence than a body echo: new_flow, never PROVEN."""
        key = marker.mint_key()
        token = _token(key, "0")
        vs = _run(
            [_cand("cand-1")], [_req()],
            _mk_plant(key),
            [_plant_obs("0", "raw", status=200)],
            key,
        )
        # Rebuild with a header echo (plant_obs helper has no headers param)
        obs = _plant_obs("0", "raw", status=200)
        obs.headers = [("x-request-id", token)]
        report = observe([obs], _mk_plant(key), key, RUN_ID)
        mr = map_candidates([_cand("cand-1")], [_req()])
        vs = verdicts(report, [obs], _mk_plant(key), mr)
        assert vs[0].verdict == VERDICT_NEW_FLOW

    def test_off_route_path_plant_cannot_prove(self):
        """A path-segment site rewrites the URL to a different route; a 2xx
        echo there is not the predicted surface."""
        key = marker.mint_key()
        token = _token(key, "0")
        obs = Observation(
            identity=1, kind="plant",
            url=BASE + "/x/" + token, status=200,
            body=("fallback " + token).encode(), headers=[],
            source=PlantSource(entry_id="0", variant="raw",
                               path_id="path:x"),
            error=None,
        )
        pr = PlantResult(mapping={
            ("0", "raw"): Attribution(
                entry_id="0", variant="raw", source_index=0,
                method="GET", url=BASE + "/x?q=1",
                path_id="path:x", original_value="x",
                candidate_ids=("cand-1",),
            )
        })
        mr = map_candidates([_cand("cand-1")], [_req()])
        vs = verdicts(observe([obs], pr, key, RUN_ID), [obs], pr, mr)
        assert vs[0].verdict == VERDICT_NEW_FLOW


class TestMultiRequestUnion:
    def test_hit_on_second_mapped_request_is_proven(self):
        key = marker.mint_key()
        token = _token(key, "1")
        pr = PlantResult(mapping={
            ("0", "raw"): _attr("0", "raw", 0, ("cand-1",)),
            ("1", "raw"): _attr("1", "raw", 1, ("cand-1",)),
        })
        mr = map_candidates(
            [_cand("cand-1", detail="route /x")],
            [_req(), _req(BASE + "/x?z=2")],
        )
        obs = [
            _plant_obs("0", "raw"),
            _plant_obs("1", "raw", body=("hit " + token).encode(),
                       url=BASE + "/x?z=2"),
        ]
        vs = verdicts(observe(obs, pr, key, RUN_ID), obs, pr, mr)
        assert vs[0].verdict == VERDICT_PROVEN

    def test_verdicts_preserve_candidate_file_order(self):
        key = marker.mint_key()
        vs = _run(
            [
                _cand("cand-unmapped", kind="exported"),
                _cand("cand-k", detail="get /x"),
            ],
            [_req()],
            _mk_plant(key, cids=("cand-k",)),
            [_plant_obs("0", "raw")],
            key,
        )
        assert [v.candidate.id for v in vs] == ["cand-unmapped", "cand-k"]


class TestKillReason:
    def test_kill_differing_from_replay_baseline(self):
        key = marker.mint_key()
        vs = _run(
            [_cand("cand-1")], [_req()],
            _mk_plant(key),
            [
                _plant_obs("0", "raw", body=b"processed"),
                _prop_obs(b"ok"),
            ],
            key,
        )
        assert vs[0].verdict == VERDICT_KILL
        assert vs[0].reason == "differing_response"

    def test_kill_identical_to_replay_baseline(self):
        """P0-3: a plant response byte-identical to the unplanted replay is
        soft-200 evidence - the input may never have reached a handler, so
        the verdict is unexercised, not KILL."""
        key = marker.mint_key()
        vs = _run(
            [_cand("cand-1")], [_req()],
            _mk_plant(key),
            [
                _plant_obs("0", "raw", body=b"ok"),
                _prop_obs(b"ok"),
            ],
            key,
        )
        assert vs[0].verdict == VERDICT_UNEXERCISED
        assert vs[0].reason == "identical_response"

    def test_kill_no_baseline(self):
        key = marker.mint_key()
        vs = _run(
            [_cand("cand-1")], [_req()],
            _mk_plant(key),
            [_plant_obs("0", "raw")],
            key,
        )
        assert vs[0].reason == "no_baseline"


class TestPredictedSurfaces:
    def test_predicted_propagate_surface_proven(self):
        """bind predicted="propagate:N": a tracer resurfacing on the unplanted
        replay of recorded request N is PROVEN even though the candidate's own
        plant response did not echo (second-order flow)."""
        key = marker.mint_key()
        token = _token(key, "0")
        cands = [_cand("cand-1")]
        reqs = [_req(), _req(BASE + "/profile")]
        mr = map_candidates(cands, reqs)
        mapped = mr.mapped[0]
        from tests.oss_fixtures import _bind_obj
        mapped.bind = _bind_obj("cand-1", 0, predicted="propagate:1")
        pr = _mk_plant(key)
        obs = [
            _plant_obs("0", "raw"),                          # no echo at plant
            _prop_obs(("stored " + token).encode(), index=1),  # reflect at 1
        ]
        report = observe(obs, pr, key, RUN_ID)
        vs = verdicts(report, obs, pr, mr)
        assert vs[0].verdict == VERDICT_PROVEN
        assert vs[0].predicted == "propagate:1"

    def test_no_predicted_same_case_is_new_flow(self):
        """Regression: the same second-order reflect without a predicted spec
        stays new_flow - plant response is the default predicted surface."""
        key = marker.mint_key()
        token = _token(key, "0")
        vs = _run(
            [_cand("cand-1")], [_req(), _req(BASE + "/profile")],
            _mk_plant(key),
            [
                _plant_obs("0", "raw"),
                _prop_obs(("stored " + token).encode(), index=1),
            ],
            key,
        )
        assert vs[0].verdict == VERDICT_NEW_FLOW
        assert vs[0].predicted == "plant"

    def test_predicted_identity_surface_proven(self):
        key = marker.mint_key()
        token = _token(key, "0")
        cands = [_cand("cand-1")]
        reqs = [_req()]
        mr = map_candidates(cands, reqs)
        from tests.oss_fixtures import _bind_obj
        mr.mapped[0].bind = _bind_obj("cand-1", 0, predicted="identity:2")
        pr = _mk_plant(key)
        obs = [
            _plant_obs("0", "raw"),
            Observation(identity=2, kind="propagate",
                        url=BASE + "/x?q=1", status=200,
                        body=("id2 " + token).encode(), headers=[],
                        source=PropagateSource(index=0), error=None),
        ]
        vs = verdicts(observe(obs, pr, key, RUN_ID), obs, pr, mr)
        assert vs[0].verdict == VERDICT_PROVEN

    def test_predicted_propagate_wrong_index_is_new_flow(self):
        key = marker.mint_key()
        token = _token(key, "0")
        cands = [_cand("cand-1")]
        reqs = [_req(), _req(BASE + "/profile"), _req(BASE + "/home")]
        mr = map_candidates(cands, reqs)
        from tests.oss_fixtures import _bind_obj
        mr.mapped[0].bind = _bind_obj("cand-1", 0, predicted="propagate:2")
        obs = [
            _plant_obs("0", "raw"),
            _prop_obs(("stored " + token).encode(), index=1),  # wrong index
        ]
        vs = verdicts(observe(obs, _mk_plant(key), key, RUN_ID),
                      obs, _mk_plant(key), mr)
        assert vs[0].verdict == VERDICT_NEW_FLOW


class TestPathParamPlants:
    def test_param_substituted_path_plant_can_prove(self):
        """Fix 2: planting the {name} segment of /api/items/{name}/action
        keeps the same handler, so a body echo at the plant response is
        predicted evidence."""
        key = marker.mint_key()
        token = _token(key, "0")
        reqs = [_req(BASE + "/api/items/bob/action?q=1")]
        mr = map_candidates(
            [_cand("cand-1", detail="get /api/items/:name/action")], reqs)
        obs = [Observation(
            identity=1, kind="plant",
            url=BASE + "/api/items/" + token + "/action?q=1",
            status=200, body=("item " + token).encode(), headers=[],
            source=PlantSource(entry_id="0", variant="raw",
                               path_id="path:/api/items/{seg1}/action"),
            error=None)]
        pr = PlantResult(mapping={
            ("0", "raw"): _attr("0", "raw", 0, ("cand-1",))})
        vs = verdicts(observe(obs, pr, key, RUN_ID), obs, pr, mr)
        assert vs[0].verdict == VERDICT_PROVEN

    def test_route_jumping_path_plant_stays_excluded(self):
        """Substituting a literal segment changes which route matches, so the
        plant obs still cannot prove or exercise the candidate."""
        key = marker.mint_key()
        token = _token(key, "0")
        reqs = [_req(BASE + "/api/items/bob/action?q=1")]
        mr = map_candidates(
            [_cand("cand-1", detail="get /api/items/:name/action")], reqs)
        obs = [Observation(
            identity=1, kind="plant",
            url=BASE + "/api/" + token + "/bob/action?q=1",
            status=200, body=("echo " + token).encode(), headers=[],
            source=PlantSource(entry_id="0", variant="raw",
                               path_id="path:/api/{seg1}/bob/action"),
            error=None)]
        pr = PlantResult(mapping={
            ("0", "raw"): _attr("0", "raw", 0, ("cand-1",))})
        vs = verdicts(observe(obs, pr, key, RUN_ID), obs, pr, mr)
        # The tracer still resurfaced somewhere -> new_flow, never PROVEN.
        assert vs[0].verdict == VERDICT_NEW_FLOW

    def test_path_only_plants_report_path_only_reason(self):
        """Leaves existed but all were route-jumping path sites: the reason
        says path_only, not no_leaves."""
        key = marker.mint_key()
        reqs = [_req(BASE + "/x")]   # only writable leaf: the "x" segment
        mr = map_candidates([_cand("cand-1", detail="get /x")], reqs)
        obs = [Observation(
            identity=1, kind="plant",
            url=BASE + "/DYE-anything", status=200, body=b"", headers=[],
            source=PlantSource(entry_id="0", variant="raw",
                               path_id="path:/{seg0}"),
            error=None)]
        pr = PlantResult(mapping={
            ("0", "raw"): _attr("0", "raw", 0, ("cand-1",))})
        vs = verdicts(observe(obs, pr, key, RUN_ID), obs, pr, mr)
        assert vs[0].verdict == VERDICT_UNEXERCISED
        assert vs[0].reason == "path_only"


class TestBoundPathParam:
    def test_bound_fastapi_param_candidate_proven(self):
        """A bind's path: id carries the route template + wildcard position,
        so a param-substituted path plant on a bound non-route candidate is
        predicted evidence, not a route jump."""
        key = marker.mint_key()
        token = _token(key, "0")
        reqs = [_req(BASE + "/api/profiles/bob/open-terminal")]
        cands = [_cand("cand-b", kind="exported", detail="handler")]
        mr = map_candidates(cands, reqs)
        assert not mr.mapped  # unbound: unmapable
        from dyetrace.binds import apply_binds, OperatorBind
        apply_binds(mr, {"cand-b": OperatorBind(
            "cand-b", 0,
            path_id="path:/api/profiles/{seg3}/open-terminal")}, reqs)
        assert mr.mapped[0].route_patterns == [
            "/api/profiles/{seg3}/open-terminal"]
        obs = [Observation(
            identity=1, kind="plant",
            url=BASE + "/api/profiles/" + token + "/open-terminal",
            status=200, body=("profile " + token).encode(), headers=[],
            source=PlantSource(
                entry_id="0", variant="raw",
                path_id="path:/api/profiles/{seg3}/open-terminal"),
            error=None)]
        pr = PlantResult(mapping={
            ("0", "raw"): _attr("0", "raw", 0, ("cand-b",))})
        vs = verdicts(observe(obs, pr, key, RUN_ID), obs, pr, mr)
        assert vs[0].verdict == VERDICT_PROVEN
