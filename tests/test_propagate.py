"""Tests for the U6 drive-and-propagate stage.

Test-first: written before src/dyetrace/propagate.py exists, so the import
fails RED until the module is implemented. No real network: a small stub client
exposes ``.send(...)`` and returns a canned httpx.Response or raises a net/httpx
exception, so every scenario is deterministic.

Invariants under test: plant descriptors are driven as identity 1 and a
non-success plant status sets plant_rejected (KTD16); the propagate auto-replay
set is an explicit allowlist {GET, HEAD} plus operator-marked POST read surfaces
minus operator-excluded indices (R8/R24/KTD9); a second identity replays the
same surfaces through its OWN client (KTD13); a per-request failure is recorded
with a typed error string and the run continues (R20); an empty propagation set
stops fail-closed (R17/KTD11).
"""

import httpx
import pytest

from dyetrace.session import Body, MultipartPart, RecordedRequest, Session
from dyetrace.plant import MultipartBody, PlantResult, PlantedRequest, RawBody
from dyetrace.net import AllowlistError
from dyetrace.propagate import (
    EmptyPropagationError,
    Observation,
    PlantSource,
    PropagateSource,
    drive,
)


def _session(requests):
    return Session(
        version="1",
        cookies={},
        auth_headers={},
        base_url="https://app.example.com",
        allowlist_host="app.example.com",
        recorded_requests=requests,
    )


def _req(method, url):
    return RecordedRequest(method=method, url=url, headers=[], body=None)


def _planted(entry_id, variant, url, body=None, method="GET"):
    return PlantedRequest(
        entry_id=entry_id,
        variant=variant,
        method=method,
        url=url,
        headers=[],
        body=body,
        path_id="query:q",
        original_value="orig",
    )


class StubClient:
    """Records every send and returns/raises per a handler(method, url)."""

    def __init__(self, handler):
        self.calls = []
        self._handler = handler

    def send(self, method, url, *, headers=None, content=None, data=None, files=None):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers,
                "content": content,
                "data": data,
                "files": files,
            }
        )
        return self._handler(method, url)


def _ok(status=200, content=b"ok"):
    def handler(method, url):
        return httpx.Response(status, content=content)

    return handler


# --- Happy path ------------------------------------------------------------


def test_happy_three_gets_replay_and_plants_drive():
    session = _session(
        [_req("GET", "https://app.example.com/a?q=1"),
         _req("GET", "https://app.example.com/b?q=2"),
         _req("GET", "https://app.example.com/c?q=3")]
    )
    plant_result = PlantResult(
        planted=[
            _planted("0", "raw", "https://app.example.com/a?q=TRACER"),
            _planted("1", "b64", "https://app.example.com/b?q=TRACER"),
        ]
    )
    client1 = StubClient(_ok())

    obs = drive(session, plant_result, client1)

    plants = [o for o in obs if o.kind == "plant"]
    props = [o for o in obs if o.kind == "propagate"]
    assert len(plants) == 2
    assert len(props) == 3
    assert all(o.identity == 1 for o in obs)
    assert all(o.status == 200 for o in obs)
    assert all(o.error is None for o in obs)
    assert all(o.plant_rejected is False for o in obs)
    assert all(isinstance(o.source, PlantSource) for o in plants)
    assert all(isinstance(o.source, PropagateSource) for o in props)
    assert {o.source.index for o in props} == {0, 1, 2}
    assert plants[0].source.entry_id == "0"
    assert plants[0].source.variant == "raw"
    # Every send ran through the identity-1 client.
    assert len(client1.calls) == 5


# --- Negative: method gate is an allowlist --------------------------------


def test_unmarked_post_and_custom_verb_not_autofired_marked_post_is():
    session = _session(
        [_req("GET", "https://app.example.com/read?q=1"),      # 0 auto
         _req("POST", "https://app.example.com/write"),        # 1 unmarked -> no
         _req("WOBBLE", "https://app.example.com/custom"),     # 2 custom -> no
         _req("POST", "https://app.example.com/search?q=x")]   # 3 marked -> yes
    )
    client1 = StubClient(_ok())

    obs = drive(session, PlantResult(), client1, read_surface_indices=(3,))

    props = [o for o in obs if o.kind == "propagate"]
    assert {o.source.index for o in props} == {0, 3}
    # The unmarked POST and the custom verb never left the process.
    sent_urls = {c["url"] for c in client1.calls}
    assert "https://app.example.com/write" not in sent_urls
    assert "https://app.example.com/custom" not in sent_urls


def test_excluded_index_removes_an_otherwise_auto_surface():
    session = _session(
        [_req("GET", "https://app.example.com/a?q=1"),
         _req("GET", "https://app.example.com/b?q=2")]
    )
    client1 = StubClient(_ok())

    obs = drive(session, PlantResult(), client1, excluded_indices=(1,))

    props = [o for o in obs if o.kind == "propagate"]
    assert {o.source.index for o in props} == {0}


# --- Edge: second identity -------------------------------------------------


def test_second_identity_replays_same_surfaces_through_its_own_client():
    session = _session(
        [_req("GET", "https://app.example.com/a?q=1"),
         _req("GET", "https://app.example.com/b?q=2")]
    )
    session2 = _session(session.recorded_requests)
    client1 = StubClient(_ok())
    client2 = StubClient(_ok())

    obs = drive(
        session, PlantResult(), client1, identity2=session2, client2=client2
    )

    props = [o for o in obs if o.kind == "propagate"]
    id1 = [o for o in props if o.identity == 1]
    id2 = [o for o in props if o.identity == 2]
    assert {o.source.index for o in id1} == {0, 1}
    assert {o.source.index for o in id2} == {0, 1}
    # Each identity used its OWN client (KTD13).
    assert len(client1.calls) == 2
    assert len(client2.calls) == 2


def test_no_second_identity_means_no_identity2_observations():
    session = _session([_req("GET", "https://app.example.com/a?q=1")])
    client1 = StubClient(_ok())

    obs = drive(session, PlantResult(), client1)

    assert all(o.identity == 1 for o in obs)


# --- Error / continue ------------------------------------------------------


def test_per_request_failures_are_typed_and_the_run_continues():
    session = _session(
        [_req("GET", "https://app.example.com/timeout?q=1"),
         _req("GET", "https://app.example.com/conn?q=2"),
         _req("GET", "https://app.example.com/deny?q=3"),
         _req("GET", "https://app.example.com/ok?q=4")]
    )

    def handler(method, url):
        if "timeout" in url:
            raise httpx.ReadTimeout("slow")
        if "conn" in url:
            raise httpx.ConnectError("refused")
        if "deny" in url:
            raise AllowlistError("host not on allowlist")
        return httpx.Response(200, content=b"ok")

    client1 = StubClient(handler)

    obs = drive(session, PlantResult(), client1)

    props = {o.source.index: o for o in obs if o.kind == "propagate"}
    assert props[0].error == "timeout"
    assert props[0].status is None
    assert props[0].body == b""
    assert props[1].error == "connection"
    assert props[2].error == "allowlist"
    # The run did not abort: the healthy surface still produced an observation.
    assert props[3].error is None
    assert props[3].status == 200


def test_plant_non_success_status_sets_plant_rejected():
    session = _session([_req("GET", "https://app.example.com/a?q=1")])
    plant_result = PlantResult(
        planted=[_planted("0", "raw", "https://app.example.com/write?q=TRACER")]
    )

    def handler(method, url):
        if "write" in url:
            return httpx.Response(403, content=b"forbidden")
        return httpx.Response(200, content=b"ok")

    client1 = StubClient(handler)

    obs = drive(session, plant_result, client1)

    plant_obs = [o for o in obs if o.kind == "plant"]
    assert len(plant_obs) == 1
    assert plant_obs[0].status == 403
    assert plant_obs[0].plant_rejected is True
    assert plant_obs[0].error is None


def test_plant_failure_records_error_and_is_not_plant_rejected():
    session = _session([_req("GET", "https://app.example.com/a?q=1")])
    plant_result = PlantResult(
        planted=[_planted("0", "raw", "https://app.example.com/x?q=TRACER")]
    )

    def handler(method, url):
        if url.endswith("x?q=TRACER"):
            raise httpx.ConnectError("refused")
        return httpx.Response(200, content=b"ok")

    client1 = StubClient(handler)

    obs = drive(session, plant_result, client1)

    plant_obs = [o for o in obs if o.kind == "plant"][0]
    assert plant_obs.error == "connection"
    assert plant_obs.status is None
    assert plant_obs.plant_rejected is False


# --- Fail-closed -----------------------------------------------------------


def test_empty_propagation_set_raises_fail_closed():
    session = _session(
        [_req("POST", "https://app.example.com/write"),
         _req("WOBBLE", "https://app.example.com/custom")]
    )
    client1 = StubClient(_ok())

    with pytest.raises(EmptyPropagationError):
        drive(session, PlantResult(), client1)


def test_excluding_the_only_surface_raises_fail_closed():
    session = _session([_req("GET", "https://app.example.com/a?q=1")])
    client1 = StubClient(_ok())

    with pytest.raises(EmptyPropagationError):
        drive(session, PlantResult(), client1, excluded_indices=(0,))


# --- Observation carries response headers ----------------------------------


def test_observation_carries_ordered_response_headers():
    session = _session([_req("GET", "https://app.example.com/a?q=1")])

    def handler(method, url):
        return httpx.Response(200, content=b"ok", headers={"x-trace": "abc"})

    client1 = StubClient(handler)

    obs = [o for o in drive(session, PlantResult(), client1) if o.kind == "propagate"][0]
    assert ("x-trace", "abc") in obs.headers


# --- Identity isolation on replay (hardening) ------------------------------


def test_replay_strips_identity_headers_so_each_client_owns_auth():
    # A recorded read surface carrying identity-1 Cookie/Authorization must not
    # re-send those when replayed; each IdentityClient supplies its own, so an
    # identity-2 pass is not contaminated by identity-1 credentials.
    req = RecordedRequest(
        method="GET",
        url="https://app.example.com/me",
        headers=[
            ("Cookie", "sessionid=IDENTITY1SECRET"),
            ("Authorization", "Bearer IDENTITY1TOKEN"),
            ("X-Api-Key", "IDENTITY1APIKEY"),
            ("Accept", "application/json"),
        ],
        body=None,
    )
    session = _session([req])
    ok = lambda m, u: httpx.Response(200, content=b"ok")
    client1 = StubClient(ok)
    client2 = StubClient(ok)
    session2 = _session([req])
    drive(
        session,
        PlantResult(),
        client1,
        identity2=session2,
        client2=client2,
    )
    for client in (client1, client2):
        sent = client.calls[0]["headers"]
        names = {n.lower() for n, _ in sent}
        assert "cookie" not in names
        assert "authorization" not in names
        assert "x-api-key" not in names
        assert ("Accept", "application/json") in sent  # non-sensitive survives


def test_marking_a_non_post_method_is_rejected():
    from dyetrace.propagate import MarkedMethodError
    req = RecordedRequest(method="DELETE", url="https://app.example.com/thing/1",
                          headers=[], body=None)
    session = _session([req])
    ok = lambda m, u: httpx.Response(200, content=b"ok")
    with pytest.raises(MarkedMethodError):
        drive(session, PlantResult(), StubClient(ok), read_surface_indices=(0,))


def test_marked_post_read_surface_is_replayed():
    req = _req("POST", "https://app.example.com/graphql")
    session = _session([req])
    ok = lambda m, u: httpx.Response(200, content=b"ok")
    client = StubClient(ok)
    obs = drive(session, PlantResult(), client, read_surface_indices=(0,))
    assert any(o.kind == "propagate" and o.url.endswith("/graphql") for o in obs)


def test_non_httperror_httpx_exception_is_recorded_not_raised():
    # httpx.InvalidURL is not an HTTPError subclass; it must be caught per-request
    # (R20 record-and-continue), not abort the whole drive.
    req = _req("GET", "https://app.example.com/a")
    session = _session([req])
    def boom(method, url):
        raise httpx.InvalidURL("bad url")
    obs = drive(session, PlantResult(), StubClient(boom))
    prop = [o for o in obs if o.kind == "propagate"]
    assert prop and prop[0].status is None and prop[0].error == "request"


def test_allow_empty_surfaces_still_drives_plants():
    """OSS carve-out: an empty read-surface selection must not stop the plant
    phase, because in OSS mode the plant responses are the predicted sinks."""
    session = _session([_req("POST", "https://app.example.com/only-mutating")])
    client = StubClient(_ok())
    obs = drive(
        session,
        PlantResult(planted=[
            _planted("0", "raw", "https://app.example.com/only-mutating",
                     method="POST"),
        ]),
        client,
        allow_empty_surfaces=True,
    )
    assert len(obs) == 1 and obs[0].kind == "plant"
    assert len(client.calls) == 1


def test_allow_empty_surfaces_false_still_raises():
    session = _session([_req("POST", "https://app.example.com/only-mutating")])
    with pytest.raises(EmptyPropagationError):
        drive(session, PlantResult(), StubClient(_ok()))
