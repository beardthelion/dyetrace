"""U9 end-to-end harness (R16, R17).

Runs the packaged CLI (``cli.main``) against a local in-process HTTP target and
asserts the stages agree: plant -> propagate -> observe -> report. No byte
leaves the process and no real DNS runs: an httpx ``MockTransport`` is injected
as the transport for every IdentityClient, and a fake resolver pins a safe
public address for the allowlisted host.

The target is a tiny stateful store-then-reflect app. The tracer value is minted
randomly inside the CLI, so the app never hardcodes a token: in the plant phase
it captures whatever planted payload it received out of the request, and in the
replay phase a read surface reflects those captured payloads back. observe then
re-derives and HMAC-verifies the tracer from the reflected body, so a GREEN
assertion proves the whole pipeline carried the same minted token end to end.

Every recorded surface uses the root path ``/`` so the only planted site is the
single query parameter (no path segments to split into extra sites), which keeps
the universe size and the routing predictable.
"""

import json
import sys
from pathlib import Path

import httpx
import pytest

from dyetrace.cli import main
from tests.oss_fixtures import candidate_dict as _cand, candidates_doc as _candidates_doc

SAFE_IP = "93.184.216.34"  # a non-private address; the resolver returns it, no DNS
HOST = "app.example.com"
BASE = "https://app.example.com"
FIXTURES = Path(__file__).parent / "fixtures"


def _resolver(_host):
    return [SAFE_IP]


def _dye_values(request):
    """Full planted payloads carried in the request's query values.

    The planted payload round-trips through httpx's query decoding verbatim
    (verified separately), so the app reflects exactly what it received rather
    than a hardcoded token.
    """
    return [v for _k, v in request.url.params.multi_items() if "DYE-" in v]


class App:
    """A store-then-reflect target.

    Plant hits (a request carrying a DYE payload) are stashed and answered 200,
    unless the request's query carries ``reject_param``, in which case the plant
    is refused with 403 (R5(d) plant-rejected). Read hits (no DYE payload)
    reflect the stashed payloads when ``reflect`` is set, so observe finds a
    verified resurfacing.
    """

    def __init__(self, *, reflect=True, reject_param=None):
        self.seen = []
        self.reflect = reflect
        self.reject_param = reject_param

    def handler(self, request):
        keys = set(request.url.params.keys())
        if self.reject_param is not None and self.reject_param in keys:
            return httpx.Response(403, text="forbidden")
        dye = _dye_values(request)
        if dye:
            self.seen.extend(dye)
            return httpx.Response(200, text="stored ok")
        if self.reflect and self.seen:
            return httpx.Response(200, text="reflected: " + " || ".join(self.seen))
        return httpx.Response(200, text="nothing of interest here")


def _transport(app):
    return httpx.MockTransport(app.handler)


def _session(recorded, *, cookies=None, auth_headers=None):
    return {
        "version": "1",
        "cookies": cookies or {},
        "auth_headers": auth_headers or {},
        "base_url": BASE,
        "recorded_requests": recorded,
    }


def _get(url, headers=None):
    return {"method": "GET", "url": url, "headers": headers or [], "body": None}


def _write(tmp_path, obj, name="session.json"):
    p = tmp_path / name
    p.write_text(json.dumps(obj))
    return str(p)


def _run_json(session_path, app, extra=()):
    """Run the CLI with --output json and return (rc, parsed_doc)."""
    argv = ["--session", session_path, "--host", HOST, "--rate", "1000",
            "--output", "json", *extra]
    rc = main(argv, resolver=_resolver, transport=_transport(app))
    return rc, app


# --- Happy end-to-end: a stored-then-reflected tracer is a tracked resurfacing


def test_happy_end_to_end_yields_tracked_resurfacing(tmp_path, capsys):
    path = _write(tmp_path, _session([_get(f"{BASE}/?q=hello")]))
    app = App(reflect=True)
    rc = main(
        ["--session", path, "--host", HOST, "--rate", "1000",
         "--output", "json", "--raw-only"],
        resolver=_resolver, transport=_transport(app),
    )
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)

    # A "tracked" row is by construction a verified resurfacing (observe only
    # assigns that severity on a raw, same-identity hit it HMAC-verified).
    tracked = [r for r in doc["flow"] if r["severity"] == "tracked"]
    assert tracked, doc["flow"]
    assert doc["counts"]["resurfaced"] >= 1
    assert "verified leaks found" in doc["summary"]
    # The reflected row carries a real, verified tracer: observe only emits a
    # resurfaced row after HMAC verify, so the whole pipeline agreed on the
    # minted token.
    assert tracked[0]["snippet"].startswith("DYE-")
    assert tracked[0]["sink_identity"] == 1


# --- Injection candidate: a markup-breaking variant reflected unescaped ------


def test_injection_candidate_lands_in_findings_bucket(tmp_path, capsys):
    path = _write(tmp_path, _session([_get(f"{BASE}/?q=hello")]))
    app = App(reflect=True)  # all variants planted and reflected verbatim
    rc = main(
        ["--session", path, "--host", HOST, "--rate", "1000", "--output", "json"],
        resolver=_resolver, transport=_transport(app),
    )
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)

    findings = doc["findings"]
    assert findings, doc
    assert any(f["severity"] == "injection-candidate" for f in findings)
    # The markup-breaking wrapper surfaced intact in the captured snippet.
    cand = next(f for f in findings if f["severity"] == "injection-candidate")
    assert "<dye" in cand["snippet"]


# --- Cross-context: id-1 tracer reflected under id-2's replay ----------------


def test_cross_context_row_under_second_identity(tmp_path, capsys):
    primary = _write(
        tmp_path,
        _session([_get(f"{BASE}/?q=hello")], cookies={"sid": "ID1COOKIE"}),
        name="primary.json",
    )
    second = _write(
        tmp_path,
        _session([_get(f"{BASE}/?z=1")], cookies={"sid": "ID2COOKIE"}),
        name="second.json",
    )
    app = App(reflect=True)
    rc = main(
        ["--session", primary, "--second-session", second,
         "--host", HOST, "--rate", "1000", "--output", "json", "--raw-only"],
        resolver=_resolver, transport=_transport(app),
    )
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)

    cross = [r for r in doc["flow"] if r["cross_context"] is True]
    assert cross, doc["flow"]
    row = cross[0]
    assert row["sink_identity"] == 2
    assert row["source_identity"] == 1
    assert row["severity"] == "cross-context"
    # The second pass actually ran: the cross-context row only exists because
    # identity 2 replayed the read surface.
    assert any(r["sink_identity"] == 2 for r in doc["flow"])


# --- Plant-rejected (R5(d)) is distinct from a clean never-resurfaced miss ---


def test_plant_rejected_distinct_from_clean_miss(tmp_path, capsys):
    session = _session([
        _get(f"{BASE}/?a=1"),   # reject surface: plant refused with 403
        _get(f"{BASE}/?b=2"),   # miss surface: plant accepted, never reflected
    ])
    path = _write(tmp_path, session)
    app = App(reflect=False, reject_param="a")
    rc = main(
        ["--session", path, "--host", HOST, "--rate", "1000",
         "--output", "json", "--raw-only"],
        resolver=_resolver, transport=_transport(app),
    )
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    counts = doc["counts"]

    assert counts["plant_rejected"] >= 1
    assert counts["never_resurfaced"] >= 1
    assert counts["resurfaced"] == 0
    # The two outcomes are kept distinct, not collapsed (KTD11).
    assert counts["plant_rejected"] != 0 and counts["never_resurfaced"] != 0
    assert "no verified leaks" in doc["summary"]


# --- Fail-closed: empty input exits non-zero, distinct from a clean run ------


def test_fail_closed_empty_input_differs_from_clean_run(tmp_path, capsys):
    empty_path = str(FIXTURES / "empty_session.json")
    rc_empty = main(
        ["--session", empty_path, "--host", HOST, "--rate", "1000"],
        resolver=_resolver, transport=_transport(App()),
    )
    err = capsys.readouterr().err
    assert rc_empty != 0
    assert "stopped" in err.lower()

    clean = _write(tmp_path, _session([_get(f"{BASE}/?q=hello")]))
    rc_clean = main(
        ["--session", clean, "--host", HOST, "--rate", "1000"],
        resolver=_resolver, transport=_transport(App(reflect=True)),
    )
    assert rc_clean == 0
    assert rc_empty != rc_clean


# --- Escaping and credential masking through the real render -----------------


def test_render_escapes_and_masks_through_real_pipeline(tmp_path, capsys):
    session = _session(
        [_get(f"{BASE}/?q=SECRETQ789")],
        cookies={"sid": "SECRETCOOKIE123"},
        auth_headers={"Authorization": "Bearer SECRETTOKEN456"},
    )
    path = _write(tmp_path, session)
    secrets = ("SECRETQ789", "SECRETCOOKIE123", "SECRETTOKEN456")

    # html surface: the markup-breaking variant must be entity-encoded, never a
    # live <dye tag; no credential and no URL token present.
    rc = main(
        ["--session", path, "--host", HOST, "--rate", "1000", "--output", "html"],
        resolver=_resolver, transport=_transport(App(reflect=True)),
    )
    assert rc == 0
    html_out = capsys.readouterr().out
    assert "<dye" not in html_out          # no live tag survived
    assert "&lt;dye" in html_out           # it is present, escaped
    for s in secrets:
        assert s not in html_out

    # terminal surface: no raw ANSI escape and no C0 control byte (other than the
    # layout newlines); no credential and no URL token present.
    rc = main(
        ["--session", path, "--host", HOST, "--rate", "1000", "--output", "terminal"],
        resolver=_resolver, transport=_transport(App(reflect=True)),
    )
    assert rc == 0
    term_out = capsys.readouterr().out
    assert "\x1b" not in term_out
    assert not any(ord(c) < 0x20 and c != "\n" for c in term_out)
    for s in secrets:
        assert s not in term_out


# --- OSS mode end-to-end -----------------------------------------------------


class OssApp:
    """Routes: /predicted echoes its query (predicted sink surface), /other
    stores without echoing, /kill never surfaces data, /profile is the read
    surface reflecting stored payloads."""

    def __init__(self):
        self.seen = []

    def handler(self, request):
        path = request.url.path
        dye = _dye_values(request)
        if path == "/predicted":
            return httpx.Response(200, text="echo:" + (dye[0] if dye else ""))
        if dye and path == "/other":
            self.seen.extend(dye)
            return httpx.Response(200, text="stored")
        if dye:
            return httpx.Response(200, text="dropped")
        if path == "/profile":
            return httpx.Response(200, text="reflected: " + " | ".join(self.seen))
        return httpx.Response(200, text="ok")


def test_oss_end_to_end_verdicts(tmp_path, capsys):
    session = _session([
        _get(f"{BASE}/predicted?q=x"),
        _get(f"{BASE}/other?z=y"),
        _get(f"{BASE}/kill?k=v"),
        _get(f"{BASE}/profile"),
    ])
    spath = _write(tmp_path, session)
    cands = _candidates_doc([
        _cand("cand-p", "get /predicted"),
        _cand("cand-n", "get /other"),
        _cand("cand-k", "get /kill"),
        _cand("cand-u", "get /never-recorded"),
    ])
    cpath = _write(tmp_path, cands, name="candidates.json")

    rc = main(
        ["--session", spath, "--host", HOST, "--rate", "1000",
         "--output", "json", "--raw-only", "--candidates", cpath],
        resolver=_resolver, transport=_transport(OssApp()),
    )
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    by_id = {v["candidate_id"]: v for v in doc["oss"]["candidate_verdicts"]}
    assert by_id["cand-p"]["verdict"] == "PROVEN"
    assert by_id["cand-n"]["verdict"] == "new_flow"
    assert by_id["cand-n"]["jevsec_seed"]
    assert by_id["cand-k"]["verdict"] == "KILL"
    assert by_id["cand-u"]["verdict"] == "unmapable"


def test_oss_run_sends_no_requests_for_unmapable_only(tmp_path, capsys):
    """Zero mapped candidates: render verdicts, send nothing."""
    class Counter:
        def handler(self, request):
            self.n += 1
            return httpx.Response(200, text="ok")
        n = 0

    spath = _write(tmp_path, _session([_get(f"{BASE}/predicted?q=x")]))
    cpath = _write(
        tmp_path,
        _candidates_doc([_cand("cand-u", "get /never-recorded")]),
        name="candidates.json",
    )
    app = Counter()
    rc = main(
        ["--session", spath, "--host", HOST, "--rate", "1000",
         "--output", "json", "--candidates", cpath],
        resolver=_resolver, transport=_transport(app),
    )
    assert rc == 0
    assert app.n == 0


class OssMutatingApp:
    """/mutate echoes its query only for POST, for the confirm-mutating path."""

    def handler(self, request):
        dye = _dye_values(request)
        if request.url.path == "/mutate" and dye:
            return httpx.Response(200, text="echo:" + dye[0])
        return httpx.Response(200, text="ok")


def _post(url, headers=None, body=None):
    return {"method": "POST", "url": url, "headers": headers or [],
            "body": body}


def test_oss_mutating_candidate_proven_with_confirm(tmp_path, capsys):
    session = _session([_post(f"{BASE}/mutate?q=x")])
    spath = _write(tmp_path, session)
    cpath = _write(tmp_path,
                   _candidates_doc([_cand("cand-m", "post /mutate")]),
                   name="candidates.json")
    rc = main(
        ["--session", spath, "--host", HOST, "--rate", "1000",
         "--output", "json", "--raw-only", "--confirm-mutating",
         "--candidates", cpath],
        resolver=_resolver, transport=_transport(OssMutatingApp()),
    )
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    v = doc["oss"]["candidate_verdicts"][0]
    assert v["verdict"] == "PROVEN"


def test_oss_second_identity_hit_is_new_flow(tmp_path, capsys):
    """A stored tracer surfacing under the second identity is still
    off-predicted: new_flow, with the cross-context row in the flow table."""
    second = _session([_get(f"{BASE}/profile")])
    second_path = _write(tmp_path, second, name="second.json")
    spath = _write(tmp_path, _session([
        _get(f"{BASE}/other?z=y"),
        _get(f"{BASE}/profile"),
    ]))
    cpath = _write(tmp_path,
                   _candidates_doc([_cand("cand-s", "get /other")]),
                   name="candidates.json")
    app = OssApp()
    rc = main(
        ["--session", spath, "--host", HOST, "--rate", "1000",
         "--output", "json", "--raw-only", "--candidates", cpath,
         "--second-session", second_path],
        resolver=_resolver, transport=_transport(app),
    )
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    v = doc["oss"]["candidate_verdicts"][0]
    assert v["verdict"] == "new_flow"
    cross = [r for r in doc["flow"] if r["cross_context"]]
    assert cross, "expected a cross-identity hit"


def test_oss_binds_predicted_second_order_proven(tmp_path, capsys):
    """P0-2 end-to-end: /other's tracer persists and resurfaces at the
    /profile replay. With a bind naming propagate:<profile index> as the
    predicted surface, the stored-then-reflected flow is PROVEN."""
    session = _session([
        _get(f"{BASE}/other?z=y"),    # 0: plant target
        _get(f"{BASE}/profile"),      # 1: read surface reflecting store
    ])
    spath = _write(tmp_path, session)
    cpath = _write(tmp_path,
                   _candidates_doc([_cand("cand-n", "get /other")]),
                   name="candidates.json")
    bpath = _write(tmp_path,
                   {"cand-n": {"request_index": 0,
                               "predicted": "propagate:1"}},
                   name="binds.json")

    rc = main(
        ["--session", spath, "--host", HOST, "--rate", "1000",
         "--output", "json", "--raw-only", "--candidates", cpath,
         "--binds", bpath],
        resolver=_resolver, transport=_transport(OssApp()),
    )
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    v = doc["oss"]["candidate_verdicts"][0]
    assert v["candidate_id"] == "cand-n"
    assert v["verdict"] == "PROVEN"
    assert v["predicted"] == "propagate:1"
    assert v["bind"] == {"request_index": 0, "path_id": None}


def test_oss_binds_exported_candidate_plants(tmp_path, capsys):
    """P0-1 end-to-end: a non-route candidate is unmapable without a bind and
    plantable with one - here a bound 'exported' candidate proves its flow."""
    session = _session([_get(f"{BASE}/predicted?q=x")])
    spath = _write(tmp_path, session)
    cpath = _write(tmp_path,
                   _candidates_doc([_cand("cand-e", "get /predicted",
                                          kind="exported")]),
                   name="candidates.json")
    bpath = _write(tmp_path,
                   {"cand-e": {"request_index": 0}},
                   name="binds.json")
    app = OssApp()
    # Unbound: unmapable.
    rc = main(
        ["--session", spath, "--host", HOST, "--rate", "1000",
         "--output", "json", "--raw-only", "--candidates", cpath],
        resolver=_resolver, transport=_transport(app),
    )
    assert rc == 0
    v = json.loads(capsys.readouterr().out)["oss"]["candidate_verdicts"][0]
    assert v["verdict"] == "unmapable"
    # Bound: plants request 0 and proves on the default plant surface.
    rc = main(
        ["--session", spath, "--host", HOST, "--rate", "1000",
         "--output", "json", "--raw-only", "--candidates", cpath,
         "--binds", bpath],
        resolver=_resolver, transport=_transport(app),
    )
    assert rc == 0
    v = json.loads(capsys.readouterr().out)["oss"]["candidate_verdicts"][0]
    assert v["verdict"] == "PROVEN"
    assert v["bind"]["request_index"] == 0


def test_session_from_har_fixture_loads(tmp_path):
    """P1-3: a loopback HAR converts to a session the loader accepts."""
    har = {
        "log": {"entries": [
            {"request": {
                "method": "GET",
                "url": "http://127.0.0.1:8080/predicted?q=x",
                "headers": [{"name": "Host", "value": "127.0.0.1:8080"}],
                "cookies": [{"name": "sid", "value": "abc"}],
            }},
            {"request": {
                "method": "POST",
                "url": "http://localhost:8080/submit",
                "headers": [],
                "postData": {"mimeType": "application/json",
                             "text": '{"a": 1}'},
            }},
        ]},
    }
    p = tmp_path / "cap.har"
    p.write_text(json.dumps(har))
    sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
    import session_from_har
    session = session_from_har.convert(har)
    out = tmp_path / "sess.json"
    out.write_text(json.dumps(session))
    from dyetrace.session import load_session
    loaded = load_session(str(out), "127.0.0.1")
    assert len(loaded.recorded_requests) == 2
    assert loaded.recorded_requests[1].body.data == b'{"a": 1}'
    assert loaded.cookies["sid"] == "abc"


def test_session_from_har_refuses_remote_without_flag(tmp_path):
    har = {"log": {"entries": [{"request": {
        "method": "GET",
        "url": "https://app.example.com/x",
        "headers": []}}]}}
    sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
    import session_from_har
    with pytest.raises(ValueError, match="non-loopback"):
        session_from_har.convert(har)
    assert session_from_har.convert(har, allow_remote=True)


def test_oss_route_prefix_maps_mounted_route(tmp_path, capsys):
    """P1-1 e2e: a '/x' route candidate planted at recorded '/api/x' under
    --route-prefix /api, proving on its own executed plant response."""
    session = _session([_get(f"{BASE}/api/predicted?q=x")])
    spath = _write(tmp_path, session)
    cpath = _write(tmp_path,
                   _candidates_doc([_cand("cand-m", "get /predicted")]),
                   name="candidates.json")

    class App:
        def handler(self, request):
            dye = _dye_values(request)
            if request.url.path == "/api/predicted" and dye:
                return httpx.Response(200, text="echo:" + dye[0])
            return httpx.Response(200, text="ok")

    rc = main(
        ["--session", spath, "--host", HOST, "--rate", "1000",
         "--output", "json", "--raw-only", "--candidates", cpath,
         "--route-prefix", "/api"],
        resolver=_resolver, transport=_transport(App()),
    )
    assert rc == 0
    v = json.loads(capsys.readouterr().out)["oss"]["candidate_verdicts"][0]
    assert v["verdict"] == "PROVEN"


def test_oss_route_prefix_not_set_stays_unmapable(tmp_path, capsys):
    session = _session([_get(f"{BASE}/api/predicted?q=x")])
    spath = _write(tmp_path, session)
    cpath = _write(tmp_path,
                   _candidates_doc([_cand("cand-m", "get /predicted")]),
                   name="candidates.json")
    rc = main(
        ["--session", spath, "--host", HOST, "--rate", "1000",
         "--output", "json", "--raw-only", "--candidates", cpath],
        resolver=_resolver, transport=_transport(OssApp()),
    )
    assert rc == 0
    v = json.loads(capsys.readouterr().out)["oss"]["candidate_verdicts"][0]
    assert v["verdict"] == "unmapable"
