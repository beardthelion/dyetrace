"""Tests for U7 egress verdicts (R10, R11, KTD5, KTD10, KTD12).

Pure unit tests build SendRecord / Hit / ListenerSnapshot objects by hand and
fold them through a fake listener; two integration tests use the real Listener
and the real driver.
"""

import dataclasses
import http.client
import urllib.parse

import pytest

from dyetrace import egressdrive as D
from dyetrace import egressverdict as V
from dyetrace.egresscand import EgressCandidate
from dyetrace.egressmap import EgressMapResult, MappedEgress, SendPlan, UnmappedEgress
from dyetrace.egressnet import validate_advertised, validate_bind
from dyetrace.listener import Hit, Listener, ListenerSnapshot

KEY = b"\x07" * 32
RUN = "abc123"
NOTE = "probe --active from target env reached 10.0.0.5:9000"


def cand(cid, symbol="fetch"):
    return EgressCandidate(
        id=cid, source_tool="t", source_version="1.0", file="a.py", start_line=1,
        end_line=2, symbol=symbol, site_label=None, param_names=("url",),
        params_truncated=False, sinks=(), guard_classes=(), destination_kind=None,
        lead=False, tool_name=None, arg_name=None,
    )


def mapped(c, tool="fetch", arg="url", i=0):
    return MappedEgress(c, tool, arg, {}, "auto", i)


def rec(i, tool="fetch", arg="url", ids=("c1",), outcome="result", cls="public",
        ws=10.0, we=15.0, token=None):
    eid = format(i + 1, "x")
    return D.SendRecord(
        index=i, tool=tool, argument=arg, candidate_ids=tuple(ids), outcome=outcome,
        entry_id=eid, nonce="n", token=token or "DYE-%s-%s-n-%s" % (RUN, eid, "a" * 64),
        url="http://h/x", address_class=cls, advertised_host="h", advertised_port=9000,
        window_start=ws, window_end=we,
    )


def hit(r, offset=11.0):
    return Hit(
        entry_id=r.entry_id, nonce=r.nonce, token=r.token, method="GET", target="/x",
        headers=(), source=("127.0.0.1", 1), wall=0.0, offset=offset, arrival_index=1,
    )


def snap(hits=(), **kw):
    base = dict(
        verified_hits=tuple(hits), arrival_counts={}, verified_dropped=0, noise_count=0,
        noise_samples=(), refused_count=0, refused_offsets=(), deadline_close_count=0,
        deadline_close_offsets=(), unattributed_count=0, unattributed_offsets=(),
        offsets_truncated=False, oversize_closed=0, malformed_closed=0, peak_connections=0,
        active_connections=0, health="ok",
    )
    base.update(kw)
    return ListenerSnapshot(**base)


class FakeListener:
    def __init__(self, snapshot):
        self._s = snapshot

    def snapshot(self):
        return self._s

    def hits_for(self, entry_id):
        return tuple(h for h in self._s.verified_hits if h.entry_id == entry_id)


def drive_of(sends, complete=True, settle=5.0, drain=5.0, **kw):
    return D.DriveResult(list(sends), complete, settle=settle, drain=drain,
                         drain_start=100.0, drain_end=105.0, **kw)


def run(cands, sends, snapshot=None, *, att=NOTE, settle=5.0, complete=True,
        unmapable=(), stop_reason=None):
    mr = EgressMapResult(
        mapped=[mapped(c, tool=s.tool, arg=s.argument, i=i)
                for i, (c, s) in enumerate(cands)],
        unmapable=list(unmapable),
    )
    d = drive_of(sends, complete=complete, settle=settle, stop_reason=stop_reason)
    return V.egress_verdicts(mr, d, FakeListener(snapshot or snap()), attestation=att,
                             bound_port=9001)


def one(report, cid="c1"):
    return next(v for v in report.verdicts if v.candidate.id == cid)


# ---- table rows ----------------------------------------------------------


def test_row1_unmapable_passes_through_with_reason():
    c = cand("u1")
    r = run([], [], unmapable=[UnmappedEgress(c, "no_tool_match", 0)])
    assert one(r, "u1").verdict == V.VERDICT_UNMAPABLE
    assert one(r, "u1").reason == "no_tool_match"
    assert r.complete


def test_zero_mapped_is_complete():
    r = run([], [])
    assert r.verdicts == [] and r.complete and r.incomplete_reason is None


def test_row2_proven():
    s = rec(0)
    r = run([(cand("c1"), s)], [s], snap([hit(s)]))
    v = one(r)
    assert v.verdict == V.VERDICT_PROVEN and v.reason is None
    assert v.credited_hits[0].entry_id == s.entry_id and v.send is s
    assert r.counts[V.VERDICT_PROVEN] == 1


def test_row2_shared_send_both_proven():
    s = rec(0, ids=("c1", "c2"))
    r = run([(cand("c1"), s), (cand("c2"), s)], [s], snap([hit(s)]))
    assert one(r, "c1").verdict == one(r, "c2").verdict == V.VERDICT_PROVEN


def test_row3_new_flow_and_proven_outranks():
    a, b = rec(0, arg="url", ids=("cA",)), rec(1, arg="callback_url", ids=("cB",))
    r = run([(cand("cA"), a), (cand("cB"), b)], [a, b], snap([hit(b)]))
    assert one(r, "cB").verdict == V.VERDICT_PROVEN
    va = one(r, "cA")
    assert va.verdict == V.VERDICT_NEW_FLOW and va.reason is None
    assert "callback_url" in va.note
    # both hit: each is PROVEN, never new_flow
    r2 = run([(cand("cA"), a), (cand("cB"), b)], [a, b], snap([hit(a), hit(b)]))
    assert {v.verdict for v in r2.verdicts} == {V.VERDICT_PROVEN}


def test_new_flow_not_for_other_tool_or_same_argument():
    a = rec(0, tool="fetch", ids=("cA",))
    b = rec(1, tool="other", ids=("cB",))
    r = run([(cand("cA"), a), (cand("cB"), b)], [a, b], snap([hit(b)]))
    assert one(r, "cA").verdict != V.VERDICT_NEW_FLOW
    # same tool and argument, different static arguments: not a different argument
    c = rec(2, tool="fetch", arg="url", ids=("cC",))
    r2 = run([(cand("cA"), a), (cand("cC"), c)], [a, c], snap([hit(c)]))
    assert one(r2, "cA").verdict != V.VERDICT_NEW_FLOW


def test_row5_not_called():
    s = D.SendRecord(0, "fetch", "url", ("c1",), D.OUTCOME_NOT_CALLED)
    r = run([(cand("c1"), s)], [s])
    assert (one(r).verdict, one(r).reason) == (V.VERDICT_UNEXERCISED, "not_called")


@pytest.mark.parametrize("outcome,reason", [
    ("tool_error", "tool_error"), ("transport_error", "transport_error"),
    ("timeout", "timeout"), ("invalid_params", "server_rejected_input"),
])
def test_row6_failed_calls(outcome, reason):
    s = rec(0, outcome=outcome)
    r = run([(cand("c1"), s)], [s])
    assert (one(r).verdict, one(r).reason) == (V.VERDICT_UNEXERCISED, reason)


def test_row7_8_reason_set():
    s = rec(0)
    r = run([(cand("c1"), s)], [s], settle=1.0, att=None)
    assert one(r).verdict == V.VERDICT_UNEXERCISED
    assert one(r).reason == "settle_window_too_short+listener_reachability_unconfirmed"


def test_blank_attestation_is_none():
    s = rec(0)
    for att in ("", "   ", None):
        r = run([(cand("c1"), s)], [s], att=att)
        assert one(r).reason == "listener_reachability_unconfirmed"


def test_row11_kill():
    s = rec(0)
    r = run([(cand("c1"), s)], [s])
    v = one(r)
    assert (v.verdict, v.reason) == (V.VERDICT_KILL, "no_arrival_observed")
    a = v.attestation
    assert a.note == NOTE and a.operator_asserted_unverified
    assert (a.advertised_host, a.advertised_port, a.bound_port) == ("h", 9000, 9001)
    assert r.attestation.note == NOTE and r.attestation.bound_port == 9001


def test_settle_exactly_two_seconds_allows_kill():
    s = rec(0)
    assert one(run([(cand("c1"), s)], [s], settle=2.0)).verdict == V.VERDICT_KILL


# ---- address class -------------------------------------------------------


@pytest.mark.parametrize("cls", ["loopback", "private"])
def test_local_class_never_kill(cls):
    s = rec(0, cls=cls)
    v = one(run([(cand("c1"), s)], [s]))
    assert (v.verdict, v.reason) == (V.VERDICT_UNEXERCISED, "local_class_only_no_arrival")


def test_local_class_combines_with_other_reasons():
    s = rec(0, cls="private")
    v = one(run([(cand("c1"), s)], [s], settle=1.0, att=None))
    assert v.reason == ("settle_window_too_short+listener_reachability_unconfirmed"
                        "+local_class_only_no_arrival")


def test_unknown_class_never_kill():
    s = rec(0, cls=None)
    assert one(run([(cand("c1"), s)], [s])).verdict == V.VERDICT_UNEXERCISED


def test_hostname_one_public_one_private_is_private_via_validator():
    t = validate_advertised(
        "http://a.example:9000", allow_local=True,
        resolver=lambda h: ["1.1.1.1", "10.0.0.5"])
    assert t.address_class == "private"
    s = dataclasses.replace(rec(0), address_class=t.address_class)
    assert one(run([(cand("c1"), s)], [s])).reason == "local_class_only_no_arrival"


# ---- evidence bar --------------------------------------------------------


def test_echoed_token_in_result_text_not_proof():
    s = rec(0)
    s.result_text = "fetched " + s.token
    assert one(run([(cand("c1"), s)], [s])).verdict == V.VERDICT_KILL


def test_unverified_noise_never_proves_or_new_flow():
    a, b = rec(0, arg="url", ids=("cA",)), rec(1, arg="cb", ids=("cB",))
    sn = snap(noise_count=50)  # forged tokens only land here; nothing verified
    r = run([(cand("cA"), a), (cand("cB"), b)], [a, b], sn)
    assert {v.verdict for v in r.verdicts} == {V.VERDICT_KILL}


def test_hit_with_wrong_token_for_entry_is_anomaly_not_proof():
    s = rec(0)
    bad = dataclasses.replace(hit(s), token="DYE-%s-1-n-%s" % (RUN, "b" * 64))
    r = run([(cand("c1"), s)], [s], snap([bad]))
    assert one(r).verdict != V.VERDICT_PROVEN
    assert not r.complete and r.anomalies == (bad,)


def test_anomaly_unknown_entry_id():
    s = rec(0)
    ghost = dataclasses.replace(hit(s), entry_id="ff", token="DYE-%s-ff-n-%s" % (RUN, "c" * 64))
    r = run([(cand("c1"), s)], [s], snap([ghost]))
    assert r.anomalies == (ghost,) and not r.complete
    assert "anomal" in r.incomplete_reason
    v = one(r)
    assert (v.verdict, v.reason) == (V.VERDICT_UNEXERCISED, "run_incomplete")
    assert ghost in r.hits  # listed in the flat list, but credited to nothing
    assert v.credited_hits == ()


# ---- incomplete runs -----------------------------------------------------


@pytest.mark.parametrize("sn_kw,reason", [
    ({"health": "failed"}, "listener_failed"),
    ({"health": "overflowed"}, "listener_failed"),
    ({"verified_dropped": 3}, "listener_failed"),
])
def test_listener_failure_forces_listener_failed(sn_kw, reason):
    s = rec(0)
    r = run([(cand("c1"), s)], [s], snap(**sn_kw))
    assert not r.complete and r.incomplete_reason
    assert (one(r).verdict, one(r).reason) == (V.VERDICT_UNEXERCISED, reason)


def test_drive_stop_is_run_incomplete_and_proven_kept():
    a = rec(0, ids=("cA",))
    b = rec(1, tool="t2", ids=("cB",))
    c = D.SendRecord(2, "t3", "x", ("cC",), D.OUTCOME_NOT_CALLED)
    r = run([(cand("cA"), a), (cand("cB"), b), (cand("cC"), c)], [a, b, c],
            snap([hit(a)]), complete=False, stop_reason=D.STOP_RECHECK_FAILED)
    assert one(r, "cA").verdict == V.VERDICT_PROVEN
    for cid in ("cB", "cC"):
        assert (one(r, cid).verdict, one(r, cid).reason) == (
            V.VERDICT_UNEXERCISED, "run_incomplete")
    assert not r.complete and D.STOP_RECHECK_FAILED in r.incomplete_reason
    assert r.counts.get(V.VERDICT_KILL, 0) == 0


def test_incomplete_never_kill_even_with_all_preconditions():
    s = rec(0)
    r = run([(cand("c1"), s)], [s], snap(health="failed"))
    assert one(r).verdict != V.VERDICT_KILL


# ---- interference --------------------------------------------------------


def test_refused_inside_window_is_saturated_and_incomplete():
    s = rec(0)
    r = run([(cand("c1"), s)], [s], snap(refused_count=1, refused_offsets=(12.0,)))
    v = one(r)
    assert (v.verdict, v.reason) == (V.VERDICT_UNEXERCISED, "listener_saturated")
    assert not r.complete and "listener_saturated" in r.incomplete_reason


def test_deadline_close_inside_window_is_saturated():
    s = rec(0)
    v = one(run([(cand("c1"), s)], [s],
                snap(deadline_close_count=1, deadline_close_offsets=(10.0,))))
    assert v.reason == "listener_saturated"


def test_unattributed_inside_window_not_kill():
    s = rec(0)
    r = run([(cand("c1"), s)], [s], snap(unattributed_count=1, unattributed_offsets=(15.0,)))
    v = one(r)
    assert (v.verdict, v.reason) == (V.VERDICT_UNEXERCISED, "unattributed_arrival")
    assert r.complete  # unattributed alone does not mark the run incomplete


def test_drain_window_interference_counts():
    s = rec(0)
    v = one(run([(cand("c1"), s)], [s], snap(unattributed_count=1, unattributed_offsets=(102.0,))))
    assert v.reason == "unattributed_arrival"


def test_interference_outside_all_windows_is_ignored():
    s = rec(0)
    sn = snap(refused_count=1, refused_offsets=(50.0,), unattributed_count=1,
              unattributed_offsets=(1.0,), deadline_close_count=1, deadline_close_offsets=(200.0,))
    r = run([(cand("c1"), s)], [s], sn)
    assert one(r).verdict == V.VERDICT_KILL and r.complete


def test_offsets_truncated_is_interference():
    s = rec(0)
    sn = snap(offsets_truncated=True, refused_count=10001, refused_offsets=(1.0,))
    v = one(run([(cand("c1"), s)], [s], sn))
    assert (v.verdict, v.reason) == (V.VERDICT_UNEXERCISED, "listener_saturated")


def test_interference_combines_with_other_reasons():
    s = rec(0, cls="loopback")
    v = one(run([(cand("c1"), s)], [s], snap(unattributed_count=1, unattributed_offsets=(11,)),
                att=None))
    assert v.reason == ("listener_reachability_unconfirmed+unattributed_arrival"
                        "+local_class_only_no_arrival")


def test_interference_in_other_sends_window_does_not_block_this_kill():
    a, b = rec(0, ids=("cA",), ws=10, we=15), rec(1, arg="cb", ids=("cB",), ws=20, we=25)
    r = run([(cand("cA"), a), (cand("cB"), b)], [a, b],
            snap(refused_count=1, refused_offsets=(12.0,)))
    assert one(r, "cA").reason == "listener_saturated"
    # run is incomplete so the unaffected silent send cannot KILL either
    assert (one(r, "cB").verdict, one(r, "cB").reason) == (V.VERDICT_UNEXERCISED, "run_incomplete")


def test_proven_survives_interference():
    s = rec(0)
    r = run([(cand("c1"), s)], [s], snap([hit(s)], refused_count=1, refused_offsets=(12.0,)))
    assert one(r).verdict == V.VERDICT_PROVEN


# ---- report payload ------------------------------------------------------


def test_report_payload_fields():
    s = rec(0)
    r = run([(cand("c1"), s)], [s], snap([hit(s)]), settle=3.0)
    assert r.settle == 3.0 and r.drain == 5.0
    assert r.hits == (hit(s),) and r.anomalies == ()
    assert r.source_tools == (("t", "1.0"),)
    assert r.attestation.note == NOTE
    assert V.VERDICT_PROVEN in r.counts


def test_verdicts_sorted_by_input_index():
    a, b = rec(0, ids=("a",)), rec(1, arg="cb", ids=("b",))
    mr = EgressMapResult(
        mapped=[mapped(cand("b"), arg="cb", i=2), mapped(cand("a"), i=0)],
        unmapable=[UnmappedEgress(cand("u"), "no_tool_match", 1)],
    )
    r = V.egress_verdicts(mr, drive_of([a, b]), FakeListener(snap()), attestation=NOTE)
    assert [v.candidate.id for v in r.verdicts] == ["a", "u", "b"]


def test_mapped_candidate_without_send_record_raises():
    mr = EgressMapResult(mapped=[mapped(cand("zz"))])
    with pytest.raises(ValueError):
        V.egress_verdicts(mr, drive_of([rec(0)]), FakeListener(snap()), attestation=NOTE)


def test_module_docstring_states_evidence_bar():
    d = V.__doc__
    for phrase in ("HMAC", "run-id", "send record", "Status codes", "tool result text",
                   "unverified", "operator-asserted", "unverified"):
        assert phrase in d


# ---- integration with the real listener and driver -----------------------


@pytest.fixture
def lst():
    lis = Listener(validate_bind("127.0.0.1", 0, allow_port_zero=True), KEY, RUN)
    lis.start()
    try:
        yield lis
    finally:
        lis.close()


class Caller:
    def __init__(self, lis, fetch):
        self.lis, self.fetch = lis, fetch

    def list_tools(self):
        return []

    def call_tool(self, name, arguments, timeout):
        if self.fetch:
            path = urllib.parse.urlsplit(arguments["url"]).path
            h, p = self.lis.address
            c = http.client.HTTPConnection(h, p, timeout=5)
            try:
                c.request("GET", path)
                c.getresponse().read()
            finally:
                c.close()
        return D.CallOutcome("result", "ok")

    def close(self):
        pass


def _drive_real(lis, fetch, url, settle):
    plans = [SendPlan("fetch", "url", {}, ("c1",))]
    d = D.run_driver(
        plans, caller=Caller(lis, fetch), listener=lis, key=KEY, run_id=RUN,
        target=validate_advertised(url, allow_local=True), settle=settle, drain=0.0,
        sleep=lambda s: None, resolver=lambda h: ["1.1.1.1"])
    mr = EgressMapResult(mapped=[mapped(cand("c1"))], plans=plans)
    return V.egress_verdicts(mr, d, lis, attestation=NOTE, bound_port=lis.address[1])


def test_integration_proven_real_listener(lst):
    r = _drive_real(lst, True, "http://127.0.0.1:8080", 0.2)
    assert one(r).verdict == V.VERDICT_PROVEN and r.complete


def test_integration_kill_public_class_and_local_class_twin(lst):
    # settle at the 2 s floor; a public-class literal is the test-only override
    # (the listener is still on loopback; the caller does not fetch).
    r = _drive_real(lst, False, "http://1.1.1.1:8080", 2.0)
    assert (one(r).verdict, one(r).reason) == (V.VERDICT_KILL, "no_arrival_observed")
    assert r.complete


def test_integration_loopback_twin_is_local_class(lst):
    r = _drive_real(lst, False, "http://127.0.0.1:8080", 2.0)
    assert one(r).reason == "local_class_only_no_arrival"


# ---- silent head closes and out-of-window run-prefixed arrivals -----------
# A target that fetched the tracer URL with a head the listener closes silently
# (or with an unverifiable run-prefixed token outside every send window) must
# never yield a KILL. A hostile neighbour may deny a KILL, never manufacture one.

import socket
import time


def _raw(addr, data):
    s = socket.create_connection(addr, timeout=5)
    try:
        s.sendall(data)
        s.settimeout(3)
        try:
            while s.recv(65536):
                pass
        except (socket.timeout, ConnectionResetError):
            pass
    finally:
        s.close()


def _fold_kill_eligible(lis, key_unused=None):
    s = rec(0, ws=1000.0, we=1005.0)     # window far from the listener's offsets
    mr = EgressMapResult(mapped=[mapped(cand("c1"), i=0)])
    d = D.DriveResult([s], True, settle=5.0, drain=5.0, drain_start=2000.0,
                      drain_end=2005.0)
    return V.egress_verdicts(mr, d, lis, attestation=NOTE, bound_port=1)


def _wait(lis, pred):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if pred(lis.snapshot()):
            return
        time.sleep(0.02)
    raise AssertionError("listener never recorded the close")


def test_clean_listener_still_reaches_kill_in_this_harness(lst):
    r = _fold_kill_eligible(lst)
    assert one(r).verdict == V.VERDICT_KILL


_TOK = "DYE-%s-1-aa-%s" % (RUN, "a" * 64)
_HEADS = {
    "oversize_cookie": ("GET /%s HTTP/1.1\r\nHost: x\r\nCookie: %s\r\n\r\n"
                        % (_TOK, "a" * 9000)),
    "no_colon_header": "GET /%s HTTP/1.1\r\nHost: x\r\nbadheader\r\n\r\n" % _TOK,
    "obs_fold": "GET /%s HTTP/1.1\r\nHost: x\r\n folded: y\r\n\r\n" % _TOK,
    "lowercase_method": "get /%s HTTP/1.1\r\nHost: x\r\n\r\n" % _TOK,
    "no_http_version": "GET /%s\r\nHost: x\r\n\r\n" % _TOK,
}
# the same shapes with a path that carries no tracer prefix at all
_HEADS_ANON = {
    "oversize_cookie": "GET /favicon.ico HTTP/1.1\r\nHost: x\r\nCookie: %s\r\n\r\n" % ("a" * 9000),
    "no_colon_header": "GET /favicon.ico HTTP/1.1\r\nHost: x\r\nbadheader\r\n\r\n",
    "obs_fold": "GET /favicon.ico HTTP/1.1\r\nHost: x\r\n folded: y\r\n\r\n",
    "lowercase_method": "get /favicon.ico HTTP/1.1\r\nHost: x\r\n\r\n",
    "no_http_version": "GET /favicon.ico\r\nHost: x\r\n\r\n",
}


@pytest.mark.parametrize("shape", sorted(_HEADS))
@pytest.mark.parametrize("table", [_HEADS, _HEADS_ANON], ids=["prefixed", "anonymous"])
def test_silently_closed_head_anywhere_blocks_kill(lst, shape, table):
    _raw(lst.address, table[shape].encode("latin-1"))
    _wait(lst, lambda s: s.oversize_closed + s.malformed_closed >= 1)
    snap_ = lst.snapshot()
    assert snap_.oversize_offsets + snap_.malformed_offsets   # offsets recorded
    v = one(_fold_kill_eligible(lst))
    assert v.verdict == V.VERDICT_UNEXERCISED, v
    assert V.REASON_UNATTRIBUTED in v.reason.split("+")


def test_run_prefixed_unverified_arrival_outside_every_window_blocks_kill(lst):
    c = http.client.HTTPConnection(*lst.address, timeout=5)
    c.request("GET", "/DYE-%s-1-aa-%s" % (RUN, "b" * 64))   # bad MAC, no window open
    c.getresponse().read()
    c.close()
    v = one(_fold_kill_eligible(lst))
    assert v.verdict == V.VERDICT_UNEXERCISED, v
    assert V.REASON_UNATTRIBUTED in v.reason.split("+")


def test_other_run_prefix_outside_window_does_not_block_kill(lst):
    c = http.client.HTTPConnection(*lst.address, timeout=5)
    c.request("GET", "/DYE-ffffff-1-aa-%s" % ("b" * 64))
    c.getresponse().read()
    c.close()
    assert one(_fold_kill_eligible(lst)).verdict == V.VERDICT_KILL


# ---- truncated heads, active connections, global interference (round 2) ----

from dyetrace import listener as _L


def _send_then(addr, data, how):
    s = socket.create_connection(addr, timeout=5)
    try:
        if data:
            s.sendall(data)
        if how == "fin":
            s.shutdown(socket.SHUT_WR)
            s.settimeout(3)
            try:
                while s.recv(4096):
                    pass
            except (socket.timeout, ConnectionResetError):
                pass
        elif how == "rst":
            import struct
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            time.sleep(0.1)
    finally:
        s.close()


_PARTIAL = [
    ("partial_fin", b"GET /favicon.ico HTTP/1.1\r\nHost: x\r\n", "fin"),
    ("partial_prefixed_fin", ("GET /%s HTTP/1.1\r\nHo" % _TOK).encode(), "fin"),
    ("partial_rst", b"GET /favicon.ico HTTP/1.1\r\nHost", "rst"),
    ("tls_hello_fin", b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" + b"\x00" * 40, "fin"),
]


@pytest.mark.parametrize("name,data,how", _PARTIAL, ids=[p[0] for p in _PARTIAL])
def test_truncated_head_blocks_kill(lst, name, data, how):
    _send_then(lst.address, data, how)
    _wait(lst, lambda s: s.malformed_closed >= 1)
    assert lst.snapshot().malformed_offsets
    v = one(_fold_kill_eligible(lst))
    assert v.verdict == V.VERDICT_UNEXERCISED, v
    assert V.REASON_UNATTRIBUTED in v.reason.split("+")


def test_truncated_prefixed_head_sets_prefixed_count(lst):
    _send_then(lst.address, ("GET /%s HTTP/1.1\r\nHo" % _TOK).encode(), "fin")
    _wait(lst, lambda s: s.malformed_closed >= 1)
    assert lst.snapshot().prefixed_count == 1


def test_partial_head_prefixed_until_deadline_blocks_kill(lst, monkeypatch):
    monkeypatch.setattr(_L, "HEAD_DEADLINE", 0.4)
    s = socket.create_connection(lst.address, timeout=5)
    try:
        s.sendall(("GET /%s HTTP/1.1\r\nHo" % _TOK).encode())
        _wait(lst, lambda sn: sn.deadline_close_count >= 1)
        sn = lst.snapshot()
        assert sn.deadline_close_count == 1
        assert sn.prefixed_count == 1 and sn.malformed_closed == 1
    finally:
        s.close()
    v = one(_fold_kill_eligible(lst))
    assert v.verdict == V.VERDICT_UNEXERCISED, v
    assert V.REASON_UNATTRIBUTED in v.reason.split("+")


def test_zero_byte_connect_and_close_does_not_block_kill(lst):
    for how in ("fin", "plain"):
        s = socket.create_connection(lst.address, timeout=5)
        if how == "fin":
            s.shutdown(socket.SHUT_WR)
        s.close()
    time.sleep(0.3)
    sn = lst.snapshot()
    assert sn.malformed_closed == 0 and sn.prefixed_count == 0
    assert one(_fold_kill_eligible(lst)).verdict == V.VERDICT_KILL


def test_active_connection_at_fold_blocks_kill():
    s = rec(0)
    v = one(run([(cand("c1"), s)], [s], snap(active_connections=1)))
    assert v.verdict == V.VERDICT_UNEXERCISED
    assert v.reason.split("+").count(V.REASON_UNATTRIBUTED) == 1


def test_closed_listener_has_no_active_connections_and_still_kills(lst):
    lst.close()
    assert lst.snapshot().active_connections == 0
    assert one(_fold_kill_eligible(lst)).verdict == V.VERDICT_KILL


def test_live_stalled_connection_blocks_kill_then_close_clears(lst):
    s = socket.create_connection(lst.address, timeout=5)
    try:
        _wait(lst, lambda sn: sn.active_connections >= 1)
        assert one(_fold_kill_eligible(lst)).verdict == V.VERDICT_UNEXERCISED
    finally:
        s.close()


def test_prefixed_and_unattributed_offset_yield_one_token():
    s = rec(0)
    v = one(run([(cand("c1"), s)], [s],
                snap(prefixed_count=1, unattributed_count=1, unattributed_offsets=(12.0,))))
    assert v.reason.split("+").count(V.REASON_UNATTRIBUTED) == 1
    assert v.verdict == V.VERDICT_UNEXERCISED


def test_global_interference_does_not_downgrade_proven_or_new_flow():
    a = rec(0, ids=("c1",), arg="url")
    b = rec(1, ids=("c2",), arg="uri")
    c = rec(2, ids=("c3",), arg="other", tool="other")
    d = rec(3, ids=("c4",), arg="url", tool="fetch")
    sn = snap(hits=[hit(a)], malformed_closed=1, prefixed_count=1)
    r = run([(cand("c1"), a), (cand("c2"), b), (cand("c3"), c), (cand("c4"), d)],
            [a, b, c, d], sn)
    assert one(r, "c1").verdict == V.VERDICT_PROVEN
    assert one(r, "c2").verdict == V.VERDICT_NEW_FLOW or one(r, "c2").verdict == V.VERDICT_UNEXERCISED
    assert one(r, "c3").verdict == V.VERDICT_UNEXERCISED
    assert one(r, "c3").verdict != V.VERDICT_KILL
    assert one(r, "c4").verdict != V.VERDICT_KILL
