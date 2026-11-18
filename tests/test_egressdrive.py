"""Tests for U6 egress driver (R3, R9, R11, KTD2, KTD10, KTD11, KTD12).

Test-first: written before src/dyetrace/egressdrive.py exists. The integration
scenarios use the real Listener on an ephemeral port (validate_bind port-0 test
seam) with an in-process fake ToolCaller whose fixture logic performs a real
stdlib HTTP GET on its URL argument. Clock, sleep, resolver and gate are
injected, so timing and the rebind scenario need no real DNS or real waits
(settle and drain waits against the real listener use tiny real timeouts).
"""

import copy
import http.client
import threading
import time
import urllib.parse
import urllib.request

import pytest

from dyetrace import egressdrive as D
from dyetrace import marker
from dyetrace.egressmap import SendPlan
from dyetrace.egressnet import (
    AdvertisedTarget,
    MetadataAddressError,
    validate_advertised,
    validate_bind,
)
from dyetrace.listener import Listener

KEY = b"\x07" * 32
RUN = "abc123"


def plan(tool="fetch", arg="url", arguments=None, ids=("c1",)):
    return SendPlan(tool, arg, dict(arguments or {}), tuple(ids))


def lit(url="http://127.0.0.1:8080"):
    return validate_advertised(url, allow_local=True)


@pytest.fixture
def lst():
    lis = Listener(validate_bind("127.0.0.1", 0, allow_port_zero=True), KEY, RUN)
    lis.start()
    try:
        yield lis
    finally:
        lis.close()


def get(lis, path):
    h, p = lis.address
    c = http.client.HTTPConnection(h, p, timeout=5)
    try:
        c.request("GET", path)
        return c.getresponse().status
    finally:
        c.close()


class FakeCaller:
    """Records calls; `behaviors` maps call index to a callable(args) -> outcome."""

    def __init__(self, lis=None, fetch=True, behaviors=None):
        self.lis = lis
        self.fetch = fetch
        self.behaviors = behaviors or {}
        self.calls = []
        self.closed = False

    def list_tools(self):
        return []

    def call_tool(self, name, arguments, timeout):
        i = len(self.calls)
        self.calls.append((name, arguments, timeout))
        if i in self.behaviors:
            return self.behaviors[i](arguments)
        if self.fetch and self.lis is not None:
            path = urllib.parse.urlsplit(arguments["url"]).path
            get(self.lis, path)
        return D.CallOutcome("result", "ok")

    def close(self):
        self.closed = True


def drive(plans, caller, lis, **kw):
    kw.setdefault("target", lit())
    kw.setdefault("settle", 0.05)
    kw.setdefault("drain", 0.0)
    kw.setdefault("sleep", lambda s: None)
    kw.setdefault("resolver", lambda h: ["1.1.1.1"])
    return D.run_driver(plans, caller=caller, listener=lis, key=KEY, run_id=RUN, **kw)


def test_three_plans_in_order_and_exact_arguments(lst):
    plans = [
        plan("a", "url", {"mode": "x"}, ("c1",)),
        plan("b", "u", {"n": [1, 2]}, ("c2",)),
        plan("c", "url", {}, ("c3",)),
    ]
    caller = FakeCaller(lst, fetch=False)
    seen = []

    def mutate(args):
        seen.append(args)
        return D.CallOutcome("result", "ok")

    for i in range(3):
        caller.behaviors[i] = mutate
    res = drive(plans, caller, lst)
    assert [c[0] for c in caller.calls] == ["a", "b", "c"]
    assert res.complete and res.stop_reason is None
    for s in seen:
        s["mutated"] = True
        for v in s.values():
            if isinstance(v, list):
                v.append(99)
    recs = res.sends
    assert recs[0].arguments == {"mode": "x", "url": recs[0].url}
    assert recs[1].arguments == {"n": [1, 2], "u": recs[1].url}
    assert recs[0].candidate_ids == ("c1",)
    assert recs[1].argument == "u" and recs[1].tool == "b"
    assert all(r.outcome == "result" for r in recs)


def test_distinct_entry_ids_and_url_shape_and_slash(lst):
    for base, shape in (
        ("http://127.0.0.1:8080", "http://127.0.0.1:8080/"),
        ("http://127.0.0.1:8080/", "http://127.0.0.1:8080/"),
        ("http://127.0.0.1:8080/pre/", "http://127.0.0.1:8080/pre/"),
        ("http://127.0.0.1:8080/pre", "http://127.0.0.1:8080/pre/"),
    ):
        caller = FakeCaller(lst, fetch=False)
        res = drive([plan(), plan()], caller, lst, target=lit(base))
        a, b = res.sends
        assert a.entry_id != b.entry_id and a.nonce != b.nonce
        assert a.token != b.token
        assert a.url == shape + a.token
        assert "//" not in a.url[len("http://") :]
        assert marker.verify(a.token, KEY)
        assert a.entry_id == "1" and b.entry_id == "2"


def test_record_has_address_class_and_advertised_target(lst):
    caller = FakeCaller(lst, fetch=False)
    res = drive([plan()], caller, lst)
    r = res.sends[0]
    assert r.address_class == "loopback"
    assert r.advertised_host == "127.0.0.1" and r.advertised_port == 8080
    pub = validate_advertised("http://93.184.216.34:9000")
    res = drive([plan()], FakeCaller(lst, fetch=False), lst, target=pub)
    assert res.sends[0].address_class == "public"


def test_hit_after_call_returned_inside_settle_is_waited_for(lst):
    def late(args):
        path = urllib.parse.urlsplit(args["url"]).path
        threading.Timer(0.15, lambda: get(lst, path)).start()
        return D.CallOutcome("result", "ok")

    caller = FakeCaller(lst, behaviors={0: late})
    res = drive([plan()], caller, lst, settle=3.0)
    assert len(lst.hits_for(res.sends[0].entry_id)) == 1


def test_drain_window_hit_is_credited_to_its_send(lst):
    def late(args):
        path = urllib.parse.urlsplit(args["url"]).path
        threading.Timer(0.3, lambda: get(lst, path)).start()
        return D.CallOutcome("result", "ok")

    caller = FakeCaller(lst, behaviors={0: late})
    t0 = time.monotonic()
    res = D.run_driver(
        [plan()],
        caller=caller,
        listener=lst,
        key=KEY,
        run_id=RUN,
        target=lit(),
        settle=0.02,
        drain=1.0,
        resolver=lambda h: ["1.1.1.1"],
    )
    assert time.monotonic() - t0 >= 1.0
    assert len(lst.hits_for(res.sends[0].entry_id)) == 1
    assert res.drain_start is not None and res.drain_end >= res.drain_start


def test_arrival_after_listener_closes_not_seen():
    lis = Listener(validate_bind("127.0.0.1", 0, allow_port_zero=True), KEY, RUN)
    lis.start()
    addr = lis.address
    caller = FakeCaller(None, fetch=False)
    res = drive([plan()], caller, lis)
    lis.close()
    path = urllib.parse.urlsplit(res.sends[0].url).path
    with pytest.raises(OSError):
        c = http.client.HTTPConnection(*addr, timeout=2)
        c.request("GET", path)
        c.getresponse()
    assert lis.hits_for(res.sends[0].entry_id) == ()


def test_windows_recorded_and_unattributed_inside_window(lst):
    def stray(args):
        get(lst, "/DYE-" + RUN + "-zz-zz-" + "0" * 64)  # unverified, our prefix
        return D.CallOutcome("result", "ok")

    caller = FakeCaller(lst, behaviors={0: stray})
    res = drive([plan(), plan()], caller, lst, settle=0.05)
    a, b = res.sends
    assert a.window_start <= a.window_end
    snap = lst.snapshot()
    assert snap.unattributed_count >= 1
    assert all(a.window_start <= o <= a.window_end for o in snap.unattributed_offsets)
    assert a.window_end <= b.window_start
    assert not any(b.window_start <= o <= b.window_end for o in snap.unattributed_offsets)


def test_failures_recorded_and_run_continues(lst):
    def boom(args):
        raise RuntimeError("kaput")

    def slow(args):
        raise TimeoutError("slow")

    caller = FakeCaller(
        lst,
        fetch=False,
        behaviors={
            0: boom,
            1: slow,
            2: lambda a: D.CallOutcome("tool_error", "bad"),
            3: lambda a: D.CallOutcome("invalid_params", "nope"),
        },
    )
    res = drive([plan(), plan(), plan(), plan(), plan()], caller, lst)
    assert [r.outcome for r in res.sends] == [
        "transport_error",
        "timeout",
        "tool_error",
        "invalid_params",
        "result",
    ]
    assert res.complete and len(caller.calls) == 5
    assert "kaput" in res.sends[0].error


def test_unknown_outcome_kind_is_transport_error(lst):
    caller = FakeCaller(lst, fetch=False, behaviors={0: lambda a: D.CallOutcome("weird", "x")})
    res = drive([plan()], caller, lst)
    assert res.sends[0].outcome == "transport_error"


def test_result_text_bounded(lst):
    big = "A" * (D.RESULT_TEXT_CAP + 500)
    caller = FakeCaller(lst, fetch=False, behaviors={0: lambda a: D.CallOutcome("result", big)})
    res = drive([plan()], caller, lst)
    assert len(res.sends[0].result_text) == D.RESULT_TEXT_CAP
    assert res.sends[0].result_truncated is True


def test_rebind_after_wait_stops_run_and_nothing_sent(lst):
    state = {"flip": False}

    def resolver(host):
        return ["169.254.169.254"] if state["flip"] else ["1.1.1.1"]

    def sleep(s):
        state["flip"] = True

    class Gate:
        n = 0

        def wait(self):
            self.n += 1
            if self.n == 2:
                sleep(1)

    target = validate_advertised("http://canary.example:9000", resolver=resolver)
    caller = FakeCaller(lst, fetch=False)
    res = D.run_driver(
        [plan(ids=("c1",)), plan(ids=("c2",)), plan(ids=("c3",))],
        caller=caller,
        listener=lst,
        key=KEY,
        run_id=RUN,
        target=target,
        resolver=resolver,
        gate=Gate(),
        settle=0.01,
        drain=0.0,
        sleep=sleep,
    )
    assert len(caller.calls) == 1
    assert [r.outcome for r in res.sends] == ["result", "not_called", "not_called"]
    assert res.complete is False
    assert res.stop_reason == D.STOP_RECHECK_FAILED
    assert res.stop_detail
    assert res.sends[1].token is None and res.sends[2].entry_id is None


def test_no_send_before_validation_passes_once(lst):
    def resolver(host):
        return ["169.254.169.254"]

    with pytest.raises(MetadataAddressError):
        validate_advertised("http://canary.example:9000", resolver=resolver)
    # a driver handed a target whose first recheck fails never sends
    good = validate_advertised("http://canary.example:9000", resolver=lambda h: ["1.1.1.1"])
    caller = FakeCaller(lst, fetch=False)
    res = drive([plan(), plan()], caller, lst, target=good, resolver=resolver)
    assert caller.calls == []
    assert res.stop_reason == D.STOP_RECHECK_FAILED
    assert all(r.outcome == "not_called" for r in res.sends)


def test_resolver_exception_fails_closed(lst):
    good = validate_advertised("http://canary.example:9000", resolver=lambda h: ["1.1.1.1"])

    def bad(host):
        raise OSError("dns down")

    caller = FakeCaller(lst, fetch=False)
    res = drive([plan()], caller, lst, target=good, resolver=bad)
    assert caller.calls == [] and res.stop_reason == D.STOP_RECHECK_FAILED


def test_max_calls_below_plan_count_sends_nothing(lst):
    caller = FakeCaller(lst, fetch=False)
    res = drive([plan(), plan(), plan()], caller, lst, max_calls=2)
    assert caller.calls == []
    assert res.stop_reason == D.STOP_MAX_CALLS
    assert res.complete is False
    assert len(res.sends) == 3 and all(r.outcome == "not_called" for r in res.sends)
    res = drive([plan(), plan()], FakeCaller(lst, fetch=False), lst, max_calls=2)
    assert res.complete


def test_echoed_token_in_result_text_is_not_a_hit(lst):
    def echo(args):
        return D.CallOutcome("result", "fetched " + args["url"])

    caller = FakeCaller(lst, fetch=False, behaviors={0: echo})
    res = drive([plan()], caller, lst, settle=0.05)
    r = res.sends[0]
    assert r.token in r.result_text
    assert lst.hits_for(r.entry_id) == ()
    assert lst.snapshot().verified_hits == ()


def test_vulnerable_fixture_produces_verified_hit(lst):
    caller = FakeCaller(lst)
    res = drive([plan(), plan(tool="other")], caller, lst)
    for r in res.sends:
        hits = lst.hits_for(r.entry_id)
        assert len(hits) == 1 and hits[0].token == r.token


def test_listener_unhealthy_mid_run_stops(lst):
    class Flaky:
        def __init__(self, inner):
            self.inner = inner
            self.bad = False

        def __getattr__(self, n):
            return getattr(self.inner, n)

        def health(self):
            return "failed" if self.bad else "ok"

    fl = Flaky(lst)

    def trip(args):
        fl.bad = True
        return D.CallOutcome("result", "ok")

    caller = FakeCaller(lst, fetch=False, behaviors={0: trip})
    res = drive([plan(), plan(), plan()], caller, fl)
    assert len(caller.calls) == 1
    assert res.stop_reason == D.STOP_LISTENER_UNHEALTHY
    assert res.complete is False
    assert [r.outcome for r in res.sends] == ["result", "not_called", "not_called"]
    assert res.sends[0].window_end is not None


def test_listener_unhealthy_at_start_sends_nothing(lst):
    class Dead:
        def __init__(self, inner):
            self.inner = inner

        def __getattr__(self, n):
            return getattr(self.inner, n)

        def health(self):
            return "failed"

    caller = FakeCaller(lst, fetch=False)
    res = drive([plan()], caller, Dead(lst))
    assert caller.calls == [] and res.stop_reason == D.STOP_LISTENER_UNHEALTHY


def test_rate_gate_waited_before_each_call(lst):
    events = []

    class Gate:
        def wait(self):
            events.append("gate")

    caller = FakeCaller(lst, fetch=False)
    orig = caller.call_tool

    def spy(name, args, timeout):
        events.append("call")
        return orig(name, args, timeout)

    caller.call_tool = spy
    drive([plan(), plan()], caller, lst, gate=Gate())
    assert events == ["gate", "call", "gate", "call"]


def test_call_timeout_passed_and_caller_not_closed_by_driver(lst):
    caller = FakeCaller(lst, fetch=False)
    drive([plan()], caller, lst, call_timeout=7.5)
    assert caller.calls[0][2] == 7.5 and caller.closed is False


def test_bad_inputs_rejected(lst):
    with pytest.raises(TypeError):
        D.run_driver(
            [plan()], caller=FakeCaller(), listener=lst, key=KEY, run_id=RUN, target="http://x"
        )
    with pytest.raises(ValueError):
        drive([plan()], FakeCaller(), lst, settle=-1)
    assert isinstance(lit(), AdvertisedTarget)
    assert copy.deepcopy(plan()) == plan()
