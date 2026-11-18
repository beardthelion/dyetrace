"""U13 whole-path adversarial tests for `dyetrace egress`.

Every test asserts an observed must-not, deny, oversized, malformed or error
case, not the happy outcome. Items follow the U13 checklist (1 to 8). The
composed path is driven through ``egresscli.main`` with the real Listener on a
loopback port wherever the seam under test spans more than one unit.
"""

import http.client
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

from dyetrace import egresscli, marker
from dyetrace import egressdrive as D
from dyetrace.egressmap import SendPlan
from dyetrace.egressnet import (
    AdvertisedURLError,
    BindError,
    validate_advertised,
    validate_bind,
)
from dyetrace.listener import Listener
from dyetrace.mcpclient import StderrExcerpt

from tests.egress_fixtures import (
    FixtureCaller,
    candidate,
    contract,
    free_port,
    stdio_target,
    write_json,
)
from tests.test_egress_e2e import PUBLIC, Run, reasons, send_request, verdict

SERVER = str(Path(__file__).parent / "mcp_fixture_server.py")
KEY = b"\x05" * 32
RUN = "abc123"


# --- raw client helpers -------------------------------------------------------


def raw_exchange(addr, data, timeout=5.0):
    s = socket.create_connection(addr, timeout=timeout)
    try:
        s.sendall(data)
        out = b""
        while True:
            try:
                d = s.recv(65536)
            except (ConnectionResetError, socket.timeout):
                break
            if not d:
                break
            out += d
        return out
    finally:
        s.close()


def raw_get(addr, path, extra=""):
    req = "GET %s HTTP/1.1\r\nHost: x\r\n%s\r\n" % (path, extra)
    return raw_exchange(addr, req.encode("latin-1"))


@pytest.fixture
def lst():
    lis = Listener(validate_bind("127.0.0.1", 0, allow_port_zero=True), KEY, RUN)
    lis.start()
    try:
        yield lis
    finally:
        lis.close()


def tok(entry="1", nonce="aa11"):
    return marker.build_token(KEY, RUN, entry, nonce)


# --- 1/7: the listener closed for real mid-run (known open item) --------------


class _ClosingGate:
    """A rate gate that closes the listener while the driver is waiting."""

    def __init__(self, lis):
        self.lis = lis

    def wait(self):
        self.lis.close()


class _CountingCaller:
    def __init__(self):
        self.calls = 0

    def call_tool(self, name, arguments, timeout):
        self.calls += 1
        return D.CallOutcome("result", "ok")


def test_listener_closed_during_rate_gate_wait_sends_nothing(lst):
    caller = _CountingCaller()
    target = validate_advertised("http://127.0.0.1:%d" % lst.address[1], allow_local=True)
    res = D.run_driver(
        [SendPlan("t", "url", {}, ("c1",))], caller=caller, listener=lst, key=KEY,
        run_id=RUN, target=target, settle=0.1, drain=0, gate=_ClosingGate(lst))
    assert caller.calls == 0
    assert res.complete is False
    assert res.stop_reason == D.STOP_LISTENER_UNHEALTHY


def test_listener_closed_before_first_send_sends_nothing(lst):
    caller = _CountingCaller()
    target = validate_advertised("http://127.0.0.1:%d" % lst.address[1], allow_local=True)
    lst.close()
    res = D.run_driver(
        [SendPlan("t", "url", {}, ("c1",))], caller=caller, listener=lst, key=KEY,
        run_id=RUN, target=target, settle=0.1, drain=0)
    assert caller.calls == 0 and res.complete is False


def test_listener_closed_during_drain_is_incomplete(lst):
    caller = _CountingCaller()
    target = validate_advertised("http://127.0.0.1:%d" % lst.address[1], allow_local=True)
    res = D.run_driver(
        [SendPlan("t", "url", {}, ("c1",))], caller=caller, listener=lst, key=KEY,
        run_id=RUN, target=target, settle=0.0, drain=0.3,
        sleep=lambda s: lst.close())
    assert caller.calls == 1
    assert res.complete is False and res.stop_reason == D.STOP_LISTENER_UNHEALTHY


def test_normal_end_of_run_close_after_drain_stays_complete(lst):
    caller = _CountingCaller()
    target = validate_advertised("http://127.0.0.1:%d" % lst.address[1], allow_local=True)
    res = D.run_driver(
        [SendPlan("t", "url", {}, ("c1",))], caller=caller, listener=lst, key=KEY,
        run_id=RUN, target=target, settle=0.0, drain=0.0)
    assert res.complete is True
    lst.close()  # what the CLI does next
    assert lst.snapshot().health == "ok"


# --- 7: window edges and the late arrival -------------------------------------


def _unattr_inside(lis, ws, we):
    snap = lis.snapshot()
    return [o for o in snap.unattributed_offsets if ws <= o <= we]


def test_request_on_a_preopened_connection_inside_window_is_flagged(lst):
    s = socket.create_connection(lst.address, timeout=5)
    try:
        assert lst.wait_for(lambda: lst.snapshot().active_connections == 1, 5)
        w = lst.open_window()
        ws = lst.offset()
        s.sendall(b"GET /%44YE-mangled HTTP/1.1\r\nHost: x\r\n\r\n")
        assert lst.wait_for(lambda: lst.snapshot().noise_count >= 1, 5)
        we = lst.offset()
        lst.close_window(w)
    finally:
        s.close()
    assert lst.snapshot().unattributed_count == 1
    assert _unattr_inside(lst, ws, we), lst.snapshot().unattributed_offsets


def test_connection_accepted_in_window_with_head_after_close_is_flagged(lst):
    w = lst.open_window()
    ws = lst.offset()
    s = socket.create_connection(lst.address, timeout=5)
    try:
        assert lst.wait_for(lambda: lst.snapshot().active_connections == 1, 5)
        we = lst.offset()
        lst.close_window(w)
        s.sendall(b"GET /%44YE-mangled HTTP/1.1\r\nHost: x\r\n\r\n")
        assert lst.wait_for(lambda: lst.snapshot().noise_count >= 1, 5)
    finally:
        s.close()
    assert _unattr_inside(lst, ws, we), lst.snapshot().unattributed_offsets


def _late_arrival_caller(run, delay):
    """FixtureCaller whose first call spawns a fetch of its own token URL later."""
    state = {}

    def on_call(name, arguments):
        if "t" in state:
            return
        url = arguments["url"]
        path = url[url.index("/", len("http://")):]

        def later():
            time.sleep(delay)
            try:
                send_request(run.port, path)
            except OSError:
                pass

        state["t"] = threading.Thread(target=later)
        state["t"].start()

    caller = FixtureCaller(on_call=on_call)
    caller._state = state
    return caller


def test_late_arrival_of_send_n_during_send_n_plus_1_window_credits_n_only(tmp_path, capsys):
    run = Run(tmp_path, [candidate("c1", "echo_url"), candidate("c2", "fetch_url_safe")],
              binds={"c2": {"tool": "fetch_url_safe", "argument": "url"}})
    run.caller = _late_arrival_caller(run, 2.5)
    rc, out, err = run.go(capsys, run.argv(settle="2"), address_class_override="public")
    run.caller._state["t"].join()
    rep = json.loads(out)
    assert verdict(rep, "c1")["verdict"] == "PROVEN", rep["verdicts"]
    assert verdict(rep, "c2")["verdict"] != "PROVEN"
    assert [h["credited_to"] for h in rep["hits"]] == [["c1"]]


def test_arrival_during_drain_window_is_proven_not_kill(tmp_path, capsys):
    run = Run(tmp_path, [candidate("c1", "echo_url")])
    run.caller = _late_arrival_caller(run, 0.8)
    rc, out, err = run.go(capsys, run.argv(settle="0.3", output="json")[:-2] +
                          ["--drain", "1.5", "--output", "json"])
    run.caller._state["t"].join()
    rep = json.loads(out)
    assert verdict(rep, "c1")["verdict"] == "PROVEN", rep["verdicts"]


def test_arrival_after_all_windows_is_never_credited_and_never_kill(tmp_path, capsys):
    """Beyond the drain the listener is closed: the report must not claim more
    than KILL-with-limits (reasoned: the late fetch is the named residual)."""
    run = Run(tmp_path, [candidate("c1", "fetch_url_safe")])
    rc, out, err = run.go(capsys, run.argv(settle="0.3"))  # loopback class
    rep = json.loads(out)
    assert verdict(rep, "c1")["verdict"] != "KILL"
    assert rc == 3


# --- 4: KILL must not survive interference in the window ----------------------


def _kill_run(tmp_path, hook):
    run = Run(tmp_path, [candidate("c1", "fetch_url_safe")])
    run.caller = FixtureCaller(on_call=lambda n, a: hook(run))
    return run


@pytest.mark.parametrize("path", [
    "/%44YE-{run}-1-aa-{mac}",          # percent-encoded D
    "/dye-{run}-1-aa-{mac}",            # lowercased
    "/DYE-{run}-1-aa-{mac}x",           # trailing junk after the MAC
    "/DYE-{run}-1-aa-{mac2}",           # truncated MAC
    "/x/%2e%2e/DYE-{run}-1-aa-{mac}",   # path games around the token
])
def test_mangled_tracer_arrival_in_window_blocks_kill(tmp_path, capsys, path):
    def hook(run):
        mac = "a" * 64
        p = path.format(run=run.run_id, mac=mac, mac2="a" * 30)
        send_request(run.port, p)

    run = _kill_run(tmp_path, hook)
    rc, out, err = run.go(capsys, run.argv(settle="2"), address_class_override="public")
    rep = json.loads(out)
    v = verdict(rep, "c1")
    assert v["verdict"] == "unexercised", v
    assert "unattributed_arrival" in reasons(v)
    assert rc == 3


def test_any_unverified_arrival_in_window_blocks_kill(tmp_path, capsys):
    run = _kill_run(tmp_path, lambda run: send_request(run.port, "/favicon.ico"))
    rc, out, _ = run.go(capsys, run.argv(settle="2"), address_class_override="public")
    v = verdict(json.loads(out), "c1")
    assert v["verdict"] != "KILL" and "unattributed_arrival" in reasons(v)


def _hold_connections(port, n):
    socks = []
    for _ in range(n):
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        socks.append(s)
    return socks


def test_cap_refusal_in_window_marks_run_incomplete_and_blocks_kill(tmp_path, capsys):
    held = []

    def hook(run):
        held.extend(_hold_connections(run.port, 32))
        assert run.listener.wait_for(
            lambda: run.listener.snapshot().active_connections == 32, 10)
        try:
            send_request(run.port, "/probe")  # refused: closed with no reply
        except (OSError, http.client.HTTPException):
            pass

    run = _kill_run(tmp_path, hook)
    try:
        rc, out, err = run.go(capsys, run.argv(settle="2"), address_class_override="public")
    finally:
        for s in held:
            s.close()
    rep = json.loads(out)
    assert rep["status"] == "incomplete"
    assert rep["coverage"]["counts"]["KILL"] == 0
    assert rc == 2


def test_kill_requires_all_gates_matrix(tmp_path, capsys):
    """Each single missing gate alone must remove KILL (negative per gate)."""
    cases = [
        (dict(settle="1.9"), {}, "settle_window_too_short"),
        (dict(attest=None, settle="2"), {}, "listener_reachability_unconfirmed"),
        (dict(settle="2"), dict(address_class_override="private"),
         "local_class_only_no_arrival"),
        (dict(settle="2"), dict(address_class_override="loopback"),
         "local_class_only_no_arrival"),
    ]
    for kw, seams, reason in cases:
        run = Run(tmp_path, [candidate("c1", "fetch_url_safe")])
        seams = dict(seams)
        seams.setdefault("address_class_override", "public")
        rc, out, _ = run.go(capsys, run.argv(**kw), **seams)
        v = verdict(json.loads(out), "c1")
        assert v["verdict"] == "unexercised" and reason in reasons(v), (kw, v)
        assert rc == 3


# --- 6: anomalies, replay, retries --------------------------------------------


def test_verified_token_without_a_send_record_is_incomplete(tmp_path, capsys):
    def hook(run):
        t = marker.build_token(run.key, run.run_id, "ff", marker.new_nonce())
        send_request(run.port, "/" + t)

    run = _kill_run(tmp_path, hook)
    rc, out, err = run.go(capsys, run.argv(settle="2"), address_class_override="public")
    rep = json.loads(out)
    assert rep["status"] == "incomplete" and rep["anomalies"]
    assert rep["coverage"]["counts"]["KILL"] == 0
    assert rc == 2


def _from_source(port, source_ip, path):
    s = socket.socket()
    s.bind((source_ip, 0))
    s.settimeout(5)
    s.connect(("127.0.0.1", port))
    try:
        s.sendall(("GET %s HTTP/1.1\r\nHost: x\r\n\r\n" % path).encode())
        while s.recv(4096):
            pass
    finally:
        s.close()


def test_replay_from_second_source_shows_both_addresses_and_the_limit(tmp_path, capsys):
    def on_call(name, arguments):
        url = arguments["url"]
        path = url[url.index("/", len("http://")):]
        _from_source(run.port, "127.0.0.1", path)
        _from_source(run.port, "127.0.0.2", path)  # a neighbour replaying it

    run = Run(tmp_path, [candidate("c1", "echo_url")])
    run.caller = FixtureCaller(on_call=on_call)
    rc, out, err = run.go(capsys)
    rep = json.loads(out)
    arrivals = rep["evidence"][0]["evidence"]["arrivals"]
    sources = {a["source"].rsplit(":", 1)[0] for a in arrivals}
    assert sources == {"127.0.0.1", "127.0.0.2"}
    assert "replay" in rep["evidence"][0]["replay_caveat"]


def test_retrying_target_many_arrivals_are_bounded(tmp_path, capsys):
    def on_call(name, arguments):
        url = arguments["url"]
        path = url[url.index("/", len("http://")):]
        for _ in range(60):
            send_request(run.port, path)

    run = Run(tmp_path, [candidate("c1", "echo_url")])
    run.caller = FixtureCaller(on_call=on_call)
    rc, out, err = run.go(capsys)
    rep = json.loads(out)
    assert verdict(rep, "c1")["verdict"] == "PROVEN"
    assert len(rep["evidence"][0]["evidence"]["arrivals"]) == 20  # PER_TOKEN_CAP


def test_token_twice_in_one_path_is_one_hit(lst):
    t = tok("1")
    raw_get(lst.address, "/%s/%s" % (t, t))
    assert lst.wait_for_entry("1", 5)
    snap = lst.snapshot()
    assert len(snap.verified_hits) == 1 and snap.arrival_counts == {t: 1}


def test_two_tokens_in_one_path_never_credit_a_forged_prefix(lst):
    """A path holding a bad token then a good one still credits only the good."""
    good = tok("2")
    bad = "DYE-%s-1-aa11-%s" % (RUN, "0" * 64)
    raw_get(lst.address, "/%s/%s" % (bad, good))
    assert lst.wait_for_entry("2", 5)
    assert {h.entry_id for h in lst.snapshot().verified_hits} == {"2"}


def test_two_valid_tokens_in_one_path_credit_the_first_only(lst):
    """Documented limit: a request carrying two verified tokens credits the first.
    The second token's send is not credited by it (a hostile target splicing
    tokens can only withhold proof of its own second route, never forge one)."""
    raw_get(lst.address, "/%s/%s" % (tok("1", "aa11"), tok("2", "bb22")))
    assert lst.wait_for_entry("1", 5)
    snap = lst.snapshot()
    assert [h.entry_id for h in snap.verified_hits] == ["1"]
    assert lst.hits_for("2") == ()


def test_token_shaped_garbage_path_is_scanned_in_bounded_time(lst):
    path = "/" + "DYE-1-1-" * 900  # 7200 chars of near-miss prefixes
    t0 = time.monotonic()
    raw_get(lst.address, path[:7000])
    assert lst.wait_for(lambda: lst.snapshot().noise_count >= 1, 5)
    assert time.monotonic() - t0 < 2.0
    path2 = "/DYE-" + "a-" * 3400
    raw_get(lst.address, path2)
    assert lst.wait_for(lambda: lst.snapshot().noise_count >= 2, 5)
    assert time.monotonic() - t0 < 4.0


# --- 3: carriage ----------------------------------------------------------------


def test_base_path_trailing_slash_and_token_shaped_segment(tmp_path, capsys):
    run = Run(tmp_path, [candidate("c1", "echo_url")])
    shaped = "DYE-%s-1-aa11-%s" % ("0" * 6, "b" * 64)  # forged, token-shaped base segment
    argv = run.argv(advertise=False) + [
        "--advertise", "http://127.0.0.1:%d/base/%s/" % (run.port, shaped)]
    sent = []

    def on_call(name, arguments):
        sent.append(arguments["url"])
        url = arguments["url"]
        send_request(run.port, url[url.index("/", len("http://")):])

    run.caller = FixtureCaller(on_call=on_call)
    rc, out, err = run.go(capsys, argv)
    rep = json.loads(out)
    assert "//" not in sent[0][len("http://"):]
    assert verdict(rep, "c1")["verdict"] == "PROVEN"
    assert len(rep["hits"]) == 1


# --- 4: amplification -----------------------------------------------------------


@pytest.mark.parametrize("cl", ["99999999999", "-5", "abc", "1e9", "18446744073709551616"])
def test_hostile_content_length_is_bounded(lst, cl):
    body = b"A" * 200_000
    req = ("POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: %s\r\n\r\n" % cl).encode() + body
    t0 = time.monotonic()
    s = socket.create_connection(lst.address, timeout=5)
    try:
        try:
            s.sendall(req)
        except OSError:
            pass
        s.settimeout(5)
        try:
            while s.recv(65536):
                pass
        except (ConnectionResetError, socket.timeout):
            pass
    finally:
        s.close()
    assert time.monotonic() - t0 < 4.0
    assert lst.wait_for(lambda: lst.snapshot().active_connections == 0, 6)


def test_pipelined_second_request_is_not_served_or_credited(lst):
    t = tok("3")
    data = (b"GET /one HTTP/1.1\r\nHost: x\r\n\r\n"
            b"GET /" + t.encode() + b" HTTP/1.1\r\nHost: x\r\n\r\n")
    out = raw_exchange(lst.address, data)
    assert out.count(b"HTTP/1.1 200") == 1
    assert lst.snapshot().verified_hits == ()


def test_reset_before_accept_storm_does_not_fail_the_listener(lst):
    import struct

    for _ in range(200):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        s.connect(lst.address)
        s.close()  # RST
    time.sleep(0.3)
    assert lst.health() == "ok"
    assert raw_get(lst.address, "/" + tok("1")).startswith(b"HTTP/1.1 200")


def test_unbounded_result_text_and_error_are_bounded_in_records(lst):
    class Big:
        def call_tool(self, name, arguments, timeout):
            return D.CallOutcome("result", "A" * (10 * 1024 * 1024))

    target = validate_advertised("http://127.0.0.1:%d" % lst.address[1], allow_local=True)
    res = D.run_driver([SendPlan("t", "url", {}, ("c1",))], caller=Big(), listener=lst,
                       key=KEY, run_id=RUN, target=target, settle=0, drain=0)
    rec = res.sends[0]
    assert len(rec.result_text) == D.RESULT_TEXT_CAP and rec.result_truncated


def test_raising_caller_error_text_is_bounded_and_not_a_result(lst):
    class Boom:
        def call_tool(self, name, arguments, timeout):
            raise RuntimeError("x" * 100_000)

    target = validate_advertised("http://127.0.0.1:%d" % lst.address[1], allow_local=True)
    res = D.run_driver([SendPlan("t", "url", {}, ("c1",))], caller=Boom(), listener=lst,
                       key=KEY, run_id=RUN, target=target, settle=0, drain=0)
    rec = res.sends[0]
    assert rec.outcome == "transport_error" and len(rec.error) <= 200


def test_two_candidates_one_route_cost_one_call(tmp_path, capsys):
    run = Run(tmp_path, [candidate("c1", "fetch_url"), candidate("c2", "fetch_url")])
    rc, out, err = run.go(capsys)
    assert len(run.caller.calls) == 1
    rep = json.loads(out)
    assert verdict(rep, "c1")["verdict"] == verdict(rep, "c2")["verdict"] == "PROVEN"


def test_call_cap_stops_before_any_send(tmp_path, capsys):
    run = Run(tmp_path, [candidate("c1", "fetch_url"), candidate("c2", "echo_url")])
    rc, out, err = run.go(capsys, run.argv("--max-calls", "1"))
    assert rc == 2 and "call cap" in err
    assert run.caller.calls == []


# --- 1: check, wait, act --------------------------------------------------------


def test_rebind_during_rate_gate_wait_sends_nothing(lst):
    answers = {"n": 0}

    def resolver(host):
        answers["n"] += 1
        return [PUBLIC] if answers["n"] == 1 else ["169.254.169.254"]

    class Gate:
        def wait(self):
            pass

    caller = _CountingCaller()
    target = validate_advertised("http://canary.example:%d" % lst.address[1], resolver=resolver)
    res = D.run_driver([SendPlan("t", "url", {}, ("c1",))], caller=caller, listener=lst,
                       key=KEY, run_id=RUN, target=target, settle=0, drain=0,
                       gate=Gate(), resolver=resolver)
    assert caller.calls == 0
    assert res.stop_reason == D.STOP_RECHECK_FAILED and not res.complete


@pytest.mark.parametrize("answer", [
    [], ["::ffff:169.254.169.254"], ["93.184.216.34", "169.254.169.254"],
    ["not-an-ip"], ["100.100.100.200"], ["168.63.129.16"], ["fd00:ec2::254"],
])
def test_recheck_refuses_every_bad_answer_after_first_call(lst, answer):
    answers = iter([[PUBLIC]])
    caller = _CountingCaller()
    target = validate_advertised(
        "http://canary.example:%d" % lst.address[1], resolver=lambda h: [PUBLIC])
    res = D.run_driver(
        [SendPlan("t", "url", {}, ("c1",)), SendPlan("t", "url", {"a": "b"}, ("c2",))],
        caller=caller, listener=lst, key=KEY, run_id=RUN, target=target, settle=0, drain=0,
        resolver=lambda h: next(answers, answer))
    assert caller.calls == 1
    assert res.sends[1].outcome == "not_called" and res.stop_reason == D.STOP_RECHECK_FAILED


def test_resolver_raising_is_a_stop_not_a_send(lst):
    def boom(host):
        raise OSError("dns down")

    caller = _CountingCaller()
    target = validate_advertised(
        "http://canary.example:%d" % lst.address[1], resolver=lambda h: [PUBLIC])
    res = D.run_driver([SendPlan("t", "url", {}, ("c1",))], caller=caller, listener=lst,
                       key=KEY, run_id=RUN, target=target, settle=0, drain=0, resolver=boom)
    assert caller.calls == 0 and res.stop_reason == D.STOP_RECHECK_FAILED


def test_stale_target_class_is_not_reused_after_rebind_to_local(lst):
    """A hostname re-resolving to loopback after validation as public must not
    keep the stale 'public' class (it would unlock KILL)."""
    answers = iter([[PUBLIC]])
    caller = _CountingCaller()
    target = validate_advertised(
        "http://canary.example:%d" % lst.address[1], resolver=lambda h: [PUBLIC])
    res = D.run_driver(
        [SendPlan("t", "url", {}, ("c1",))], caller=caller, listener=lst, key=KEY,
        run_id=RUN, target=target, settle=0, drain=0,
        resolver=lambda h: ["127.0.0.1"])
    # allow_local is False on the target, so the loopback answer must stop the run
    assert caller.calls == 0 and res.stop_reason == D.STOP_RECHECK_FAILED


# --- 8: URL and bind canonicalization ------------------------------------------

REFUSED_URLS = [
    # trailing dot, odd numeric forms
    "http://169.254.169.254./", "http://169.254.169.254.:80/",
    "http://2852039166/", "http://0xa9fea9fe/", "http://0251.0376.0251.0376/",
    "http://169.254.43518/", "http://0xA9.0xFE.0xA9.0xFE/", "http://169.254.0xa9fe/",
    "http://169.0xfe.169.254/", "http://0300.0250.0.1/", "http://1.1.1.1.1/",
    "http://01.1.1.1/", "http://1.1.1.256/", "http://1.1/", "http://1/",
"http://0x7f.1/", "http://0/",
    # brackets and ipv6 forms
    "http://[fe80::1]/", "http://[FE80::1]/", "http://[fe80::1%25eth0]/",
    "http://[fe80::1%eth0]/", "http://[::ffff:169.254.169.254]/",
    "http://[::ffff:a9fe:a9fe]/", "http://[::FFFF:A9FE:A9FE]/",
    "http://[0:0:0:0:0:ffff:a9fe:a9fe]/", "http://[::a9fe:a9fe]/",
    "http://[64:ff9b::a9fe:a9fe]/", "http://[64:ff9b::169.254.169.254]/",
    "http://[2002:a9fe:a9fe::]/", "http://[2002:a9fe:a9fe::1]/",
    "http://[::ffff:0:a9fe:a9fe]/", "http://[fd00:ec2::254]/",
    "http://[FD00:EC2:0:0:0:0:0:254]/", "http://[fd20:ce::254]/",
    "http://[::ffff:100.100.100.200]/", "http://[::ffff:168.63.129.16]/",
    "http://[2001:0:4136:e378:8000:63bf:3fff:fdd2]/", "http://[::]/", "http://[::ffff:0.0.0.0]/",
    "http://[ff02::1]/", "http://[::ffff:224.0.0.1]/",
    "http://[fe80::5efe:169.254.169.254]/", "http://[::200:5efe:a9fe:a9fe]/",
    "http://[fe80::200:5efe:a9fe:a9fe]/", "http://[2001:db8::5efe:a9fe:a9fe]/",
    "http://[64:ff9b:1::a9fe:a9fe]/",
    "http://[::1", "http://[::1]x/", "http://[::1]:/", "http://[]/",
    # metadata hosts, loopback and other classes
    "http://100.100.100.200/", "http://168.63.129.16/", "http://192.0.0.192/",
    "http://0.0.0.0/", "http://0.1.2.3/", "http://255.255.255.255/", "http://224.0.0.251/",
    # structure
    "http://user@169.254.169.254/", "http://a@b@1.2.3.4/", "http://1.2.3.4#@x/",
    "http://1.2.3.4\\@x/", "http://1.2.3.4?x/", "http://1.2.3.4/p?q", "http://1.2.3.4/p#f",
    "http://1.2.3.4/ x", "http://1.2.3.4/\t", "http://1.2.3.4/\x00", "http://1.2.3.4/\x7f",
    "http://1.2.3.4/é", "http://１.2.3.4/", "http://1.2.3.4%2f@x/",
    "http://169.254.169.254%2e/", "http://%31%36%39.254.169.254/",
    "http://1.2.3.4:80:80/", "http://1.2.3.4:/", "http://1.2.3.4:0/",
    "http://1.2.3.4:65536/", "http://1.2.3.4:-1/", "http://1.2.3.4:８０/",
    "http://1.2.3.4:8_0/", "http://1.2.3.4: 80/", "https://1.2.3.4/", "HTTPS://1.2.3.4/",
    "ftp://1.2.3.4/", "http:1.2.3.4", "//1.2.3.4/", "http:///x", "http://", "",
    "gopher://1.2.3.4/", "file:///etc/passwd", "javascript://x/%0aalert(1)",
]


@pytest.mark.parametrize("url", REFUSED_URLS)
def test_advertised_url_matrix_refused_even_with_allow_local(url):
    resolver = lambda h: ["93.184.216.34"]  # noqa: E731
    with pytest.raises(AdvertisedURLError):
        validate_advertised(url, allow_local=True, resolver=resolver)


@pytest.mark.parametrize("host,answer", [
    ("meta.example", ["169.254.169.254"]),
    ("meta.example", ["::ffff:a9fe:a9fe"]),
    ("meta.example", ["2002:a9fe:a9fe::"]),
    ("meta.example", ["64:ff9b::a9fe:a9fe"]),
    ("meta.example", ["fe80::1%eth0"]),
    ("meta.example", ["93.184.216.34", "169.254.169.254"]),
    ("meta.example", ["169.254.169.254", "93.184.216.34"]),
    ("meta.example", []),
    ("meta.example", ["0x7f000001"]),
    ("meta.example", ["127.1"]),
    ("meta.example", ["2852039166"]),
    ("meta.example", ["169.254.169.254 "]),
])
def test_hostname_resolving_to_a_bad_answer_is_refused_with_allow_local(host, answer):
    with pytest.raises(AdvertisedURLError):
        validate_advertised("http://%s:8080" % host, allow_local=True,
                            resolver=lambda h: answer)


@pytest.mark.parametrize("url,cls", [
    ("http://127.0.0.1:8080/base", "loopback"),
    ("http://[::1]:8080", "loopback"),
    ("http://[::ffff:127.0.0.1]:8080", "loopback"),
    ("http://10.0.0.5:8080", "private"),
    ("http://100.64.0.1:8080", "private"),
    ("http://[fd12::1]:8080", "private"),
    ("http://93.184.216.34:8080", "public"),
    ("http://[2001:4860:4860::8888]:8080", "public"),
    ("http://[64:ff9b::7f00:1]:8080", "loopback"),
    ("http://[2002:0a00:0001::]:8080", "private"),
])
def test_allowed_forms_carry_the_least_public_class(url, cls):
    t = validate_advertised(url, allow_local=True, resolver=lambda h: [PUBLIC])
    assert t.address_class == cls
    if cls != "public":
        with pytest.raises(AdvertisedURLError):
            validate_advertised(url, allow_local=False, resolver=lambda h: [PUBLIC])


@pytest.mark.parametrize("host", [
    "0.0.0.0", "::", "::ffff:0.0.0.0", "10.0.0.5", "192.168.1.1", "169.254.169.254",
    "93.184.216.34", "::ffff:10.0.0.5", "fe80::1", "2001:db8::1",
])
def test_bind_non_loopback_needs_opt_in(host):
    with pytest.raises(BindError):
        validate_bind(host, 8080)
    assert validate_bind(host, 8080, allow_exposed=True).exposed is True


@pytest.mark.parametrize("host", [
    "localhost", "LOCALHOST", "127.0.0.1 ", " 127.0.0.1", "127.1", "0x7f.0.0.1",
    "0177.0.0.1", "2130706433", "127.0.0.1%lo", "::1%lo", "[::1]", "127.0.0.1.",
    "", "example.com", "127.0.0.01", "１２７.0.0.1", "127.0.0.1\n",
])
def test_bind_odd_host_forms_are_refused_even_with_opt_in(host):
    with pytest.raises(BindError):
        validate_bind(host, 8080, allow_exposed=True)


# --- 3/5: report injection -----------------------------------------------------

EVIL = "\x1b]0;PWNED\x07\x1b[2J\x1b[31m<script>alert(1)</script>\"'><img src=x onerror=1>\x9b\x85"
ANSI = ("\x1b", "\x07", "\x9b", "\x85", "\x00", "\r")


def _evil_run(tmp_path, surface):
    evil_tool = "evil" + EVIL
    cand = candidate("id" + EVIL, evil_tool, symbol_extra=None) if False else {
        "id": "id" + EVIL, "source_tool": "src" + EVIL, "source_version": "v" + EVIL,
        "file": "f" + EVIL + ".py", "start_line": 1, "end_line": 2,
        "symbol": evil_tool, "param_names": ["url"], "site_label": "site" + EVIL,
    }
    tools = [{"name": evil_tool, "description": EVIL,
              "inputSchema": {"type": "object", "required": ["url"],
                              "properties": {"url": {"type": "string"}}}}]
    run = Run(tmp_path, [cand])

    def on_call(name, arguments):
        url = arguments["url"]
        path = url[url.index("/", len("http://")):]
        hdrs = ("User-Agent: ua" + EVIL + "\r\nReferer: <script>x</script>" + EVIL +
                "\r\nX-Forwarded-For: " + EVIL + "\r\nAuthorization: Bearer topsecret1234567890\r\n")
        raw_get(("127.0.0.1", run.port), path, hdrs)

    class C(FixtureCaller):
        def call_tool(self, name, arguments, timeout):
            self.calls.append((name, dict(arguments)))
            on_call(name, arguments)
            return self._outcome("result", "echo " + EVIL)

        def stderr_excerpt(self):
            return StderrExcerpt("stderr" + EVIL, True, 999)

    run.caller = C(tools=tools)
    return run, run.argv(attest="note" + EVIL, output=surface) + ["--target-commit", "c" + EVIL]


def test_report_injection_terminal(tmp_path, capsys):
    run, argv = _evil_run(tmp_path, "terminal")
    rc, out, err = run.go(capsys, argv)
    assert "PROVEN" in out
    for bad in ANSI:
        assert bad not in out, repr(bad)
    # the line structure holds: no attacker string can start a forged verdict row
    assert all(not ln.startswith("  forged") for ln in out.splitlines())


def test_report_injection_html(tmp_path, capsys):
    run, argv = _evil_run(tmp_path, "html")
    rc, out, err = run.go(capsys, argv)
    assert "PROVEN" in out
    assert "<script" not in out and "<img" not in out
    assert "onerror=1>" not in out and "&lt;script&gt;" in out


def test_report_injection_json_is_valid_and_data_only(tmp_path, capsys):
    run, argv = _evil_run(tmp_path, "json")
    rc, out, err = run.go(capsys, argv)
    rep = json.loads(out)  # still valid JSON with raw control characters inside
    assert rep["verdicts"][0]["verdict"] == "PROVEN"
    assert "\x1b" not in out  # json escapes control characters
    assert rep["reporting"]["attestation"]["note"].startswith("note")


def test_report_injection_authorization_header_is_masked(tmp_path, capsys):
    run, argv = _evil_run(tmp_path, "json")
    rc, out, err = run.go(capsys, argv)
    assert "topsecret1234567890" not in out


def test_stop_reason_text_is_terminal_safe(tmp_path, capsys):
    run = Run(tmp_path, [candidate("c1", "fetch_url")])
    run.cand_path = write_json(tmp_path / "bad.json", "{" + EVIL)
    rc, out, err = run.go(capsys)
    assert rc == 2
    assert err.startswith("dyetrace: stopped: ")
    for bad in ANSI[:5]:
        assert bad not in err


@pytest.mark.xfail(strict=True, reason=(
    "report._terminal_safe (out of scope for U13) strips C0/C1 and ANSI but not "
    "Unicode bidi overrides, which can visually reorder a hostile string"))
def test_bidi_override_in_untrusted_string_is_neutralized_on_terminal(tmp_path, capsys):
    evil_tool = "tool‮NEVERDONE⁦"
    cand = {"id": "c1", "source_tool": "s", "source_version": "1", "file": "f.py",
            "start_line": 1, "end_line": 2, "symbol": evil_tool, "param_names": ["url"]}
    tools = [{"name": evil_tool, "inputSchema": {"type": "object", "required": ["url"],
              "properties": {"url": {"type": "string"}}}}]
    run = Run(tmp_path, [cand])

    class C(FixtureCaller):
        def call_tool(self, name, arguments, timeout):
            return self._outcome("tool_error", "x")

    run.caller = C(tools=tools)
    rc, out, err = run.go(capsys, run.argv(output="terminal"))
    assert "‮" not in out and "⁦" not in out


# --- mapper: hostile tools/list ------------------------------------------------


def test_duplicate_tool_names_in_catalog_never_guess(tmp_path, capsys):
    dup = [t for t in FixtureCaller().tools if t["name"] == "fetch_url"] * 2
    run = Run(tmp_path, [candidate("c1", "fetch_url")])
    run.caller = FixtureCaller(tools=dup)
    rc, out, err = run.go(capsys)
    if rc == 2:  # a typed stop is also a fail-closed answer
        assert "tools/list" in err
    else:
        assert verdict(json.loads(out), "c1")["verdict"] == "unmapable"
    assert run.caller.calls == []


def test_tool_with_extra_required_args_is_not_called(tmp_path, capsys):
    tools = [{"name": "fetch_url", "inputSchema": {
        "type": "object", "required": ["url", "token"],
        "properties": {"url": {"type": "string"}, "token": {"type": "string"}}}}]
    run = Run(tmp_path, [candidate("c1", "fetch_url")])
    run.caller = FixtureCaller(tools=tools)
    rc, out, err = run.go(capsys)
    assert verdict(json.loads(out), "c1")["verdict"] == "unmapable"
    assert run.caller.calls == [] and rc == 3


@pytest.mark.parametrize("hint", [
    {"tool_name": "not_in_catalog"},
    {"tool_name": "fetch_url", "arg_name": "not_a_property"},
])
def test_hint_not_in_live_catalog_is_unmapable_and_nothing_is_called(tmp_path, capsys, hint):
    run = Run(tmp_path, [candidate("c1", "fetch_url", **hint)])
    rc, out, err = run.go(capsys)
    assert verdict(json.loads(out), "c1")["verdict"] == "unmapable"
    assert run.caller.calls == [] and rc == 3


# --- 8: denial must not render as success --------------------------------------


@pytest.mark.parametrize("url", [
    "http://169.254.169.254:%d", "http://[fd00:ec2::254]:%d", "http://0xa9fea9fe:%d",
    "http://100.100.100.200:%d", "https://127.0.0.1:%d", "http://127.0.0.1.:%d",
])
def test_refused_advertised_url_via_cli_opens_nothing(tmp_path, capsys, url):
    run = Run(tmp_path, [candidate("c1", "fetch_url")])
    opened = []
    argv = run.argv(advertise=False) + ["--advertise", url % run.port]
    rc, out, err = run.go(capsys, argv, caller_factory=lambda t, **kw: opened.append(1),
                          listener_factory=lambda *a: opened.append(2))
    assert rc == 2 and out == "" and not opened
    assert err.startswith("dyetrace: stopped: ")


def test_port_in_use_is_a_stop_and_calls_nothing(tmp_path, capsys):
    run = Run(tmp_path, [candidate("c1", "fetch_url")])
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", run.port))
    blocker.listen(1)
    try:
        rc, out, err = run.go(capsys)
    finally:
        blocker.close()
    assert rc == 2 and "listener failed to start" in err
    assert run.caller.calls == [] and out == ""


def test_every_call_errors_is_exit_3_never_zero(tmp_path, capsys):
    run = Run(tmp_path, [candidate("c1", "fetch_url_guard_raises"), candidate("c2", "echo_url")])
    run.caller = FixtureCaller(tools=FixtureCaller().tools)

    def broken(name, arguments):
        raise RuntimeError("boom")

    class C(FixtureCaller):
        def call_tool(self, name, arguments, timeout):
            self.calls.append((name, dict(arguments)))
            return self._outcome("transport_error", "down")

    run.caller = C()
    rc, out, err = run.go(capsys, run.argv(settle="2"), address_class_override="public")
    rep = json.loads(out)
    assert rc == 3
    assert rep["coverage"]["counts"]["KILL"] == 0 and rep["coverage"]["counts"]["PROVEN"] == 0


def test_listener_closed_mid_run_terminal_says_incomplete(tmp_path, capsys):
    run = Run(tmp_path, [candidate("c1", "fetch_url_safe"), candidate("c2", "echo_url")])
    run.caller = FixtureCaller(on_call=lambda n, a: run.listener.close())
    rc, out, err = run.go(capsys, run.argv(settle="2", output="terminal"),
                          address_class_override="public")
    assert rc == 2
    assert "INCOMPLETE" in out.splitlines()[0]
    assert "KILL" not in [ln.split(" | ")[1] for ln in out.splitlines() if " | " in ln
                          and ln.startswith("  c")]
    assert "listener_unhealthy" in err or "listener" in err


def test_unwritable_out_path_is_a_stop(tmp_path, capsys):
    run = Run(tmp_path, [candidate("c1", "fetch_url")])
    rc, out, err = run.go(capsys, run.argv("--out", str(tmp_path / "nope" / "r.json")))
    assert rc == 2 and "cannot write output file" in err


def test_zero_mapped_never_starts_a_listener(tmp_path, capsys):
    run = Run(tmp_path, [candidate("c1", "no_such_tool")])
    rc, out, err = run.go(capsys, listener_factory=lambda *a: pytest.fail("listener built"))
    assert rc == 3 and run.caller.calls == []
    assert json.loads(out)["verdicts"][0]["verdict"] == "unmapable"


# --- 7: lifecycle ---------------------------------------------------------------


def _threads():
    return {t.name for t in threading.enumerate() if t.name.startswith("dye-listener")}


def test_keyboard_interrupt_mid_call_releases_listener_and_caller(tmp_path):
    run = Run(tmp_path, [candidate("c1", "fetch_url")])

    def boom(name, arguments):
        raise KeyboardInterrupt

    run.caller = FixtureCaller(on_call=boom)
    with pytest.raises(KeyboardInterrupt):
        egresscli.main(run.argv(), caller_factory=lambda t, **kw: run.caller,
                       listener_factory=run.factory, resolver=lambda h: [PUBLIC])
    assert run.listener.closed is True
    assert run.caller.closed >= 1
    assert not _threads()
    s = socket.socket()
    s.bind(("127.0.0.1", run.port))  # the port was released
    s.close()


def test_keyboard_interrupt_in_settle_wait_releases_everything(tmp_path):
    run = Run(tmp_path, [candidate("c1", "echo_url")])

    def hit_wait(entry_id, timeout):
        raise KeyboardInterrupt

    def factory(bind, key, run_id):
        lis = run.factory(bind, key, run_id)
        lis.wait_for_entry = hit_wait
        return lis

    with pytest.raises(KeyboardInterrupt):
        egresscli.main(run.argv(), caller_factory=lambda t, **kw: run.caller,
                       listener_factory=factory, resolver=lambda h: [PUBLIC])
    assert run.listener.closed is True and not _threads()


def test_exception_in_render_still_closes_everything(tmp_path, monkeypatch):
    run = Run(tmp_path, [candidate("c1", "fetch_url")])

    def bad_render(*a, **kw):
        raise RuntimeError("render exploded")

    monkeypatch.setattr(egresscli, "render", bad_render)
    with pytest.raises(RuntimeError):
        egresscli.main(run.argv(), caller_factory=lambda t, **kw: run.caller,
                       listener_factory=run.factory, resolver=lambda h: [PUBLIC])
    assert run.listener.closed is True and run.caller.closed >= 1 and not _threads()


def test_close_racing_in_flight_request_does_not_hang_or_credit(lst):
    s = socket.create_connection(lst.address, timeout=5)
    s.sendall(b"GET /" + tok("1").encode()[:20])  # head incomplete
    assert lst.wait_for(lambda: lst.snapshot().active_connections == 1, 5)
    t0 = time.monotonic()
    lst.close()
    s.close()
    assert time.monotonic() - t0 < 5
    assert lst.snapshot().verified_hits == ()


def _pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:
        with open("/proc/%d/stat" % pid) as fh:
            return fh.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def _fds():
    return len(os.listdir("/proc/self/fd"))


def test_sdk_stdio_run_leaves_no_child_thread_or_fd(tmp_path, capsys):
    pytest.importorskip("mcp")
    run = Run(tmp_path, [candidate("c1", "fetch_url"), candidate("c2", "echo_url")],
              target=stdio_target(sys.executable, SERVER, "egress"))
    before_fds, before_threads = _fds(), threading.active_count()
    rc = egresscli.main(run.argv(), resolver=lambda h: [PUBLIC])
    capsys.readouterr()
    time.sleep(0.5)
    assert rc in (0, 3)
    assert _fds() <= before_fds + 1
    assert threading.active_count() <= before_threads


def test_sdk_keyboard_interrupt_in_drain_kills_the_stdio_child(tmp_path, capsys):
    pytest.importorskip("mcp")
    run = Run(tmp_path, [candidate("c1", "echo_url")],
              target=stdio_target(sys.executable, SERVER, "egress"))
    pids = []

    def sleeper(seconds):
        raise KeyboardInterrupt

    import subprocess as _sp  # test code only; src stays confined

    with pytest.raises(KeyboardInterrupt):
        egresscli.main(run.argv() + ["--drain", "1"], resolver=lambda h: [PUBLIC],
                       sleep=sleeper)
    capsys.readouterr()
    time.sleep(1.0)
    out = _sp.run(["pgrep", "-f", "mcp_fixture_server.py egress"], capture_output=True, text=True)
    assert out.stdout.strip() == "", out.stdout


def test_sdk_server_flooding_stderr_cannot_stall_the_run(tmp_path, capsys):
    pytest.importorskip("mcp")
    run = Run(tmp_path, [candidate("c1", "echo_url")],
              target=stdio_target(sys.executable, SERVER, "egress", "stderr_flood"))
    t0 = time.monotonic()
    rc = egresscli.main(run.argv(), resolver=lambda h: [PUBLIC])
    capsys.readouterr()
    assert time.monotonic() - t0 < 30
