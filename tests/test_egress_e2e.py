"""U12 end-to-end acceptance suite for `dyetrace egress` (AE1 to AE5, R3, R4, R10, R11, R13).

Layer 1 needs no MCP SDK: a fake ToolCaller dispatches to the fixture tool
logic in egress_fixtures.py, which really connects to the real loopback
Listener, and every case enters through ``egresscli.main``. Layer 2 serves the
same tools over stdio with the real SDK (``pytest.importorskip("mcp")``) and
drives them through the real ``open_caller``.

The KILL cases use the TEST-ONLY ``address_class_override="public"`` seam
(absent from the CLI flags) because a loopback-bound listener is never a
public-class target; a real ``--settle 2`` is needed (settle waits use real
time), so those cases take about two seconds each.
"""

import http.client
import json
import socket
import sys
import threading
from pathlib import Path

import pytest

from dyetrace import egresscli, marker
from dyetrace.egresscand import load_egress_candidates, to_contract
from dyetrace.listener import Listener

from tests.egress_fixtures import (
    FixtureCaller,
    candidate,
    contract,
    free_port,
    stdio_target,
    write_json,
)

FIX = Path(__file__).parent / "fixtures"
SERVER = str(Path(__file__).parent / "mcp_fixture_server.py")
PUBLIC = "93.184.216.34"


class Run:
    """One CLI run against the real Listener on a free explicit port."""

    def __init__(self, tmp_path, cands, caller=None, binds=None, target=None):
        self.tmp = tmp_path
        self.port = free_port()
        self.caller = caller if caller is not None else FixtureCaller()
        self.cand_path = write_json(tmp_path / "cands.json", contract(cands))
        self.target_path = write_json(
            tmp_path / "target.json", target or stdio_target("unused"))
        self.binds_path = write_json(tmp_path / "binds.json", binds) if binds else None
        self.listener = None
        self.key = None
        self.run_id = None
        self.listener_cls = Listener

    def factory(self, bind, key, run_id):
        self.key, self.run_id = key, run_id
        self.listener = self.listener_cls(bind, key, run_id)
        return self.listener

    def argv(self, *extra, attest="lab note", settle="0.3", output="json",
             advertise=True):
        a = ["--candidates", self.cand_path, "--target", self.target_path,
             "--listen", "127.0.0.1:%d" % self.port,
             "--allow-local-advertise", "--settle", settle, "--drain", "0",
             "--rate", "1000", "--output", output]
        if advertise:
            a += ["--advertise", "http://127.0.0.1:%d" % self.port]
        if attest is not None:
            a += ["--attest-listener-reachable", attest]
        if self.binds_path:
            a += ["--binds", self.binds_path]
        return a + list(extra)

    def go(self, capsys, argv=None, **seams):
        seams.setdefault("caller_factory", lambda t, **kw: self.caller)
        seams.setdefault("listener_factory", self.factory)
        seams.setdefault("resolver", lambda h: [PUBLIC])
        rc = egresscli.main(argv if argv is not None else self.argv(), **seams)
        cap = capsys.readouterr()
        return rc, cap.out, cap.err


PROXY_BINDS = {
    "cb": {"tool": "proxy_fetch", "argument": "callback_url",
           "arguments": {"url": "http://example.invalid/ignored"}},
    "cu": {"tool": "proxy_fetch", "argument": "url",
           "arguments": {"callback_url": "none"}},
}


def verdict(rep, cid):
    return next(v for v in rep["verdicts"] if v["id"] == cid)


def reasons(v):
    return set((v["reason"] or "").split("+"))


def reason_of(err):
    assert err.startswith("dyetrace: stopped: "), err
    return err.strip().split("dyetrace: stopped: ", 1)[1]


def send_request(port, path):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        c.request("GET", path)
        c.getresponse().read()
    finally:
        c.close()


# --- AE1: vulnerable tool is PROVEN -----------------------------------------


def test_ae1_vulnerable_fetch_is_proven_with_loopback_evidence(tmp_path, capsys):
    run = Run(tmp_path, [candidate("c1", "fetch_url")])
    rc, out, err = run.go(capsys)
    rep = json.loads(out)
    assert rc == 0, err
    v = verdict(rep, "c1")
    assert v["verdict"] == "PROVEN"
    assert (v["tool"], v["argument"]) == ("fetch_url", "url")
    ev = rep["evidence"][0]
    assert ev["tool"] == "fetch_url" and ev["argument"] == "url"
    arrival = ev["evidence"]["arrivals"][0]
    assert arrival["source"].startswith("127.0.0.1:")
    assert arrival["request_path"] == "/" + ev["evidence"]["token"]
    sent = run.caller.calls[0][1]["url"]
    assert sent == "http://127.0.0.1:%d/%s" % (run.port, ev["evidence"]["token"])
    assert rep["hits"][0]["credited_to"] == ["c1"]


def test_ae1_default_listener_all_surfaces(tmp_path, capsys):
    for surface in ("terminal", "html", "json"):
        run = Run(tmp_path, [candidate("c1", "fetch_url")])
        rc, out, err = run.go(capsys, run.argv(output=surface), listener_factory=None)
        assert rc == 0, err
        assert "PROVEN" in out


def test_echoed_token_in_tool_text_proves_nothing(tmp_path, capsys):
    run = Run(tmp_path, [candidate("c1", "echo_url")])
    rc, out, _ = run.go(capsys)
    rep = json.loads(out)
    v = verdict(rep, "c1")
    assert v["verdict"] == "unexercised"
    assert "DYE-" in run.caller.calls[0][1]["url"]  # the token was sent and echoed
    assert rep["hits"] == [] and rc == 3


# --- AE2: guarded twin ------------------------------------------------------


def test_ae2_guarded_twin_loopback_is_local_class_only(tmp_path, capsys):
    run = Run(tmp_path, [candidate("c1", "fetch_url_safe")])
    rc, out, _ = run.go(capsys, run.argv(settle="2"))
    rep = json.loads(out)
    v = verdict(rep, "c1")
    assert v["verdict"] == "unexercised"
    assert "local_class_only_no_arrival" in reasons(v)
    assert "listener_reachability_unconfirmed" not in reasons(v)
    assert rep["hits"] == [] and rc == 3


def test_ae2_guarded_twin_public_class_override_is_kill(tmp_path, capsys):
    run = Run(tmp_path, [candidate("c1", "fetch_url_safe")])
    rc, out, err = run.go(capsys, run.argv(settle="2"), address_class_override="public")
    rep = json.loads(out)
    v = verdict(rep, "c1")
    assert v["verdict"] == "KILL", v
    assert v["reason"] == "no_arrival_observed"
    assert v["attestation"]["note"] == "lab note"
    assert "unverified" in v["attestation"]["label"]
    assert rc == 0, err
    assert "KILL means no arrival was observed" in rep["reporting"]["limits"]


def test_ae2_no_attestation_is_unconfirmed_never_kill(tmp_path, capsys):
    run = Run(tmp_path, [candidate("c1", "fetch_url_safe")])
    rc, out, _ = run.go(capsys, run.argv(settle="2", attest=None),
                        address_class_override="public")
    v = verdict(json.loads(out), "c1")
    assert v["verdict"] == "unexercised"
    assert "listener_reachability_unconfirmed" in reasons(v)
    assert rc == 3


def test_ae2_short_settle_never_kill_even_attested_public(tmp_path, capsys):
    run = Run(tmp_path, [candidate("c1", "fetch_url_safe")])
    rc, out, _ = run.go(capsys, run.argv(settle="1"), address_class_override="public")
    v = verdict(json.loads(out), "c1")
    assert v["verdict"] == "unexercised"
    assert "settle_window_too_short" in reasons(v)


def test_ae2_raising_guard_variant_is_tool_error(tmp_path, capsys):
    run = Run(tmp_path, [candidate("c1", "fetch_url_guard_raises")])
    rc, out, _ = run.go(capsys, run.argv(settle="2"), address_class_override="public")
    v = verdict(json.loads(out), "c1")
    assert v["verdict"] == "unexercised"
    assert "tool_error" in reasons(v)
    assert rc == 3


# --- unmapable and binds ----------------------------------------------------


def test_unmatched_candidate_is_unmapable_then_a_bind_maps_it(tmp_path, capsys):
    cands = [candidate("c1", "fetch_url"), candidate("c2", "some_other_name")]
    run = Run(tmp_path, cands)
    rc, out, _ = run.go(capsys)
    rep = json.loads(out)
    u = verdict(rep, "c2")
    assert u["verdict"] == "unmapable" and u["reason"]
    assert verdict(rep, "c1")["verdict"] == "PROVEN"
    assert rc == 3
    assert [c[0] for c in run.caller.calls] == ["fetch_url"]

    binds = {"c2": {"tool": "fetch_url", "argument": "url"}}
    run2 = Run(tmp_path, cands, binds=binds)
    rc, out, err = run2.go(capsys)
    rep = json.loads(out)
    assert verdict(rep, "c2")["verdict"] == "PROVEN", rep["verdicts"]
    assert rc == 0, err


# --- AE5: two-argument tool and new_flow ------------------------------------


def test_ae5_proxy_fetch_proven_and_new_flow(tmp_path, capsys):
    # Each candidate names the other argument as a static value so the
    # required-argument check passes; only the callback_url send is fetched.
    cands = [candidate("cb", "proxy_fetch", ("callback_url",)),
             candidate("cu", "proxy_fetch", ("url",))]
    run = Run(tmp_path, cands, binds=PROXY_BINDS)
    rc, out, err = run.go(capsys)
    rep = json.loads(out)
    assert verdict(rep, "cb")["verdict"] == "PROVEN"
    nf = verdict(rep, "cu")
    assert nf["verdict"] == "new_flow"
    assert "callback_url" in nf["note"]
    assert rc == 0, err
    # credit follows the send: only the callback_url send produced the hit
    assert [h["credited_to"] for h in rep["hits"]] == [["cb"]]


# --- real adapter fixture to verdict ----------------------------------------


def test_ssrf_guard_audit_fixture_to_verdict(tmp_path, capsys):
    cs = load_egress_candidates(FIX / "ssrf_guard_audit_scan.json", "ssrf-guard-audit")
    assert {c.symbol for c in cs.candidates} == {
        "check_may_autonomously_fetch_url", "fetch_url"}
    # Neither candidate maps by itself (one symbol has no live tool, the other
    # carries no parameter names), so both are bound explicitly and share a send.
    run = Run(tmp_path, [])
    run.cand_path = str(FIX / "ssrf_guard_audit_scan.json")
    run.binds_path = write_json(tmp_path / "b.json", {
        c.id: {"tool": "fetch_url", "argument": "url"} for c in cs.candidates})
    argv = run.argv() + ["--candidates-format", "ssrf-guard-audit"]
    rc, out, err = run.go(capsys, argv)
    rep = json.loads(out)
    by_sym = {v["symbol"]: v for v in rep["verdicts"]}
    assert by_sym["fetch_url"]["verdict"] == "PROVEN"
    assert by_sym["check_may_autonomously_fetch_url"]["verdict"] == "PROVEN"
    assert rc == 0, err


def test_to_contract_roundtrip_feeds_the_cli(tmp_path, capsys):
    cs = load_egress_candidates(FIX / "ssrf_guard_audit_scan.json", "ssrf-guard-audit")
    run = Run(tmp_path, [])
    run.cand_path = write_json(tmp_path / "norm.json", to_contract(cs))
    rc, out, _ = run.go(capsys)
    rep = json.loads(out)
    # no guess-free map exists for either, so nothing is sent
    assert {v["verdict"] for v in rep["verdicts"]} == {"unmapable"}
    assert run.caller.calls == [] and rc == 3


# --- AE3: refusals leave no socket and no call -------------------------------


def test_ae3_metadata_advertised_no_socket_no_call(tmp_path, capsys, monkeypatch):
    run = Run(tmp_path, [candidate("c1", "fetch_url")])
    made = []
    real = socket.socket

    def spy(*a, **k):
        made.append(a)
        return real(*a, **k)

    monkeypatch.setattr(socket, "socket", spy)

    def boom(*a, **k):
        raise AssertionError("must not be called")

    argv = run.argv(advertise=False) + ["--advertise", "http://169.254.169.254:%d" % run.port]
    rc, out, err = run.go(capsys, argv, caller_factory=boom, listener_factory=boom)
    assert rc == 2
    assert "advertised URL" in reason_of(err)
    assert made == [] and out == ""
    assert run.caller.calls == []


def test_ae3_wildcard_bind_without_opt_in_stops_with_no_socket(tmp_path, capsys, monkeypatch):
    run = Run(tmp_path, [candidate("c1", "fetch_url")])
    made = []
    monkeypatch.setattr(socket, "socket", lambda *a, **k: made.append(a))

    def boom(*a, **k):
        raise AssertionError("must not be called")

    argv = run.argv(advertise=False)
    argv[argv.index("--listen") + 1] = "0.0.0.0:%d" % run.port
    rc, _, err = run.go(capsys, argv, caller_factory=boom, listener_factory=boom)
    assert rc == 2
    assert "bind policy" in reason_of(err)
    assert made == []


# --- AE4 live: forged and foreign tokens are noise ---------------------------


def _inject(run):
    """Hook: send a forged-MAC token and another run's token to the live listener."""
    state = {"sent": False}

    def on_call(name, arguments):
        if state["sent"]:
            return
        state["sent"] = True
        nonce = marker.new_nonce()
        forged = "DYE-%s-1-%s-%s" % (run.run_id, nonce, "0" * 64)
        other = marker.build_token(run.key, marker.new_nonce(), "1", nonce)
        send_request(run.port, "/" + forged)
        send_request(run.port, "/" + other)

    return on_call


def test_ae4_live_forged_and_foreign_tokens_are_noise(tmp_path, capsys):
    run = Run(tmp_path, [candidate("c1", "fetch_url")])
    run.caller = FixtureCaller(on_call=_inject(run))
    rc, out, err = run.go(capsys)
    rep = json.loads(out)
    assert rc == 0, err
    assert verdict(rep, "c1")["verdict"] == "PROVEN"
    assert len(rep["hits"]) == 1  # only the genuine arrival
    assert rep["noise"]["noise_count"] == 2
    snap = run.listener.snapshot()
    assert len(snap.verified_hits) == 1 and snap.noise_count == 2
    assert rep["status"] == "complete"


def test_ae4_live_injection_alone_never_proves(tmp_path, capsys):
    run = Run(tmp_path, [candidate("c1", "fetch_url_safe")])
    run.caller = FixtureCaller(on_call=_inject(run))
    rc, out, _ = run.go(capsys, run.argv(settle="2"), address_class_override="public")
    rep = json.loads(out)
    v = verdict(rep, "c1")
    assert v["verdict"] != "PROVEN" and rep["hits"] == []
    # the run-prefixed unverified arrival also blocks KILL (R11)
    assert v["verdict"] == "unexercised"
    assert "unattributed_arrival" in reasons(v)
    assert rc == 3


# --- bounds in a live run ----------------------------------------------------


def test_noise_flood_during_run_changes_no_verdict(tmp_path, capsys):
    run = Run(tmp_path, [candidate("c1", "fetch_url"), candidate("c2", "echo_url")])

    def flood(name, arguments):
        for i in range(300):
            send_request(run.port, "/noise-%d" % i)

    run.caller = FixtureCaller(on_call=flood)
    rc, out, err = run.go(capsys)
    rep = json.loads(out)
    assert verdict(rep, "c1")["verdict"] == "PROVEN"
    assert verdict(rep, "c2")["verdict"] == "unexercised"
    assert rep["status"] == "complete" and rep["noise"]["noise_count"] >= 600
    assert len(rep["hits"]) == 1
    assert rc == 3


# --- fail closed: listener lost mid-run --------------------------------------


def test_listener_stopped_mid_run_is_incomplete_no_kill(tmp_path, capsys):
    class Dying(Listener):
        dead = False

        def health(self):
            return "failed" if Dying.dead else super().health()

    Dying.dead = False
    run = Run(tmp_path, [candidate("c1", "fetch_url_safe"),
                         candidate("c2", "fetch_url_guard_raises")])
    run.listener_cls = Dying

    def kill_listener(name, arguments):
        Dying.dead = True

    run.caller = FixtureCaller(on_call=kill_listener)
    out_path = tmp_path / "report.json"
    rc, _, err = run.go(capsys, run.argv("--out", str(out_path), settle="2"),
                        address_class_override="public")
    rep = json.loads(out_path.read_text())
    assert rc == 2
    assert "run incomplete" in reason_of(err)
    assert rep["status"] == "incomplete"
    assert all(v["verdict"] != "KILL" for v in rep["verdicts"])
    assert all(v["verdict"] == "unexercised" for v in rep["verdicts"])
    assert rep["coverage"]["counts"]["KILL"] == 0


def test_listener_closed_for_real_mid_run_is_incomplete(tmp_path, capsys):
    run = Run(tmp_path, [candidate("c1", "fetch_url_safe"), candidate("c2", "echo_url")])

    def close_it(name, arguments):
        run.listener.close()

    run.caller = FixtureCaller(on_call=close_it)
    rc, out, err = run.go(capsys, run.argv(settle="2"), address_class_override="public")
    rep = json.loads(out)
    assert rep["status"] == "incomplete", rep["verdicts"]
    assert rc == 2
    assert rep["coverage"]["counts"]["KILL"] == 0


# --- rebind after the first call ---------------------------------------------


def test_rebind_after_first_call_second_send_not_called(tmp_path, capsys):
    run = Run(tmp_path, [candidate("c1", "echo_url"), candidate("c2", "echo_url")],
              binds={"c2": {"tool": "echo_url", "argument": "url",
                            "arguments": {"extra": "x"}}})
    answers = iter([[PUBLIC], [PUBLIC], ["169.254.169.254"]])
    argv = run.argv(advertise=False) + ["--advertise", "http://canary.example:%d" % run.port]
    rc, out, err = run.go(capsys, argv, resolver=lambda h: next(answers, ["169.254.169.254"]))
    rep = json.loads(out)
    assert rc == 2
    assert rep["status"] == "incomplete"
    assert "advertised_recheck_failed" in json.dumps(rep)
    assert len(run.caller.calls) == 1
    assert all(v["verdict"] != "KILL" for v in rep["verdicts"])


# --- layer 2: the real SDK over stdio ----------------------------------------


@pytest.fixture
def sdk_run(tmp_path):
    pytest.importorskip("mcp")

    def make(cands, **kw):
        run = Run(tmp_path, cands, target=stdio_target(sys.executable, SERVER, "egress"), **kw)
        return run

    return make


def sdk_go(run, capsys, argv=None, **seams):
    seams.setdefault("listener_factory", None)
    seams.setdefault("caller_factory", None)
    rc = egresscli.main(argv if argv is not None else run.argv(), **seams)
    cap = capsys.readouterr()
    return rc, cap.out, cap.err


def test_sdk_ae1_vulnerable_proven(sdk_run, capsys):
    run = sdk_run([candidate("c1", "fetch_url")])
    rc, out, err = sdk_go(run, capsys)
    rep = json.loads(out)
    assert rc == 0, err
    assert verdict(rep, "c1")["verdict"] == "PROVEN"
    assert rep["hits"][0]["source"].startswith("127.0.0.1:")


def test_sdk_ae2_guarded_twin_local_class_then_kill_under_override(sdk_run, capsys):
    run = sdk_run([candidate("c1", "fetch_url_safe")])
    rc, out, _ = sdk_go(run, capsys, run.argv(settle="2"))
    v = verdict(json.loads(out), "c1")
    assert v["verdict"] == "unexercised" and "local_class_only_no_arrival" in reasons(v)
    assert rc == 3

    run = sdk_run([candidate("c1", "fetch_url_safe")])
    rc, out, err = sdk_go(run, capsys, run.argv(settle="2"), address_class_override="public")
    assert verdict(json.loads(out), "c1")["verdict"] == "KILL", out[:400]
    assert rc == 0, err


def test_sdk_ae2_no_attestation_and_raising_guard(sdk_run, capsys):
    run = sdk_run([candidate("c1", "fetch_url_safe"), candidate("c2", "fetch_url_guard_raises")])
    rc, out, _ = sdk_go(run, capsys, run.argv(attest=None, settle="0.3"))
    rep = json.loads(out)
    assert "listener_reachability_unconfirmed" in reasons(verdict(rep, "c1"))
    assert "tool_error" in reasons(verdict(rep, "c2"))
    assert rc == 3


def test_sdk_ae5_new_flow_and_unmatched_unmapable(sdk_run, capsys):
    run = sdk_run([candidate("cb", "proxy_fetch", ("callback_url",)),
                   candidate("cu", "proxy_fetch", ("url",)),
                   candidate("cx", "not_a_tool")], binds=PROXY_BINDS)
    rc, out, err = sdk_go(run, capsys)
    rep = json.loads(out)
    assert verdict(rep, "cb")["verdict"] == "PROVEN"
    assert verdict(rep, "cu")["verdict"] == "new_flow"
    assert verdict(rep, "cx")["verdict"] == "unmapable"
    assert rc == 3, err


def test_sdk_echo_tool_text_proves_nothing(sdk_run, capsys):
    run = sdk_run([candidate("c1", "echo_url")])
    rc, out, _ = sdk_go(run, capsys)
    rep = json.loads(out)
    assert verdict(rep, "c1")["verdict"] == "unexercised" and rep["hits"] == []


def test_sdk_ae4_forged_tokens_while_stdio_server_runs(sdk_run, capsys):
    run = sdk_run([candidate("c1", "fetch_url"), candidate("c2", "echo_url")])
    seen = {}

    def factory(bind, key, run_id):
        run.key, run.run_id = key, run_id
        lis = Listener(bind, key, run_id)
        orig_start = lis.start

        def start():
            addr = orig_start()

            def attack():
                nonce = marker.new_nonce()
                send_request(addr[1], "/DYE-%s-1-%s-%s" % (run_id, nonce, "f" * 64))
                send_request(addr[1], "/" + marker.build_token(
                    key, marker.new_nonce(), "1", nonce))
                seen["done"] = True

            threading.Thread(target=attack).start()
            return addr

        lis.start = start
        return lis

    rc, out, err = sdk_go(run, capsys, listener_factory=factory)
    rep = json.loads(out)
    assert seen.get("done")
    assert verdict(rep, "c1")["verdict"] == "PROVEN"
    assert len(rep["hits"]) == 1 and rep["noise"]["noise_count"] >= 2


def test_sdk_ae3_metadata_advertised_spawns_nothing(sdk_run, capsys, tmp_path):
    marker_file = tmp_path / "spawned"
    run = sdk_run([candidate("c1", "fetch_url")])
    run.target_path = write_json(tmp_path / "t2.json", stdio_target(
        sys.executable, "-c", "open(%r, 'w').close()" % str(marker_file)))
    argv = run.argv(advertise=False) + ["--advertise", "http://169.254.169.254:%d" % run.port]
    rc, _, err = sdk_go(run, capsys, argv)
    assert rc == 2 and "advertised URL" in reason_of(err)
    assert not marker_file.exists()
