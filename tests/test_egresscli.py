"""Tests for U11 `dyetrace egress` subcommand (R6, R7, R9, R11, R13, R14, KTD6, KTD12).

Test-first: written before src/dyetrace/egresscli.py exists. The entry takes
injectable seams (resolver, caller_factory, listener_factory, clock, sleep and
the test-only address_class_override), so the whole pipeline runs with a fake
ToolCaller and the real Listener on ephemeral ports (the listener-factory seam
is the only way to ask for port 0). Fakes connect to the listener with stdlib
http.client; no MCP SDK is needed.
"""

import http.client
import json
import socket
import urllib.parse

import pytest

from dyetrace import egresscli
from dyetrace.egressdrive import CallOutcome
from dyetrace.listener import Listener
from dyetrace.mcpclient import (
    McpCatalogLimitError,
    McpSdkMissingError,
    StderrExcerpt,
)

PUBLIC = "93.184.216.34"


def cand(cid="c1", symbol="fetch", params=("url",)):
    return {
        "id": cid, "source_tool": "t", "source_version": "1", "file": "a.py",
        "start_line": 1, "end_line": 2, "symbol": symbol,
        "param_names": list(params),
    }


def tool(name="fetch", props=("url",)):
    return {"name": name, "inputSchema": {
        "type": "object", "properties": {p: {"type": "string"} for p in props}}}


class FakeCaller:
    """A ToolCaller; `fetch` really GETs the URL argument (a vulnerable tool)."""

    def __init__(self, tools=None, fetch=True, fetch_arg="url", kind="result",
                 list_exc=None, excerpt=None):
        self.tools = [tool()] if tools is None else tools
        self.fetch = fetch
        self.fetch_arg = fetch_arg
        self.kind = kind
        self.list_exc = list_exc
        self.calls = []
        self.close_calls = 0
        if excerpt is not None:
            self.stderr_excerpt = lambda: excerpt

    def list_tools(self):
        if self.list_exc is not None:
            raise self.list_exc
        return self.tools

    def call_tool(self, name, arguments, timeout):
        self.calls.append((name, dict(arguments), timeout))
        url = arguments.get(self.fetch_arg)
        if self.fetch and url:
            parts = urllib.parse.urlsplit(url)
            c = http.client.HTTPConnection(parts.hostname, parts.port, timeout=5)
            try:
                c.request("GET", parts.path)
                c.getresponse().read()
            finally:
                c.close()
        return CallOutcome(self.kind, "ok")

    def close(self):
        self.close_calls += 1


class Env:
    """Files, seams and a recorder for one egress run."""

    def __init__(self, tmp_path, cands=None, tools=None, caller=None, binds=None):
        self.tmp = tmp_path
        self.caller = caller or FakeCaller(tools)
        self.listeners = []
        self.caller_args = []
        doc = {"version": 1, "candidates": [cand()] if cands is None else cands}
        self.cand_path = self._w("cands.json", doc)
        self.target_path = self._w("target.json", {"transport": "stdio", "command": ["x"]})
        self.binds_path = self._w("binds.json", binds) if binds is not None else None

    def _w(self, name, obj):
        p = self.tmp / name
        p.write_text(obj if isinstance(obj, str) else json.dumps(obj))
        return str(p)

    def caller_factory(self, target, **kw):
        self.caller_args.append((target, kw))
        return self.caller

    def listener_factory(self, bind, key, run_id):
        lis = Listener(bind, key, run_id)
        self.listeners.append(lis)
        return lis

    def argv(self, *extra, local=True, attest="lab note", output="json", settle="0.2"):
        a = ["--candidates", self.cand_path, "--target", self.target_path,
             "--listen", "127.0.0.1:0", "--settle", settle, "--drain", "0",
             "--rate", "1000", "--output", output]
        if local:
            a.append("--allow-local-advertise")
        if attest is not None:
            a += ["--attest-listener-reachable", attest]
        if self.binds_path:
            a += ["--binds", self.binds_path]
        return a + list(extra)

    def run(self, argv, capsys, **seams):
        seams.setdefault("caller_factory", self.caller_factory)
        seams.setdefault("listener_factory", self.listener_factory)
        seams.setdefault("resolver", lambda h: [PUBLIC])
        seams.setdefault("sleep", lambda s: None)
        rc = egresscli.main(argv, **seams)
        cap = capsys.readouterr()
        return rc, cap.out, cap.err


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def reason(err):
    assert err.startswith("dyetrace: stopped: "), err
    return err.strip().split("dyetrace: stopped: ", 1)[1]


def boom(*a, **k):
    raise AssertionError("must not be called")


# --- happy path and surfaces -------------------------------------------------


def test_happy_proven_exit_0_on_each_surface(tmp_path, capsys):
    for surface in ("terminal", "html", "json"):
        env = Env(tmp_path)
        rc, out, err = env.run(env.argv(output=surface), capsys)
        assert rc == 0, err
        assert "PROVEN" in out
        assert env.caller.close_calls >= 1
        assert env.listeners[0].closed


def test_json_has_coverage_block_and_proven_verdict(tmp_path, capsys):
    env = Env(tmp_path)
    rc, out, _ = env.run(env.argv(), capsys)
    rep = json.loads(out)
    assert rc == 0
    assert rep["coverage"]["counts"]["PROVEN"] == 1
    assert rep["coverage"]["fraction_exercised"] == 1.0
    assert rep["status"] == "complete"


def test_real_listener_default_factory_and_exact_port(tmp_path, capsys):
    port = free_port()
    env = Env(tmp_path)
    argv = ["--candidates", env.cand_path, "--target", env.target_path,
            "--listen", "127.0.0.1:%d" % port,
            "--advertise", "http://127.0.0.1:%d" % port,
            "--allow-local-advertise", "--settle", "0.2", "--drain", "0",
            "--rate", "1000", "--output", "json"]
    rc, out, err = env.run(argv, capsys, listener_factory=None)
    assert rc == 0, err
    assert json.loads(out)["coverage"]["counts"]["PROVEN"] == 1
    url = env.caller.calls[0][1]["url"]
    assert url.startswith("http://127.0.0.1:%d/DYE-" % port)


def test_flags_are_passed_through(tmp_path, capsys):
    env = Env(tmp_path)
    rc, out, _ = env.run(
        env.argv("--target-commit", "abc123", "--call-timeout", "7",
                 "--allow-loopback", "--allow-cleartext"), capsys)
    assert rc == 0
    assert json.loads(out)["reporting"]["target_commit"] == "abc123"
    assert env.caller.calls[0][2] == 7.0
    assert env.caller_args[0][1] == {"allow_loopback": True, "allow_cleartext": True}


def test_candidates_format_adapter_flag(tmp_path, capsys):
    env = Env(tmp_path)
    p = tmp_path / "bad.json"
    p.write_text("{}")
    rc, _, err = env.run(
        ["--candidates", str(p), "--candidates-format", "egress-plane",
         "--target", env.target_path], capsys)
    assert rc == 2
    assert "candidates error" in reason(err)


def test_help_lists_flags(capsys):
    with pytest.raises(SystemExit) as e:
        egresscli.main(["--help"])
    assert e.value.code == 0
    out = capsys.readouterr().out
    for flag in ("--candidates", "--candidates-format", "--binds", "--target",
                 "--listen", "--advertise", "--allow-exposed-bind",
                 "--allow-local-advertise", "--attest-listener-reachable",
                 "--settle", "--drain", "--call-timeout", "--rate", "--max-calls",
                 "--target-commit", "--allow-cleartext", "--allow-loopback",
                 "--output", "--out"):
        assert flag in out


def test_address_class_override_is_not_a_cli_flag(tmp_path, capsys):
    env = Env(tmp_path)
    with pytest.raises(SystemExit) as e:
        egresscli.main(env.argv("--address-class-override", "public"))
    assert e.value.code == 2
    assert "address-class" not in egresscli.build_parser().format_help()


# --- safety refusals ---------------------------------------------------------


def test_metadata_advertised_no_socket_no_call(tmp_path, capsys, monkeypatch):
    env = Env(tmp_path)
    created = []
    real = socket.socket

    class Spy(real):
        def __init__(self, *a, **k):
            created.append(a)
            super().__init__(*a, **k)

    monkeypatch.setattr(socket, "socket", Spy)
    rc, out, err = env.run(
        env.argv("--advertise", "http://169.254.169.254:8099"), capsys,
        caller_factory=boom, listener_factory=boom)
    assert rc == 2
    assert "advertised URL" in reason(err)
    assert created == []


def test_https_advertised_refused(tmp_path, capsys):
    env = Env(tmp_path)
    rc, _, err = env.run(
        env.argv("--advertise", "https://%s:8443" % PUBLIC), capsys,
        caller_factory=boom, listener_factory=boom)
    assert rc == 2
    assert "https" in reason(err)


@pytest.mark.parametrize("listen,adv,needle", [
    ("127.0.0.1:0", "http://%s:8099" % PUBLIC, "port"),
    ("127.0.0.1:8099", "http://%s" % PUBLIC, "port"),
    ("127.0.0.1:8098", "http://%s:8099" % PUBLIC, "port"),
])
def test_port_contract_stops(tmp_path, capsys, listen, adv, needle):
    env = Env(tmp_path)
    argv = env.argv("--advertise", adv)
    argv[argv.index("--listen") + 1] = listen
    rc, _, err = env.run(argv, capsys, caller_factory=boom, listener_factory=boom)
    assert rc == 2
    assert needle in reason(err)
    assert env.listeners == []


def test_port_contract_reasons_are_distinct(tmp_path, capsys):
    reasons = set()
    for listen, adv in (("127.0.0.1:0", "http://%s:8099" % PUBLIC),
                        ("127.0.0.1:8099", "http://%s" % PUBLIC),
                        ("127.0.0.1:8098", "http://%s:8099" % PUBLIC)):
        env = Env(tmp_path)
        argv = env.argv("--advertise", adv)
        argv[argv.index("--listen") + 1] = listen
        rc, _, err = env.run(argv, capsys, caller_factory=boom, listener_factory=boom)
        assert rc == 2
        reasons.add(reason(err))
    assert len(reasons) == 3


def test_port_zero_without_factory_refused(tmp_path, capsys):
    env = Env(tmp_path)
    rc, _, err = env.run(env.argv(), capsys, listener_factory=None, caller_factory=boom)
    assert rc == 2
    assert "port" in reason(err)


def test_wildcard_bind_needs_opt_in(tmp_path, capsys):
    env = Env(tmp_path)
    argv = env.argv("--advertise", "http://%s:8099" % PUBLIC, local=False)
    argv[argv.index("--listen") + 1] = "0.0.0.0:8099"
    rc, _, err = env.run(argv, capsys, caller_factory=boom, listener_factory=boom)
    assert rc == 2
    assert "bind policy" in reason(err)


def test_wildcard_bind_passes_with_flag(tmp_path, capsys):
    env = Env(tmp_path)
    seen = []

    class Fake:
        address = ("0.0.0.0", 8099)

        def __init__(self, bind, key, run_id):
            seen.append(bind)
            self.real = Listener(
                __import__("dyetrace.egressnet", fromlist=["x"]).validate_bind(
                    "127.0.0.1", 0, allow_port_zero=True), key, run_id)

        def __getattr__(self, name):
            return getattr(self.real, name)

        def start(self):
            self.real.start()
            return self.address

    argv = env.argv("--advertise", "http://%s:8099" % PUBLIC, "--allow-exposed-bind",
                    local=False)
    argv[argv.index("--listen") + 1] = "0.0.0.0:8099"
    rc, out, err = env.run(argv, capsys, listener_factory=Fake)
    assert seen and seen[0].host == "0.0.0.0" and seen[0].exposed
    assert rc in (0, 3), err


def test_local_advertise_needs_opt_in(tmp_path, capsys):
    env = Env(tmp_path)
    argv = env.argv("--advertise", "http://127.0.0.1:9", local=False)
    argv[argv.index("--listen") + 1] = "127.0.0.1:9"
    rc, _, err = env.run(argv, capsys, caller_factory=boom, listener_factory=boom)
    assert rc == 2
    assert "advertised URL" in reason(err)


def test_no_advertise_loopback_derived_needs_local_opt_in(tmp_path, capsys):
    env = Env(tmp_path)
    rc, _, err = env.run(env.argv(local=False), capsys, caller_factory=boom,
                         listener_factory=boom)
    assert rc == 2
    assert "advertised URL" in reason(err)


# --- attestation, timing -----------------------------------------------------


def test_no_attestation_is_unconfirmed_never_kill(tmp_path, capsys):
    env = Env(tmp_path, caller=FakeCaller(fetch=False))
    rc, out, _ = env.run(env.argv(attest=None), capsys, address_class_override="public")
    v = json.loads(out)["verdicts"][0]
    assert v["verdict"] == "unexercised"
    assert "listener_reachability_unconfirmed" in v["reason"]
    assert rc == 3


def test_settle_below_minimum(tmp_path, capsys):
    env = Env(tmp_path, caller=FakeCaller(fetch=False))
    rc, out, _ = env.run(env.argv(settle="1"), capsys, address_class_override="public")
    assert "settle_window_too_short" in json.loads(out)["verdicts"][0]["reason"]
    assert rc == 3


def test_empty_attestation_refused(tmp_path, capsys):
    env = Env(tmp_path)
    for note in ("", "   "):
        rc, _, err = env.run(env.argv(attest=note), capsys, caller_factory=boom,
                             listener_factory=boom)
        assert rc == 2
        assert "attestation" in reason(err)


@pytest.mark.parametrize("flag,val", [
    ("--settle", "-1"), ("--drain", "-1"), ("--call-timeout", "0"),
    ("--rate", "0"), ("--max-calls", "0"), ("--settle", "nan"),
])
def test_bad_timing_flags_stop(tmp_path, capsys, flag, val):
    env = Env(tmp_path)
    rc, _, err = env.run(env.argv(flag, val), capsys, caller_factory=boom,
                         listener_factory=boom)
    assert rc == 2
    assert "timing" in reason(err)


def test_kill_under_public_override_with_attestation(tmp_path, capsys):
    env = Env(tmp_path, caller=FakeCaller(fetch=False))
    rc, out, _ = env.run(env.argv(settle="2"), capsys, address_class_override="public")
    rep = json.loads(out)
    assert rep["verdicts"][0]["verdict"] == "KILL"
    att = rep["reporting"]["attestation"]
    assert att["note"] == "lab note"
    assert "operator-asserted" in json.dumps(att).lower()
    assert rc == 0


def test_local_class_without_override_is_not_kill(tmp_path, capsys):
    env = Env(tmp_path, caller=FakeCaller(fetch=False))
    rc, out, _ = env.run(env.argv(settle="2"), capsys)
    v = json.loads(out)["verdicts"][0]
    assert v["verdict"] == "unexercised"
    assert "local_class_only_no_arrival" in v["reason"]
    assert rc == 3


# --- exit code 3 rule --------------------------------------------------------


def test_zero_mapped_no_listener_exit_3(tmp_path, capsys):
    env = Env(tmp_path, cands=[cand(symbol="nomatch")])
    rc, out, err = env.run(env.argv(), capsys, listener_factory=boom)
    rep = json.loads(out)
    assert rc == 3
    assert rep["coverage"]["counts"]["unmapable"] == 1
    assert rep["status"] == "complete"
    assert env.caller.calls == []
    assert env.caller.close_calls >= 1


def test_mixed_proven_and_unmapable_exits_3(tmp_path, capsys):
    env = Env(tmp_path, cands=[cand(), cand("c2", symbol="other")])
    rc, out, _ = env.run(env.argv(), capsys)
    rep = json.loads(out)
    assert rep["coverage"]["counts"]["PROVEN"] == 1
    assert rep["coverage"]["counts"]["unmapable"] == 1
    assert rc == 3


def test_two_arg_new_flow_and_proven_exit_0(tmp_path, capsys):
    caller = FakeCaller([tool("proxy", ("url", "callback_url"))], fetch_arg="callback_url")
    env = Env(tmp_path, cands=[cand("a", "proxy", ("callback_url",)),
                               cand("b", "proxy", ("url",))], caller=caller)
    rc, out, _ = env.run(env.argv(), capsys)
    counts = json.loads(out)["coverage"]["counts"]
    assert counts["PROVEN"] == 1 and counts["new_flow"] == 1
    assert rc == 0


def test_incomplete_run_exits_2_and_writes_report(tmp_path, capsys):
    class Failing(Listener):
        def health(self):
            return "failed"

    env = Env(tmp_path)
    out_path = tmp_path / "rep.txt"
    rc, out, err = env.run(
        env.argv("--out", str(out_path), output="terminal"), capsys,
        listener_factory=lambda b, k, r: Failing(b, k, r))
    assert rc == 2
    assert "run incomplete" in reason(err)
    assert "INCOMPLETE" in out_path.read_text()
    assert env.caller.calls == []


# --- stops, each with its own reason ----------------------------------------


def _stop(env, argv, capsys, **seams):
    rc, out, err = env.run(argv, capsys, **seams)
    assert rc == 2, (out, err)
    return reason(err)


def test_every_stop_has_a_distinct_reason(tmp_path, capsys):
    reasons = {}

    def case(name, env, argv, **seams):
        reasons[name] = _stop(env, argv, capsys, **seams)

    e = Env(tmp_path)
    case("candidates", e, ["--candidates", str(tmp_path / "nope.json"),
                           "--target", e.target_path], )
    e = Env(tmp_path, cands=[])
    case("zero", e, e.argv())
    e = Env(tmp_path, binds="{not json")
    case("binds", e, e.argv())
    e = Env(tmp_path)
    case("target", e, ["--candidates", e.cand_path, "--target", str(tmp_path / "nope.json")])
    e = Env(tmp_path)
    case("advertised", e, e.argv("--advertise", "http://169.254.169.254:80"))
    e = Env(tmp_path)
    case("listen", e, e.argv("--listen", "nonsense"))
    e = Env(tmp_path)
    case("attest", e, e.argv(attest=""))
    e = Env(tmp_path)
    case("timing", e, e.argv("--settle", "-5"))
    e = Env(tmp_path)

    def nosdk(target, **kw):
        raise McpSdkMissingError("install dyetrace[mcp]")

    case("sdk", e, e.argv(), caller_factory=nosdk, listener_factory=boom)
    e = Env(tmp_path, caller=FakeCaller(list_exc=RuntimeError("down")))
    case("list", e, e.argv(), listener_factory=boom)
    e = Env(tmp_path, caller=FakeCaller(list_exc=McpCatalogLimitError("too big")))
    case("catalog_limit", e, e.argv(), listener_factory=boom)
    e = Env(tmp_path, binds={"c1": {"tool": "ghost", "argument": "url"}})
    case("bind_catalog", e, e.argv(), listener_factory=boom)
    e = Env(tmp_path, cands=[cand(), cand("c2", symbol="other")],
            binds={"c2": {"tool": "fetch", "argument": "url", "arguments": {"m": "x"}}})
    case("call_cap", e, e.argv("--max-calls", "1"), listener_factory=boom)

    class NoStart:
        def __init__(self, *a):
            pass

        def start(self):
            raise OSError("address in use")

        def close(self):
            pass

    e = Env(tmp_path)
    case("listener_start", e, e.argv(), listener_factory=NoStart)
    e = Env(tmp_path)
    case("out", e, e.argv("--out", str(tmp_path / "no" / "dir" / "x.json")))

    assert len(set(reasons.values())) == len(reasons), reasons


def test_zero_candidates_stop_text(tmp_path, capsys):
    env = Env(tmp_path, cands=[])
    rc, _, err = env.run(env.argv(), capsys)
    assert rc == 2 and "zero candidates" in reason(err)


def test_missing_sdk_stops_before_listener_with_hint(tmp_path, capsys):
    env = Env(tmp_path)

    def nosdk(target, **kw):
        raise McpSdkMissingError("no mcp")

    rc, _, err = env.run(env.argv(), capsys, caller_factory=nosdk, listener_factory=boom)
    assert rc == 2
    assert "dyetrace[mcp]" in reason(err)


def test_tools_list_failure_closes_caller_no_listener(tmp_path, capsys):
    env = Env(tmp_path, caller=FakeCaller(list_exc=RuntimeError("down")))
    rc, _, err = env.run(env.argv(), capsys, listener_factory=boom)
    assert rc == 2
    assert env.caller.close_calls >= 1


def test_out_unwritable_distinct_stop(tmp_path, capsys):
    env = Env(tmp_path)
    rc, _, err = env.run(env.argv("--out", str(tmp_path / "no" / "x.json")), capsys)
    assert rc == 2
    assert "output" in reason(err)


def test_out_file_written(tmp_path, capsys):
    env = Env(tmp_path)
    p = tmp_path / "r.json"
    rc, out, _ = env.run(env.argv("--out", str(p)), capsys)
    assert rc == 0 and out == ""
    assert json.loads(p.read_text())["coverage"]["total"] == 1


# --- rebind, stderr excerpt, cleanup ----------------------------------------


def test_rebind_after_first_call_stops_second_send(tmp_path, capsys):
    port = free_port()
    env = Env(tmp_path, cands=[cand(), cand("c2", symbol="other")],
              binds={"c2": {"tool": "fetch", "argument": "url", "arguments": {"m": "x"}}})
    answers = iter([[PUBLIC], [PUBLIC], ["169.254.169.254"]])

    def res(host):
        return next(answers, ["169.254.169.254"])

    argv = ["--candidates", env.cand_path, "--target", env.target_path,
            "--binds", env.binds_path, "--listen", "127.0.0.1:%d" % port,
            "--advertise", "http://canary.example:%d" % port,
            "--settle", "0.1", "--drain", "0", "--rate", "1000", "--output", "json",
            "--attest-listener-reachable", "n"]
    rc, out, err = env.run(argv, capsys, resolver=res, listener_factory=None)
    rep = json.loads(out)
    assert rc == 2
    assert rep["status"] == "incomplete"
    assert "advertised_recheck_failed" in json.dumps(rep)
    assert len(env.caller.calls) == 1


def test_stdio_stderr_excerpt_in_report(tmp_path, capsys):
    ex = StderrExcerpt("boom \x1b[31mred\x1b[0m", True, 9999)
    env = Env(tmp_path, caller=FakeCaller(excerpt=ex))
    rc, out, _ = env.run(env.argv(), capsys)
    limits = json.loads(out)["reporting"]["adapter_limits"]
    joined = " ".join(limits)
    assert "boom" in joined and "[truncated]" in joined
    assert "\x1b" not in joined


def test_http_caller_without_excerpt_ok(tmp_path, capsys):
    env = Env(tmp_path)
    rc, out, _ = env.run(env.argv(), capsys)
    assert rc == 0
    assert not any("stderr" in x for x in json.loads(out)["reporting"]["adapter_limits"])


def test_listener_and_caller_closed_on_unexpected_error(tmp_path, capsys):
    env = Env(tmp_path)

    def bad_sleep(s):
        raise RuntimeError("clock exploded")

    with pytest.raises(RuntimeError):
        egresscli.main(
            env.argv("--drain", "1"), caller_factory=env.caller_factory,
            listener_factory=env.listener_factory, sleep=bad_sleep,
            resolver=lambda h: [PUBLIC])
    assert env.caller.close_calls >= 1
    assert env.listeners[0].closed
