"""U9 tests: the MCP SDK adapter, stdio leg (KTD2, KTD13, R8, R9, R14).

SDK-dependent tests use ``pytest.importorskip("mcp")`` through the ``sdk``
fixture; the target loader and the missing-SDK path need no SDK.
"""

from __future__ import annotations

import _thread
import json
import os
import pathlib
import sys
import threading
import time

import pytest

from dyetrace import mcpclient
from dyetrace.egressdrive import RESULT_TEXT_CAP, OUTCOME_KINDS
from dyetrace.egressmap import build_catalog

FIXTURE = str(pathlib.Path(__file__).resolve().parent / "mcp_fixture_server.py")


@pytest.fixture
def sdk():
    pytest.importorskip("mcp")


def _target(*modes: str, **extra) -> mcpclient.StdioTarget:
    cfg = {"transport": "stdio", "command": [sys.executable, FIXTURE, *modes]}
    cfg.update(extra)
    return mcpclient.parse_target(cfg)


@pytest.fixture
def make_caller():
    made = []

    def _make(*modes: str, **extra):
        caller = mcpclient.open_stdio_caller(_target(*modes, **extra))
        made.append(caller)
        return caller

    yield _make
    for c in made:
        c.close()


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # a zombie still answers kill(0); read its state
    try:
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def _wait_dead(pid: int, secs: float = 8.0) -> bool:
    end = time.monotonic() + secs
    while time.monotonic() < end:
        if not _pid_alive(pid):
            return True
        time.sleep(0.05)
    return False


# --- target config loader (no SDK needed) ----------------------------------


def test_parse_target_minimal():
    t = mcpclient.parse_target({"transport": "stdio", "command": ["python", "-V"]})
    assert t.command == ("python", "-V")
    assert t.env == {} and t.env_passthrough == () and t.cwd is None


def test_parse_target_full():
    t = mcpclient.parse_target(
        {
            "transport": "stdio",
            "command": ["srv"],
            "env": {"A": "1"},
            "env_passthrough": ["B"],
            "cwd": "/tmp",
        }
    )
    assert t.env == {"A": "1"} and t.env_passthrough == ("B",) and t.cwd == "/tmp"


@pytest.mark.parametrize(
    "cfg",
    [
        {"transport": "stdio", "command": "python server.py"},  # shell-style string
        {"transport": "stdio", "command": []},
        {"transport": "stdio", "command": ["ok", 3]},
        {"transport": "stdio", "command": ["", "x"]},
        {"transport": "stdio", "command": ["ok"], "args": ["x"]},  # unknown key
        {"transport": "stdio", "command": ["ok"], "shell": True},
        {"transport": "stdio"},
        {"command": ["ok"]},
        {"transport": "carrier-pigeon", "command": ["ok"]},
        {"transport": "stdio", "command": ["ok"], "env": ["A=1"]},
        {"transport": "stdio", "command": ["ok"], "env": {"A": 1}},
        {"transport": "stdio", "command": ["ok"], "env": {"A=B": "1"}},
        {"transport": "stdio", "command": ["ok"], "env_passthrough": "PATH"},
        {"transport": "stdio", "command": ["ok"], "env_passthrough": [1]},
        {"transport": "stdio", "command": ["ok"], "cwd": 5},
        {"transport": "stdio", "command": ["a\x00b"]},
        ["not", "an", "object"],
    ],
)
def test_parse_target_rejects(cfg):
    with pytest.raises(mcpclient.TargetConfigError):
        mcpclient.parse_target(cfg)


def test_load_target_file_ok(tmp_path):
    p = tmp_path / "t.json"
    p.write_text(json.dumps({"transport": "stdio", "command": ["x"]}))
    assert mcpclient.load_target(p).command == ("x",)


@pytest.mark.parametrize(
    "text",
    [
        "{not json",
        '{"transport": "stdio", "command": ["x"], "command": ["y"]}',  # duplicate key
        '{"transport": "stdio", "command": ["x"], "env": {"A": NaN}}',
        "[]",
        "",
    ],
)
def test_load_target_file_rejects_bad_json(tmp_path, text):
    p = tmp_path / "t.json"
    p.write_text(text)
    with pytest.raises(mcpclient.TargetConfigError):
        mcpclient.load_target(p)


def test_load_target_file_size_capped(tmp_path):
    p = tmp_path / "t.json"
    p.write_text('{"transport": "stdio", "command": ["x"], "cwd": "' + "a" * (mcpclient.TARGET_MAX_BYTES + 1) + '"}')
    with pytest.raises(mcpclient.TargetConfigError, match="too large"):
        mcpclient.load_target(p)


def test_load_target_missing_file(tmp_path):
    with pytest.raises(mcpclient.TargetConfigError):
        mcpclient.load_target(tmp_path / "nope.json")


# --- missing SDK ------------------------------------------------------------


def test_missing_sdk_raises_install_hint_and_spawns_nothing(monkeypatch, tmp_path):
    marker = tmp_path / "spawned"
    monkeypatch.setitem(sys.modules, "mcp", None)  # `import mcp` now fails
    target = mcpclient.parse_target(
        {
            "transport": "stdio",
            "command": [sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"],
        }
    )
    with pytest.raises(mcpclient.McpSdkMissingError) as ei:
        mcpclient.open_stdio_caller(target)
    assert "pip install 'dyetrace[mcp]'" in str(ei.value)
    time.sleep(0.3)
    assert not marker.exists()


# --- happy path and outcome mapping (SDK) -----------------------------------


def test_list_tools_feeds_the_catalog(sdk, make_caller):
    caller = make_caller()
    tools = caller.list_tools()
    cat = build_catalog(tools)
    by = {t.name: t for t in cat.tools}
    assert {"echo", "needs_url", "boom", "slow"} <= set(by)
    assert by["needs_url"].properties == ("url", "n")
    assert by["needs_url"].string_properties == ("url",)
    assert by["needs_url"].required == ("url",)
    assert by["echo"].required == ("text",)


def test_call_echo_result(sdk, make_caller):
    out = make_caller().call_tool("echo", {"text": "hello"}, 10)
    assert (out.kind, out.text) == ("result", "hello")
    assert out.kind in OUTCOME_KINDS


def test_is_error_maps_to_tool_error(sdk, make_caller):
    out = make_caller().call_tool("boom", {}, 10)
    assert out.kind == "tool_error" and "it broke" in out.text


def test_missing_required_argument_maps_to_invalid_params(sdk, make_caller):
    out = make_caller().call_tool("needs_url", {}, 10)
    assert out.kind == "invalid_params"


def test_unknown_tool_is_not_a_result(sdk, make_caller):
    out = make_caller().call_tool("no_such_tool", {}, 10)
    assert out.kind != "result"


def test_deadline_maps_to_timeout_and_session_survives(sdk, make_caller):
    caller = make_caller()
    t0 = time.monotonic()
    out = caller.call_tool("slow", {"seconds": 30}, 0.5)
    assert out.kind == "timeout"
    assert time.monotonic() - t0 < 6
    # a later call on the same caller still gets an outcome of a valid kind
    assert caller.call_tool("echo", {"text": "again"}, 5).kind in OUTCOME_KINDS


def test_immediate_exit_maps_to_transport_error(sdk):
    target = mcpclient.parse_target({"transport": "stdio", "command": [sys.executable, "-c", "pass"]})
    caller = mcpclient.open_stdio_caller(target)
    try:
        out = caller.call_tool("echo", {"text": "x"}, 5)
        assert out.kind == "transport_error"
        with pytest.raises(mcpclient.McpTransportError):
            caller.list_tools()
    finally:
        caller.close()


def test_missing_executable_maps_to_transport_error(sdk, tmp_path):
    target = mcpclient.parse_target({"transport": "stdio", "command": [str(tmp_path / "does-not-exist")]})
    caller = mcpclient.open_stdio_caller(target)
    try:
        assert caller.call_tool("echo", {"text": "x"}, 5).kind == "transport_error"
    finally:
        caller.close()


def test_server_death_mid_session_maps_to_transport_error(sdk, make_caller):
    caller = make_caller()
    pid = int(caller.call_tool("pid", {}, 10).text)
    os.kill(pid, 9)
    assert _wait_dead(pid)
    assert caller.call_tool("echo", {"text": "x"}, 5).kind == "transport_error"


# --- edge: result cap, child lifetime ---------------------------------------


def test_oversize_result_is_bounded_but_detectable(sdk, make_caller):
    out = make_caller().call_tool("big", {"n": RESULT_TEXT_CAP * 3}, 20)
    assert out.kind == "result"
    # one past the cap: the driver cuts at the cap and flags truncation
    assert len(out.text) == RESULT_TEXT_CAP + 1


def test_child_gone_after_close(sdk):
    caller = mcpclient.open_stdio_caller(_target())
    pid = int(caller.call_tool("pid", {}, 10).text)
    assert _pid_alive(pid)
    caller.close()
    assert _wait_dead(pid)
    caller.close()  # idempotent


def test_child_gone_after_error(sdk, make_caller):
    caller = make_caller()
    pid = int(caller.call_tool("pid", {}, 10).text)
    assert caller.call_tool("slow", {"seconds": 30}, 0.3).kind == "timeout"
    caller.close()
    assert _wait_dead(pid)


def test_child_gone_after_keyboard_interrupt(sdk):
    caller = mcpclient.open_stdio_caller(_target())
    pid = int(caller.call_tool("pid", {}, 10).text)
    timer = threading.Timer(0.7, _thread.interrupt_main)
    timer.start()
    try:
        with pytest.raises(KeyboardInterrupt):
            caller.call_tool("slow", {"seconds": 60}, 60)
    finally:
        timer.cancel()
    assert _wait_dead(pid)


def test_calls_after_close_are_transport_errors(sdk):
    caller = mcpclient.open_stdio_caller(_target())
    caller.close()
    assert caller.call_tool("echo", {"text": "x"}, 5).kind == "transport_error"


# --- must-not: environment and argv -----------------------------------------


def test_child_env_is_operator_listed_plus_sdk_defaults(sdk, monkeypatch, make_caller):
    from mcp.client.stdio import get_default_environment

    monkeypatch.setenv("DYE_FAKE_SECRET", "hunter2")
    monkeypatch.setenv("DYE_PASSED", "yes")
    caller = make_caller(env={"DYE_OPERATOR": "1"}, env_passthrough=["DYE_PASSED", "DYE_ABSENT_NAME"])
    names = set(json.loads(caller.call_tool("env_names", {}, 10).text))
    expected = set(get_default_environment()) | {"DYE_OPERATOR", "DYE_PASSED"}
    assert "DYE_FAKE_SECRET" not in names
    assert "DYE_ABSENT_NAME" not in names
    # the interpreter may add a locale variable of its own; nothing else may appear
    assert names - expected <= {"LC_CTYPE"}, names - expected
    assert expected <= names


def test_passthrough_is_off_by_default(sdk, monkeypatch, make_caller):
    monkeypatch.setenv("DYE_FAKE_SECRET", "hunter2")
    names = json.loads(make_caller().call_tool("env_names", {}, 10).text)
    assert "DYE_FAKE_SECRET" not in names


def test_candidate_command_fields_never_alter_spawn_argv(sdk, make_caller):
    caller = make_caller()
    hostile = {"text": "x", "command": ["touch", "/tmp/pwn"], "args": ["-rf", "/"]}
    assert caller.call_tool("echo", hostile, 10).kind == "result"
    argv = json.loads(caller.call_tool("argv", {}, 10).text)
    assert argv == [FIXTURE]  # sys.argv of the child: the script alone
    assert mcpclient.spawn_argv(_target()) == [sys.executable, FIXTURE]


# --- must-not: stderr -------------------------------------------------------


def test_child_stderr_never_reaches_our_terminal(sdk, capfd):
    caller = mcpclient.open_stdio_caller(_target("stderr"))
    try:
        assert caller.call_tool("echo", {"text": "x"}, 10).kind == "result"
    finally:
        caller.close()
    cap = capfd.readouterr()
    for stream in (cap.out, cap.err):
        assert "\x1b" not in stream and "\x9b" not in stream and "\x07" not in stream
        assert "pwned" not in stream and "red" not in stream


def test_stderr_excerpt_is_bounded_and_renders_neutralized(sdk):
    caller = mcpclient.open_stdio_caller(_target("stderr"))
    try:
        caller.call_tool("echo", {"text": "x"}, 10)
    finally:
        caller.close()
    ex = caller.stderr_excerpt()
    assert "\x1b" in ex.text  # kept raw for the evidence pack, escaped at render only
    assert len(ex.text) <= mcpclient.STDERR_EXCERPT_CHARS
    shown = mcpclient.render_stderr_excerpt(ex)
    for bad in ("\x1b", "\x07", "\x9b"):
        assert bad not in shown
    assert "red" in shown


def test_stderr_flood_is_capped(sdk):
    caller = mcpclient.open_stdio_caller(_target("stderr_flood"))
    try:
        assert caller.call_tool("echo", {"text": "x"}, 20).kind == "result"
    finally:
        caller.close()
    ex = caller.stderr_excerpt()
    assert ex.truncated
    assert ex.total_bytes > mcpclient.STDERR_CAPTURE_CAP
    assert len(ex.text) <= mcpclient.STDERR_EXCERPT_CHARS


# --- bounds on tools/list and server-initiated requests ---------------------


@pytest.mark.parametrize("mode", ["many_tools", "long_string", "many_props", "huge_catalog"])
def test_oversized_catalog_is_a_typed_stop(sdk, make_caller, mode):
    caller = make_caller(mode)
    with pytest.raises(mcpclient.McpCatalogLimitError):
        caller.list_tools()


def test_catalog_at_the_limits_passes(sdk, make_caller):
    assert len(make_caller().list_tools()) >= 5


def test_server_initiated_requests_are_declined_without_side_effects(sdk, make_caller):
    out = make_caller("sampling").call_tool("poke", {}, 15)
    assert out.kind == "result"
    seen = json.loads(out.text)
    assert seen["sampling"].startswith("error:"), seen
    assert seen["roots"].startswith("error:"), seen


# --- U10: the HTTP leg (outcome A) -------------------------------------------

import asyncio  # noqa: E402
import socket  # noqa: E402

SERVER_URL = "https://mcp.example.test/mcp"
PUBLIC = "93.184.216.34"


class _HttpEndpoint:
    """In-process streamable-HTTP MCP endpoint behind an async handler."""

    def __init__(self, mode: str = "") -> None:
        self.mode = mode
        self.seen: list[tuple[str, str]] = []

    async def __call__(self, request):
        import httpx2

        self.seen.append((request.method, str(request.url)))
        if request.method == "DELETE":
            return httpx2.Response(200)
        if request.method == "GET":
            return httpx2.Response(405)
        msg = json.loads(request.content.decode())
        if "id" not in msg:
            return httpx2.Response(202)
        method = msg["method"]
        if method == "initialize":
            result = {
                "protocolVersion": msg["params"]["protocolVersion"],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake", "version": "0"},
            }
        elif method == "tools/list":
            result = {"tools": [{"name": "fetch_url", "description": "d", "inputSchema": {
                "type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}]}
        elif method == "tools/call":
            if self.mode == "redirect":
                return httpx2.Response(302, headers={"location": "https://evil.example.test/x"})
            if self.mode == "big":
                return httpx2.Response(200, content=b"x" * 300_000,
                                       headers={"content-type": "application/json"})
            if self.mode == "stall":
                return httpx2.Response(200, stream=_Stall(),
                                       headers={"content-type": "text/event-stream"})
            result = {"content": [{"type": "text", "text": "ok"}], "isError": False}
        else:
            result = {}
        return httpx2.Response(
            200, json={"jsonrpc": "2.0", "id": msg["id"], "result": result},
            headers={"mcp-session-id": "s1"})


def _stall_cls():
    import httpx2

    class Stall(httpx2.AsyncByteStream):
        async def __aiter__(self):
            yield b": keepalive\n\n"
            await asyncio.sleep(60)

    return Stall


class _Stall:
    def __new__(cls):
        return _stall_cls()()


def _resolver(*addrs_by_call, default=PUBLIC):
    """Resolver stub: returns the scripted answers in order, then `default`."""
    calls: list[str] = []
    script = list(addrs_by_call)

    def resolve(host):
        calls.append(host)
        return [script.pop(0)] if script else [default]

    resolve.calls = calls  # type: ignore[attr-defined]
    return resolve


def _http_target(url: str = SERVER_URL):
    return mcpclient.parse_target({"transport": "http", "url": url})


@pytest.fixture
def make_http():
    made = []

    def _make(mode: str = "", url: str = SERVER_URL, resolver=None, **kw):
        import httpx2

        endpoint = _HttpEndpoint(mode)
        caller = mcpclient.open_http_caller(
            _http_target(url), resolver=resolver or _resolver(),
            transport=httpx2.MockTransport(endpoint), **kw)
        made.append(caller)
        return caller, endpoint

    yield _make
    for c in made:
        c.close()


def _guarded(endpoint, resolver=None, url=SERVER_URL, **kw):
    import httpx2

    return mcpclient.build_guarded_http_client(
        _http_target(url), resolver=resolver or _resolver(),
        transport=httpx2.MockTransport(endpoint), **kw)


# target schema (no SDK needed)


def test_parse_http_target():
    t = mcpclient.parse_target({"transport": "http", "url": "https://h.example/mcp"})
    assert isinstance(t, mcpclient.HttpTarget) and t.url == "https://h.example/mcp"
    assert mcpclient.parse_target({"transport": "stdio", "command": ["x"]}).command == ("x",)


@pytest.mark.parametrize(
    "cfg",
    [
        {"transport": "http"},
        {"transport": "http", "url": 5},
        {"transport": "http", "url": ""},
        {"transport": "http", "url": "ftp://h/x"},
        {"transport": "http", "url": "https:///x"},
        {"transport": "http", "url": "https://u:p@h/x"},
        {"transport": "http", "url": "https://h/x#frag"},
        {"transport": "http", "url": "https://h/x y"},
        {"transport": "http", "url": "https://h/x\x00"},
        {"transport": "http", "url": "https://h:99999/x"},
        {"transport": "http", "url": "https://h/x", "command": ["x"]},
        {"transport": "http", "url": "https://h/x", "env": {}},
        {"transport": "http", "url": "https://h/x", "headers": {"A": "b"}},
        {"transport": "stdio", "command": ["x"], "url": "https://h/x"},
        {"transport": "sse", "url": "https://h/x"},
    ],
)
def test_parse_http_target_rejects(cfg):
    with pytest.raises(mcpclient.TargetConfigError):
        mcpclient.parse_target(cfg)


def test_load_http_target_file(tmp_path):
    p = tmp_path / "t.json"
    p.write_text(json.dumps({"transport": "http", "url": "https://h.example/mcp"}))
    assert mcpclient.load_target(p).url == "https://h.example/mcp"


def test_missing_sdk_http(monkeypatch):
    monkeypatch.setitem(sys.modules, "mcp", None)
    with pytest.raises(mcpclient.McpSdkMissingError) as ei:
        mcpclient.open_http_caller(_http_target(), resolver=_resolver())
    assert "pip install 'dyetrace[mcp]'" in str(ei.value)


def test_legacy_sse_transport_not_exposed():
    import ast

    tree = ast.parse(pathlib.Path(mcpclient.__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert not (node.module or "").endswith("client.sse"), node.module
            assert all(a.name != "sse_client" for a in node.names)
        elif isinstance(node, ast.Import):
            assert all(not a.name.endswith("client.sse") for a in node.names)


# open-time refusals


def test_cleartext_refused_without_flag(sdk):
    with pytest.raises(mcpclient.McpHttpRefusedError):
        mcpclient.open_http_caller(_http_target("http://mcp.example.test/mcp"), resolver=_resolver())
    c = mcpclient.open_http_caller(
        _http_target("http://mcp.example.test/mcp"), resolver=_resolver(), allow_cleartext=True)
    c.close()


def test_loopback_refused_without_flag(sdk):
    r = _resolver("127.0.0.1", "127.0.0.1")
    with pytest.raises(mcpclient.McpHttpRefusedError):
        mcpclient.open_http_caller(_http_target(), resolver=r)
    mcpclient.open_http_caller(
        _http_target(), resolver=_resolver("127.0.0.1", default="127.0.0.1"), allow_loopback=True).close()


def test_metadata_address_refused_even_with_loopback_allowed(sdk):
    with pytest.raises(mcpclient.McpHttpRefusedError):
        mcpclient.open_http_caller(
            _http_target(), resolver=_resolver("169.254.169.254"), allow_loopback=True)


# happy path and outcome mapping through the real SDK


def test_http_happy_path_every_request_to_the_server(sdk, make_http):
    caller, endpoint = make_http()
    assert [t["name"] for t in caller.list_tools()] == ["fetch_url"]
    out = caller.call_tool("fetch_url", {"url": "http://x/y"}, 15)
    assert out.kind == "result" and out.text == "ok"
    caller.close()
    assert endpoint.seen and {u for _, u in endpoint.seen} == {SERVER_URL}
    assert "POST" in {m for m, _ in endpoint.seen}


def test_http_bypass_control_no_real_socket(sdk, make_http, monkeypatch):
    attempts: list = []

    def fail(self, address):
        attempts.append(address)
        raise AssertionError(f"real connect to {address!r}")

    monkeypatch.setattr(socket.socket, "connect", fail)
    monkeypatch.setattr(socket.socket, "connect_ex", lambda self, a: attempts.append(a) or 1)
    import mcp.client.streamable_http as sdk_http

    def no_default(*a, **k):
        raise AssertionError("SDK built its own unguarded client")

    monkeypatch.setattr(sdk_http, "create_mcp_http_client", no_default)
    caller, endpoint = make_http()
    caller.list_tools()
    assert caller.call_tool("fetch_url", {"url": "u"}, 15).kind == "result"
    caller.close()
    assert not attempts
    assert {m for m, _ in endpoint.seen} >= {"POST", "DELETE"}


def test_resolver_runs_off_the_event_loop(sdk, make_http):
    main = threading.get_ident()
    idents: list[int] = []

    def resolve(host):
        idents.append(threading.get_ident())
        return [PUBLIC]

    caller, _ = make_http(resolver=resolve)
    caller.list_tools()
    caller.close()
    assert len(idents) > 2 and all(i != main for i in idents[1:]), idents


# the guard, driven directly (no SDK needed beyond httpx2)


@pytest.mark.parametrize("method", ["POST", "GET", "DELETE", "PUT"])
def test_non_allowlisted_host_refused_before_transport(method):
    pytest.importorskip("httpx2")
    from dyetrace.net import AllowlistError

    endpoint = _HttpEndpoint()

    async def run():
        async with _guarded(endpoint) as client:
            # an OAuth discovery document, an SSE GET, a DELETE: all hosts are checked
            with pytest.raises(AllowlistError):
                await client.request(method, "https://evil.example.test/.well-known/oauth-protected-resource")

    asyncio.run(run())
    assert endpoint.seen == []


def test_exact_host_only_no_subdomain_or_port_trick():
    pytest.importorskip("httpx2")
    from dyetrace.net import AllowlistError

    endpoint = _HttpEndpoint()

    async def run():
        async with _guarded(endpoint) as client:
            for u in ("https://sub.mcp.example.test/", "https://mcp.example.test.evil.test/"):
                with pytest.raises(AllowlistError):
                    await client.get(u)

    asyncio.run(run())
    assert endpoint.seen == []


def test_redirect_is_returned_not_followed():
    pytest.importorskip("httpx2")
    endpoint = _HttpEndpoint("redirect")

    async def run():
        async with _guarded(endpoint) as client:
            r = await client.post(SERVER_URL, content=json.dumps(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}}))
            return r.status_code, r.headers["location"]

    assert asyncio.run(run()) == (302, "https://evil.example.test/x")
    assert endpoint.seen == [("POST", SERVER_URL)]


def test_sdk_does_not_follow_a_cross_host_redirect(sdk, make_http):
    caller, endpoint = make_http("redirect")
    caller.list_tools()
    out = caller.call_tool("fetch_url", {"url": "u"}, 10)
    caller.close()
    assert out.kind == "transport_error", out
    assert not [u for _, u in endpoint.seen if "evil" in u]


def test_plain_http_refused_per_request_without_cleartext():
    pytest.importorskip("httpx2")
    from dyetrace.net import CleartextError

    endpoint = _HttpEndpoint()

    async def run():
        async with _guarded(endpoint) as client:
            with pytest.raises(CleartextError):
                await client.get("http://mcp.example.test/mcp")

    asyncio.run(run())
    assert endpoint.seen == []


def test_rebind_across_an_awaited_step_sends_nothing():
    """resolver: safe (pin), safe (first check), then metadata (adjacent recheck)."""
    pytest.importorskip("httpx2")
    from dyetrace.net import UnsafeAddressError

    endpoint = _HttpEndpoint()
    r = _resolver(PUBLIC, PUBLIC, "169.254.169.254")

    async def run():
        async with _guarded(endpoint, resolver=r) as client:
            with pytest.raises(UnsafeAddressError):
                await client.post(SERVER_URL, content=b"{}")

    asyncio.run(run())
    assert len(r.calls) == 3
    assert endpoint.seen == [], "the rebind slipped past the adjacent recheck"


def test_rebind_after_pinning_is_caught_on_every_request():
    pytest.importorskip("httpx2")
    from dyetrace.net import UnsafeAddressError

    endpoint = _HttpEndpoint()
    r = _resolver(PUBLIC, PUBLIC, PUBLIC, "10.0.0.5")

    async def run():
        async with _guarded(endpoint, resolver=r) as client:
            await client.post(SERVER_URL, content=b"{}")
            with pytest.raises(UnsafeAddressError):
                await client.post(SERVER_URL, content=b"{}")

    asyncio.run(run())
    assert len(endpoint.seen) == 1


def test_byte_cap_aborts_with_typed_error():
    pytest.importorskip("httpx2")
    from dyetrace.net import ResponseTooLargeError

    endpoint = _HttpEndpoint("big")
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}})

    async def run():
        async with _guarded(endpoint, byte_cap=64 * 1024) as client:
            with pytest.raises(ResponseTooLargeError):
                await client.post(SERVER_URL, content=body)

    asyncio.run(run())


def test_declared_oversize_and_compressed_responses_refused():
    pytest.importorskip("httpx2")
    import httpx2
    from dyetrace.net import ResponseTooLargeError

    def handler(h):
        async def go(request):
            return httpx2.Response(200, content=b"x", headers=h)
        return go

    async def run(h):
        client = mcpclient.build_guarded_http_client(
            _http_target(), resolver=_resolver(), byte_cap=1000,
            transport=httpx2.MockTransport(handler(h)))
        async with client:
            with pytest.raises(ResponseTooLargeError):
                await client.get(SERVER_URL)

    asyncio.run(run({"content-length": "5000"}))
    asyncio.run(run({"content-encoding": "gzip"}))


def test_total_time_cap_aborts_a_stalled_stream():
    pytest.importorskip("httpx2")
    endpoint = _HttpEndpoint("stall")
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}})

    async def run():
        async with _guarded(endpoint, total_timeout=0.5) as client:
            with pytest.raises(mcpclient.McpResponseLimitError):
                await client.post(SERVER_URL, content=body)

    start = time.monotonic()
    asyncio.run(run())
    assert time.monotonic() - start < 10


def test_oversize_response_maps_to_transport_error(sdk, make_http):
    caller, _ = make_http("big", byte_cap=64 * 1024)
    caller.list_tools()
    out = caller.call_tool("fetch_url", {"url": "u"}, 10)
    caller.close()
    assert out.kind == "transport_error", out


def test_stalled_stream_maps_to_transport_error(sdk, make_http):
    caller, _ = make_http("stall", total_timeout=1.0)
    caller.list_tools()
    start = time.monotonic()
    out = caller.call_tool("fetch_url", {"url": "u"}, 20)
    caller.close()
    assert out.kind in ("transport_error", "timeout"), out
    assert time.monotonic() - start < 15


def test_call_after_rebind_is_transport_error_and_sends_nothing(sdk, make_http):
    caller, endpoint = make_http()
    caller.list_tools()
    n = len(endpoint.seen)
    # rebind the live guard's DNS answer to the metadata address
    caller._guard._resolver = _resolver("169.254.169.254", default="169.254.169.254")
    out = caller.call_tool("fetch_url", {"url": "u"}, 10)
    caller.close()
    assert out.kind == "transport_error", out
    assert len(endpoint.seen) == n
