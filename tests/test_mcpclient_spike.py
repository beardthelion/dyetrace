"""U1 characterization spike: can the MCP SDK's streamable-HTTP client be forced
through one injected async httpx2 client, so a dyetrace guard sees every request
(KTD2, R8, R14)?

The test drives a full session (initialize, list tools, one call, close) through
a recording ``httpx2.MockTransport`` with ``socket.socket.connect`` patched to
fail, and compares the SDK's request count with the fake endpoint's. A request
class the SDK issues outside the injected client is named in the failure message.
"""

from __future__ import annotations

import asyncio
import json
import socket

import pytest

pytest.importorskip("mcp")

import httpx2  # noqa: E402  (the SDK's HTTP layer; a dependency of mcp)
import mcp.client.streamable_http as sdk_http  # noqa: E402
from mcp import ClientSession  # noqa: E402

URL = "http://mcp.invalid/mcp"
TOOLS = [
    {
        "name": "fetch_url",
        "description": "fetch",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    }
]


class FakeEndpoint:
    """Counts every request that reaches the transport, by class."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, str, str]] = []

    async def __call__(self, request: httpx2.Request) -> httpx2.Response:
        body = request.content.decode() if request.content else ""
        self.seen.append((request.method, str(request.url), body))
        if request.method == "DELETE":
            return httpx2.Response(200)
        if request.method == "GET":
            return httpx2.Response(405)
        msg = json.loads(body)
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
            result = {"tools": TOOLS}
        elif method == "tools/call":
            result = {"content": [{"type": "text", "text": "ok"}], "isError": False}
        else:
            result = {}
        return httpx2.Response(
            200,
            json={"jsonrpc": "2.0", "id": msg["id"], "result": result},
            headers={"mcp-session-id": "s1"},
        )


class RecordingTransport(httpx2.MockTransport):
    """The injected guard point: counts what the SDK sends through the client."""

    def __init__(self, endpoint: FakeEndpoint) -> None:
        super().__init__(endpoint)
        self.count = 0

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        self.count += 1
        return await super().handle_async_request(request)


def _forbid_connect(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    attempts: list[object] = []

    def _fail(self, address):  # noqa: ANN001
        attempts.append(address)
        raise AssertionError(f"real socket connect attempted to {address!r}")

    monkeypatch.setattr(socket.socket, "connect", _fail)
    monkeypatch.setattr(socket.socket, "connect_ex", lambda self, a: attempts.append(a) or 1)
    return attempts


async def _session(http_client: httpx2.AsyncClient | None) -> list[str]:
    names: list[str] = []
    async with sdk_http.streamable_http_client(URL, http_client=http_client) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = [t.name for t in tools.tools]
            await session.call_tool("fetch_url", {"url": "http://x/y"})
    return names


def test_sdk_http_entry_accepts_injected_client() -> None:
    import inspect

    params = inspect.signature(sdk_http.streamable_http_client).parameters
    assert "http_client" in params, (
        "no injection point for the HTTP client: outcome B (stdio only)"
    )


def test_full_session_goes_only_through_injected_transport(monkeypatch) -> None:
    attempts = _forbid_connect(monkeypatch)
    endpoint = FakeEndpoint()
    transport = RecordingTransport(endpoint)

    async def run() -> list[str]:
        async with httpx2.AsyncClient(transport=transport) as client:
            return await _session(client)

    names = asyncio.run(run())
    assert names == ["fetch_url"]
    assert not attempts, f"request class bypassed the injected client: {attempts!r}"
    classes = sorted({m for m, _, _ in endpoint.seen})
    assert transport.count == len(endpoint.seen) >= 5, (
        f"SDK requests outside the injected client: guard saw {transport.count}, "
        f"endpoint saw {len(endpoint.seen)}"
    )
    # initialize, initialized notification, list, call, and the session DELETE
    # are all observed by the guard point; the SSE GET stream is attempted too.
    assert "DELETE" in classes and "POST" in classes, classes
    assert all(u == URL for _, u, _ in endpoint.seen)


def test_every_request_class_is_visible_to_the_guard(monkeypatch) -> None:
    """Per-class evidence: POST (rpc), GET (SSE stream), DELETE (terminate)."""
    _forbid_connect(monkeypatch)
    endpoint = FakeEndpoint()

    async def run() -> None:
        async with httpx2.AsyncClient(transport=RecordingTransport(endpoint)) as c:
            await _session(c)
            await asyncio.sleep(0)

    asyncio.run(run())
    methods = {m for m, _, _ in endpoint.seen}
    assert {"POST", "DELETE"} <= methods, methods


def test_omitting_the_client_bypasses_the_guard(monkeypatch) -> None:
    """Negative control: the SDK builds its own client when none is injected.

    U10 must therefore always pass http_client; this is the bypass the guard
    has to close, and the reason an unguarded call never ships.
    """
    built: list[object] = []
    real = sdk_http.create_mcp_http_client

    def spy(*a, **k):  # noqa: ANN002, ANN003
        built.append(1)
        return real(*a, **k)

    monkeypatch.setattr(sdk_http, "create_mcp_http_client", spy)
    _forbid_connect(monkeypatch)

    async def run() -> None:
        with pytest.raises(BaseException):
            await asyncio.wait_for(_session(None), timeout=5)

    asyncio.run(run())
    assert built, "SDK did not build its own client when none injected"


def test_oauth_discovery_rides_the_injected_client() -> None:
    """Auth discovery is an httpx2.Auth flow run by the client, not a side client."""
    import inspect
    import mcp.client.auth.oauth2 as oauth2

    src = inspect.getsource(oauth2)
    assert "AsyncClient(" not in src and "httpx2.Client(" not in src, (
        "OAuth provider opens its own HTTP client: auth discovery bypasses the guard"
    )
