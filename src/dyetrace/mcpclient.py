"""MCP client seam for the egress prover (KTD2, R8, R14).

This module holds the U1 spike outcome, the U9 stdio adapter and the U10
guarded streamable-HTTP leg, which share one target schema, one outcome mapping
and one bounded session caller.

OUTCOME A: the HTTP leg can be guarded.

Evidence (``mcp`` 2.3.0, pinned ``mcp>=2.3,<3`` in the ``mcp`` extra, tested in
``tests/test_mcpclient_spike.py``):

- ``mcp.client.streamable_http.streamable_http_client(url, http_client=...)``
  takes an injected ``httpx2.AsyncClient``. The SDK's HTTP layer is ``httpx2``
  (a dependency of ``mcp``), not ``httpx``, so the U10 guard is an
  ``httpx2.AsyncBaseTransport`` handed to an ``httpx2.AsyncClient``, separate
  from the sync ``httpx.Client`` behind ``IdentityClient``.
- A full session (initialize, initialized notification, list tools, call tool,
  close) issues every request through that client: the POSTs, the SSE GET
  attempt and the session DELETE. The recording transport count equals the fake
  endpoint's count, and ``socket.socket.connect`` patched to fail is never hit.
- OAuth discovery is an ``httpx2.Auth`` flow that the injected client runs; the
  provider module opens no client of its own.
- The bypass is the default: when ``http_client`` is omitted the SDK builds its
  own client through ``create_mcp_http_client``. ``session_group`` does the same.
  U10 must always pass ``http_client`` and never use the SDK's URL-string
  conveniences (``mcp.client.Client("http://...")``, session groups).
- Redirects: the SDK follows only same-origin redirects, through the same
  client, so a redirect cannot leave the guarded origin.

Therefore U10 builds the guarded transport (outcome A). Not run in the spike:
a live OAuth flow, and the legacy SSE transport (``mcp.client.sse``), which U10
must not expose.

U10 HTTP leg (KTD2, KTD7, KTD11, R8, R14):

- ``transport: http`` with ``url``. ``build_guarded_http_client`` returns an
  ``httpx2.AsyncClient`` over a guard transport; ``open_http_caller`` always
  hands it to ``streamable_http_client(url, http_client=...)``. Only the
  streamable transport is used; the legacy SSE client is never imported.
- Every request (POST, the SSE GET, DELETE, any OAuth discovery fetch, any
  same-origin redirect hop the SDK follows) passes: the scheme rule (https, or
  http only with ``allow_cleartext``), ``HostGuard.check`` (exact host of the
  server URL, resolve-and-pin, unsafe-address rejection, ``allow_loopback``),
  an awaited second ``HostGuard.check`` placed directly before the inner
  transport call (the post-wait recheck, as in ``IdentityClient.send``), no
  redirect following by the guard, ``accept-encoding: identity`` plus a
  rejection of compressed bodies, a streamed byte cap and a total time cap per
  response (the stream total, since SSE responses are long-lived).
- ``HostGuard.check`` is synchronous and resolves DNS, so it runs on the default
  executor, not on the event loop. A stuck resolver stalls only that request.
- Named limits: the inner transport re-resolves when it dials, so a rebind after
  the recheck remains possible (KTD7). The SDK parses a whole message before the
  byte cap can see it only up to ``byte_cap``; the SDK's own ``max_sse_event_size``
  applies as well. The guard denies hosts named by server-supplied URLs because
  they pass through the same client; the SDK itself follows only same-origin
  redirects.

U9 stdio leg (KTD2, KTD13, R8, R9, R14):

- The target config is operator input only: ``transport: stdio``, ``command`` as
  a list (never a shell string), optional ``env`` map, ``env_passthrough`` names
  and ``cwd``. Candidates and tool output never reach the spawn argv.
- The SDK is imported lazily inside ``_load_sdk`` (a literal ``import mcp``
  statement); a missing SDK raises ``McpSdkMissingError`` before any spawn. The
  SDK spawns the child (this module never imports a process-spawning module).
- The child environment is the SDK's ``get_default_environment()`` (verified in
  ``mcp`` 2.3.0: HOME, LOGNAME, PATH, SHELL, TERM, USER on POSIX, only those
  that are set) merged under the operator's ``env`` and the ``env_passthrough``
  names. Nothing else of the process environment is inherited.
- The child's stderr goes to a pipe drained by a thread into a size-capped
  buffer, never to the inherited terminal. ``stderr_excerpt()`` returns raw
  bounded text; ``render_stderr_excerpt`` neutralizes it at render only.
- ``tools/list`` is bounded (count, serialized bytes, pages, per-tool property
  count, string length) with a typed ``McpCatalogLimitError`` stop. The SDK
  parses a whole message before we can see it, so these bounds cap what the
  mapper and report carry, not the SDK's transient memory.
- Server-initiated requests (sampling, roots, elicitation) get the SDK's default
  decline: no callback is registered, so no capability is advertised and the
  request is answered with a protocol error and no side effect.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import os
import queue
import threading
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from dyetrace.egressdrive import RESULT_TEXT_CAP, CallOutcome
from dyetrace.net import (
    CleartextError,
    HostGuard,
    NetError,
    ResponseTooLargeError,
)
from dyetrace.masking import terminal_safe

__all__ = [
    "TARGET_MAX_BYTES",
    "MAX_TOOLS",
    "MAX_CATALOG_BYTES",
    "MAX_PROPS_PER_TOOL",
    "MAX_STRING_LEN",
    "STDERR_CAPTURE_CAP",
    "STDERR_EXCERPT_CHARS",
    "TargetConfigError",
    "McpClientError",
    "McpSdkMissingError",
    "McpTransportError",
    "McpCatalogLimitError",
    "McpHttpRefusedError",
    "McpResponseLimitError",
    "StdioTarget",
    "HttpTarget",
    "StderrExcerpt",
    "StdioToolCaller",
    "HTTP_BYTE_CAP",
    "HTTP_TOTAL_TIMEOUT",
    "parse_target",
    "load_target",
    "spawn_argv",
    "open_stdio_caller",
    "open_http_caller",
    "open_caller",
    "build_guarded_http_client",
    "HttpToolCaller",
    "render_stderr_excerpt",
]

TARGET_MAX_BYTES = 64 * 1024

MAX_TOOLS = 1000
MAX_CATALOG_BYTES = 512 * 1024
MAX_PROPS_PER_TOOL = 256
MAX_STRING_LEN = 1024
_MAX_PAGES = 20

STDERR_CAPTURE_CAP = 64 * 1024
STDERR_EXCERPT_CHARS = 4096

_START_TIMEOUT = 30.0
_LIST_TIMEOUT = 30.0
_CLOSE_JOIN = 20.0
_ERR_TEXT = 500
INVALID_PARAMS = -32602

HTTP_BYTE_CAP = 8 * 1024 * 1024
HTTP_TOTAL_TIMEOUT = 300.0

_STDIO_KEYS = frozenset({"transport", "command", "env", "env_passthrough", "cwd"})
_HTTP_KEYS = frozenset({"transport", "url"})


class TargetConfigError(Exception):
    """The operator target config failed to load; the run must stop."""


class McpClientError(Exception):
    """Base for adapter failures."""


class McpSdkMissingError(McpClientError):
    """The optional ``mcp`` SDK is not installed."""


class McpTransportError(McpClientError):
    """Spawn, pipe or protocol failure talking to the server."""


class McpCatalogLimitError(McpClientError):
    """tools/list exceeded a bound; the run must stop."""


class McpHttpRefusedError(McpClientError):
    """The HTTP target failed the guard at open (scheme, allowlist, address)."""


class McpResponseLimitError(McpClientError):
    """An HTTP response exceeded the total time cap."""


# --- target config -----------------------------------------------------------


@dataclass(frozen=True)
class StdioTarget:
    command: tuple[str, ...]
    env: dict = field(default_factory=dict)
    env_passthrough: tuple[str, ...] = ()
    cwd: str | None = None


@dataclass(frozen=True)
class HttpTarget:
    url: str


def _str_list(value: Any, where: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise TargetConfigError(f"{where} must be an array of strings")
    for v in value:
        if not isinstance(v, str) or "\x00" in v:
            raise TargetConfigError(f"{where} must hold only strings without NUL")
    return tuple(value)


def _parse_http(cfg: dict) -> HttpTarget:
    unknown = sorted(set(cfg) - _HTTP_KEYS)
    if unknown:
        raise TargetConfigError(f"unknown target key(s): {', '.join(map(repr, unknown))}")
    url = cfg.get("url")
    if not isinstance(url, str) or not url:
        raise TargetConfigError("url must be a non-empty string")
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in url):
        raise TargetConfigError("url must not contain whitespace or control characters")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise TargetConfigError("url is not a valid URL") from None
    if parts.scheme not in ("http", "https"):
        raise TargetConfigError("url scheme must be http or https")
    if not parts.hostname:
        raise TargetConfigError("url must name a host")
    if parts.username is not None or parts.password is not None:
        raise TargetConfigError("url must not carry credentials")
    if parts.fragment or "#" in url:
        raise TargetConfigError("url must not carry a fragment")
    if port == 0:
        raise TargetConfigError("url port must be nonzero")
    return HttpTarget(url)


def parse_target(cfg: Any) -> "StdioTarget | HttpTarget":
    """Validate an already-parsed target config. Strict: unknown keys stop."""
    if not isinstance(cfg, dict):
        raise TargetConfigError("target config must be a JSON object")
    transport = cfg.get("transport")
    if transport == "http":
        return _parse_http(cfg)
    unknown = sorted(set(cfg) - _STDIO_KEYS)
    if unknown:
        raise TargetConfigError(f"unknown target key(s): {', '.join(map(repr, unknown))}")
    if transport != "stdio":
        raise TargetConfigError("target transport must be 'stdio' or 'http'")
    command = cfg.get("command")
    if isinstance(command, str):
        raise TargetConfigError("command must be a list of strings, not a shell string")
    command = _str_list(command, "command") if command is not None else ()
    if not command:
        raise TargetConfigError("command must be a non-empty list of strings")
    if not command[0]:
        raise TargetConfigError("command[0] must be a non-empty string")
    env = cfg.get("env", {})
    if not isinstance(env, dict):
        raise TargetConfigError("env must be an object of string values")
    for k, v in env.items():
        if not isinstance(k, str) or not k or "=" in k or "\x00" in k:
            raise TargetConfigError("env names must be non-empty strings without '=' or NUL")
        if not isinstance(v, str) or "\x00" in v:
            raise TargetConfigError("env values must be strings without NUL")
    passthrough = _str_list(cfg.get("env_passthrough", []), "env_passthrough")
    for n in passthrough:
        if not n or "=" in n:
            raise TargetConfigError("env_passthrough names must be non-empty and contain no '='")
    cwd = cfg.get("cwd")
    if cwd is not None and (not isinstance(cwd, str) or not cwd or "\x00" in cwd):
        raise TargetConfigError("cwd must be a non-empty string")
    return StdioTarget(command, dict(env), passthrough, cwd)


def _no_dupes(pairs: list) -> dict:
    out: dict = {}
    for k, v in pairs:
        if k in out:
            raise TargetConfigError(f"duplicate key {k!r} in target config")
        out[k] = v
    return out


def _no_const(name: str):
    raise TargetConfigError(f"non-finite number {name} in target config")


def load_target(path) -> "StdioTarget | HttpTarget":
    """Load the operator target config file: strict JSON, size-capped."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(TARGET_MAX_BYTES + 1)
    except OSError as exc:
        raise TargetConfigError(f"cannot read target config: {exc.strerror or exc}") from None
    if len(raw) > TARGET_MAX_BYTES:
        raise TargetConfigError(f"target config too large (max {TARGET_MAX_BYTES} bytes)")
    try:
        cfg = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_no_dupes, parse_constant=_no_const)
    except TargetConfigError:
        raise
    except (ValueError, RecursionError) as exc:
        raise TargetConfigError(f"target config is not valid JSON: {exc}") from None
    return parse_target(cfg)


def spawn_argv(target: StdioTarget) -> list[str]:
    """The exact argv the child is spawned with: the operator's command only."""
    return list(target.command)


def _child_env(target: StdioTarget, environ) -> dict[str, str]:
    env: dict[str, str] = {}
    for name in target.env_passthrough:
        if name in environ:
            env[name] = environ[name]
    env.update(target.env)
    return env


# --- lazy SDK ----------------------------------------------------------------


def _load_sdk():
    try:
        import mcp
        from mcp.client.stdio import StdioServerParameters, stdio_client
    except ImportError:
        raise McpSdkMissingError(
            "the MCP SDK is not installed; run: pip install 'dyetrace[mcp]'") from None
    return mcp, StdioServerParameters, stdio_client


# --- stderr capture ------------------------------------------------------------


@dataclass(frozen=True)
class StderrExcerpt:
    text: str  # raw (may hold escape sequences); escape at render only
    truncated: bool
    total_bytes: int


class _StderrCapture:
    """Pipe the child's stderr into a capped buffer, off the terminal."""

    def __init__(self) -> None:
        self._r, w = os.pipe()
        self.writer = os.fdopen(w, "w")
        self._buf = bytearray()
        self.total = 0
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._drain, daemon=True)
        self._thread.start()

    def _drain(self) -> None:
        while True:
            try:
                chunk = os.read(self._r, 65536)
            except OSError:
                return
            if not chunk:
                return
            with self._lock:
                self.total += len(chunk)
                room = STDERR_CAPTURE_CAP - len(self._buf)
                if room > 0:
                    self._buf += chunk[:room]

    def finish(self) -> None:
        try:
            self.writer.close()
        except OSError:
            pass
        self._thread.join(timeout=2.0)
        if not self._thread.is_alive():
            try:
                os.close(self._r)
            except OSError:
                pass

    def excerpt(self) -> StderrExcerpt:
        with self._lock:
            data = bytes(self._buf)
            total = self.total
        text = data.decode("utf-8", errors="replace")
        cut = text[:STDERR_EXCERPT_CHARS]
        return StderrExcerpt(cut, truncated=(total > len(cut.encode("utf-8")) or len(cut) < len(text)),
                             total_bytes=total)


def render_stderr_excerpt(excerpt: StderrExcerpt) -> str:
    """Neutralize ANSI/OSC and control bytes; the only place the excerpt is escaped."""
    out = terminal_safe(excerpt.text)
    if excerpt.truncated:
        out += " [truncated]"
    return out


# --- the caller ------------------------------------------------------------------


def _short(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:_ERR_TEXT]


def _trim_tool(tool: Any, where: str) -> dict:
    def check(s: Any, what: str) -> str:
        if not isinstance(s, str) or len(s) > MAX_STRING_LEN:
            raise McpCatalogLimitError(f"{where}: {what} exceeds {MAX_STRING_LEN} characters")
        return s

    name = check(tool.name, "tool name")
    schema = tool.input_schema if isinstance(tool.input_schema, dict) else {}
    props = schema.get("properties")
    props = props if isinstance(props, dict) else {}
    if len(props) > MAX_PROPS_PER_TOOL:
        raise McpCatalogLimitError(f"{where}: more than {MAX_PROPS_PER_TOOL} properties")
    out_props: dict = {}
    for pname, spec in props.items():
        check(pname, "property name")
        kind = spec.get("type") if isinstance(spec, dict) else None
        out_props[pname] = {"type": check(kind, "property type")} if isinstance(kind, str) else {}
    req = schema.get("required")
    req = req if isinstance(req, list) else []
    if len(req) > MAX_PROPS_PER_TOOL:
        raise McpCatalogLimitError(f"{where}: more than {MAX_PROPS_PER_TOOL} required entries")
    required = [check(r, "required entry") for r in req if isinstance(r, str)]
    return {"name": name, "inputSchema": {"type": "object", "properties": out_props, "required": required}}


def _result_text(res: Any) -> str:
    parts: list[str] = []
    size = 0
    for block in getattr(res, "content", None) or []:
        text = getattr(block, "text", None)
        piece = text if isinstance(text, str) else f"[{getattr(block, 'type', 'content')}]"
        parts.append(piece)
        size += len(piece) + 1
        if size > RESULT_TEXT_CAP + 1:
            break
    # one past the cap so the driver can see and flag truncation
    return "\n".join(parts)[: RESULT_TEXT_CAP + 1]


class _SessionToolCaller:
    """A ToolCaller over an MCP SDK client session (KTD2), transport-agnostic.

    A sync wrapper: the SDK session lives in one asyncio task on a private
    thread; each call is a coroutine handed to it. The connection opens on first
    use; a connect or handshake failure is cached and surfaces as
    ``transport_error`` on calls and ``McpTransportError`` from ``list_tools``.
    Subclasses supply ``_connect`` (an async context manager yielding the SDK
    read and write streams) and ``_after_close``.
    """

    def __init__(self, sdk) -> None:
        self._sdk = sdk
        self._lock = threading.Lock()
        self._started = False
        self._closed = False
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._loop_ready = threading.Event()
        self._ready = threading.Event()
        self._done = threading.Event()
        self._start_error: BaseException | None = None
        self._q: "queue.Queue[tuple | None]" = queue.Queue()
        self._wake: asyncio.Event | None = None
        self._stop: asyncio.Event | None = None

    # -- lifecycle ----------------------------------------------------------

    def _ensure_started(self) -> None:
        with self._lock:
            if self._closed:
                raise McpTransportError("caller is closed")
            if not self._started:
                self._started = True
                self._thread = threading.Thread(
                    target=lambda: asyncio.run(self._main()), name="dyetrace-mcp", daemon=True)
                self._thread.start()
        self._wait_ready()
        if self._start_error is not None:
            raise McpTransportError(_short(self._start_error))

    def _wait_ready(self) -> None:
        while not (self._ready.is_set() or self._done.is_set()):
            self._ready.wait(0.1)

    async def _main(self) -> None:
        mcp = self._sdk[0]
        self._loop = asyncio.get_running_loop()
        self._stop = asyncio.Event()
        self._wake = asyncio.Event()
        self._loop_ready.set()
        try:
            async with self._connect() as (read, write):
                async with mcp.ClientSession(read, write) as session:
                    serve = asyncio.create_task(self._serve(session))
                    stop = asyncio.create_task(self._stop.wait())
                    await asyncio.wait({serve, stop}, return_when=asyncio.FIRST_COMPLETED)
                    for t in (serve, stop):
                        t.cancel()
                    for t in (serve, stop):
                        try:
                            await t
                        except (asyncio.CancelledError, Exception):
                            pass
        except Exception as exc:  # spawn failure, OSError, ExceptionGroup
            if self._start_error is None and not self._ready.is_set():
                self._start_error = exc
        finally:
            self._done.set()
            self._ready.set()
            self._fail_pending()

    async def _serve(self, session) -> None:
        try:
            await asyncio.wait_for(session.initialize(), _START_TIMEOUT)
        except BaseException as exc:  # noqa: BLE001
            self._start_error = exc
            if isinstance(exc, asyncio.CancelledError):
                raise
            return
        self._ready.set()
        while True:
            try:
                item = self._q.get_nowait()
            except queue.Empty:
                self._wake.clear()
                await self._wake.wait()
                continue
            if item is None:
                return
            fn, fut = item
            if fut.cancelled():
                continue
            try:
                fut.set_result(await fn(session))
            except asyncio.CancelledError:
                fut.set_exception(McpTransportError("closed"))
                raise
            except Exception as exc:  # noqa: BLE001
                fut.set_exception(exc)

    def _fail_pending(self) -> None:
        while True:
            try:
                item = self._q.get_nowait()
            except queue.Empty:
                return
            if item is not None and not item[1].done():
                item[1].set_exception(McpTransportError("session ended"))

    def _submit(self, fn, deadline: float) -> Any:
        """Run coroutine factory ``fn(session)`` on the session task; block for it."""
        self._ensure_started()
        fut: concurrent.futures.Future = concurrent.futures.Future()
        self._q.put((fn, fut))
        self._loop.call_soon_threadsafe(self._wake.set)
        end = time.monotonic() + deadline
        while True:
            try:
                return fut.result(timeout=0.1)
            except concurrent.futures.TimeoutError:
                if self._done.is_set() and not fut.done():
                    raise McpTransportError("session ended") from None
                if time.monotonic() >= end:
                    fut.cancel()
                    raise TimeoutError("no answer from the session thread") from None

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            started = self._started
        if started:
            self._loop_ready.wait(5.0)
            if self._loop is not None and self._stop is not None and not self._done.is_set():
                try:
                    self._loop.call_soon_threadsafe(self._stop.set)
                except RuntimeError:
                    pass
            if self._thread is not None:
                self._thread.join(timeout=_CLOSE_JOIN)
        self._after_close()

    def _connect(self):
        raise NotImplementedError

    def _after_close(self) -> None:
        pass

    # -- ToolCaller ----------------------------------------------------------

    def list_tools(self) -> list[dict]:
        async def run(session) -> list[dict]:
            tools: list[dict] = []
            total = 0
            cursor = None
            for _ in range(_MAX_PAGES):
                params = None
                if cursor is not None:
                    params = mcp_types_params(cursor)
                page = await asyncio.wait_for(session.list_tools(params=params), _LIST_TIMEOUT)
                total += len(page.model_dump_json(by_alias=True))
                if total > MAX_CATALOG_BYTES:
                    raise McpCatalogLimitError(f"tools/list exceeds {MAX_CATALOG_BYTES} bytes")
                if len(tools) + len(page.tools) > MAX_TOOLS:
                    raise McpCatalogLimitError(f"tools/list holds more than {MAX_TOOLS} tools")
                for i, t in enumerate(page.tools):
                    tools.append(_trim_tool(t, f"tools[{len(tools) + i}]"))
                cursor = page.next_cursor
                if cursor is None:
                    return tools
            raise McpCatalogLimitError(f"tools/list has more than {_MAX_PAGES} pages")

        try:
            return self._submit(run, _LIST_TIMEOUT * (_MAX_PAGES + 1))
        except McpClientError:
            raise
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                self.close()
                raise
            raise McpTransportError(_short(exc)) from None

    def call_tool(self, name: str, arguments: dict, timeout: float) -> CallOutcome:
        mcp = self._sdk[0]

        async def run(session) -> CallOutcome:
            try:
                res = await asyncio.wait_for(session.call_tool(name, arguments), timeout)
            except (asyncio.TimeoutError, TimeoutError):
                return CallOutcome("timeout", "")
            except mcp.MCPError as exc:
                if exc.code == INVALID_PARAMS:
                    return CallOutcome("invalid_params", str(exc.message)[:_ERR_TEXT])
                return CallOutcome("transport_error", _short(exc))
            if not hasattr(res, "content"):
                return CallOutcome("transport_error", "unexpected result type " + type(res).__name__)
            kind = "tool_error" if getattr(res, "is_error", False) else "result"
            return CallOutcome(kind, _result_text(res))

        try:
            return self._submit(run, timeout + 15.0)
        except TimeoutError:
            return CallOutcome("timeout", "")
        except McpTransportError as exc:
            return CallOutcome("transport_error", str(exc)[:_ERR_TEXT])
        except Exception as exc:  # noqa: BLE001
            return CallOutcome("transport_error", _short(exc))
        except BaseException:
            # KeyboardInterrupt and friends: never leave the child running.
            self.close()
            raise



class StdioToolCaller(_SessionToolCaller):
    """The stdio leg: the SDK spawns the operator-named child on first use."""

    def __init__(self, target: StdioTarget, sdk, environ=None) -> None:
        super().__init__(sdk)
        self._target = target
        self._env = _child_env(target, os.environ if environ is None else environ)
        self._stderr = _StderrCapture()

    def _connect(self):
        _, params_cls, stdio_client = self._sdk
        params = params_cls(
            command=self._target.command[0],
            args=list(self._target.command[1:]),
            env=self._env,
            cwd=self._target.cwd,
        )
        return stdio_client(params, errlog=self._stderr.writer)

    def _after_close(self) -> None:
        self._stderr.finish()

    def stderr_excerpt(self) -> StderrExcerpt:
        return self._stderr.excerpt()



def mcp_types_params(cursor: str):
    import mcp_types

    return mcp_types.PaginatedRequestParams(cursor=cursor)


def open_stdio_caller(target: StdioTarget, environ=None) -> StdioToolCaller:
    """Build the stdio ToolCaller. Raises ``McpSdkMissingError`` before any spawn."""
    sdk = _load_sdk()
    return StdioToolCaller(target, sdk, environ)


# --- U10: the guarded HTTP leg ------------------------------------------------


def _load_http_sdk():
    try:
        import mcp
        import httpx2
        from mcp.client.streamable_http import streamable_http_client
    except ImportError:
        raise McpSdkMissingError(
            "the MCP SDK is not installed; run: pip install 'dyetrace[mcp]'") from None
    return mcp, streamable_http_client, httpx2


def _build_guard_client(
    guard: HostGuard, *, allow_cleartext: bool, byte_cap: int,
    total_timeout: float, transport, httpx2,
):
    """The httpx2 client every SDK request goes through (see the module docstring)."""

    class _Capped(httpx2.AsyncByteStream):
        def __init__(self, inner) -> None:
            self._inner = inner
            self._deadline = time.monotonic() + total_timeout

        async def __aiter__(self):
            total = 0
            it = self._inner.__aiter__()
            try:
                while True:
                    left = self._deadline - time.monotonic()
                    if left <= 0:
                        raise McpResponseLimitError(
                            f"response exceeded the {total_timeout:g}s total time cap")
                    try:
                        chunk = await asyncio.wait_for(it.__anext__(), left)
                    except StopAsyncIteration:
                        return
                    except asyncio.TimeoutError:
                        raise McpResponseLimitError(
                            f"response exceeded the {total_timeout:g}s total time cap") from None
                    total += len(chunk)
                    if total > byte_cap:
                        raise ResponseTooLargeError(f"response body exceeds cap {byte_cap}")
                    yield chunk
            finally:
                await self.aclose()

        async def aclose(self) -> None:
            close = getattr(self._inner, "aclose", None)
            if close is not None:
                await close()

    class _GuardTransport(httpx2.AsyncBaseTransport):
        def __init__(self) -> None:
            self._inner = transport if transport is not None else httpx2.AsyncHTTPTransport()

        @staticmethod
        def _check_scheme(scheme: str) -> None:
            if scheme == "https" or (scheme == "http" and allow_cleartext):
                return
            if scheme == "http":
                raise CleartextError("plain HTTP requires the allow_cleartext flag")
            raise CleartextError(f"unsupported URL scheme: {scheme!r}")

        async def _check_host(self, host: str) -> None:
            # check() resolves DNS synchronously: keep it off the event loop
            await asyncio.get_running_loop().run_in_executor(None, guard.check, host)

        async def handle_async_request(self, request):
            host = request.url.host
            self._check_scheme(request.url.scheme)
            await self._check_host(host)
            # Re-validate after the awaited step and directly before the dial,
            # as IdentityClient.send does around its rate gate.
            await self._check_host(host)
            resp = await self._inner.handle_async_request(request)
            try:
                encoding = resp.headers.get("content-encoding", "").strip().lower()
                if encoding and encoding != "identity":
                    raise ResponseTooLargeError(
                        f"refusing compressed response (content-encoding {encoding!r})")
                declared = resp.headers.get("content-length")
                if declared is not None and declared.isdigit() and int(declared) > byte_cap:
                    raise ResponseTooLargeError(
                        f"declared content-length {declared} exceeds cap {byte_cap}")
            except BaseException:
                await resp.stream.aclose()
                raise
            resp.stream = _Capped(resp.stream)
            return resp

        async def aclose(self) -> None:
            await self._inner.aclose()

    return httpx2.AsyncClient(
        transport=_GuardTransport(),
        follow_redirects=False,
        headers={"accept-encoding": "identity"},
        timeout=httpx2.Timeout(connect=10.0, read=total_timeout, write=30.0, pool=10.0),
    )


def _make_guard(target: HttpTarget, *, allow_loopback: bool, allow_cleartext: bool,
                resolver) -> HostGuard:
    parts = urlsplit(target.url)
    if parts.scheme == "http" and not allow_cleartext:
        raise McpHttpRefusedError("plain HTTP requires --allow-cleartext")
    try:
        return HostGuard([parts.hostname], resolver=resolver, allow_loopback=allow_loopback)
    except NetError as exc:
        raise McpHttpRefusedError(_short(exc)) from None


def build_guarded_http_client(
    target: HttpTarget, *, allow_loopback: bool = False, allow_cleartext: bool = False,
    resolver=None, transport=None, byte_cap: int = HTTP_BYTE_CAP,
    total_timeout: float = HTTP_TOTAL_TIMEOUT,
):
    """An ``httpx2.AsyncClient`` whose every request passes the dyetrace guard."""
    sdk = _load_http_sdk()
    guard = _make_guard(target, allow_loopback=allow_loopback,
                        allow_cleartext=allow_cleartext, resolver=resolver)
    return _build_guard_client(
        guard, allow_cleartext=allow_cleartext, byte_cap=byte_cap,
        total_timeout=total_timeout, transport=transport, httpx2=sdk[2])


class HttpToolCaller(_SessionToolCaller):
    """The HTTP leg: streamable HTTP through the guarded client, always injected."""

    def __init__(self, target: HttpTarget, sdk, guard: HostGuard, *, allow_cleartext: bool,
                 byte_cap: int, total_timeout: float, transport) -> None:
        super().__init__(sdk)
        self._target = target
        self._guard = guard
        self._opts = dict(allow_cleartext=allow_cleartext, byte_cap=byte_cap,
                          total_timeout=total_timeout, transport=transport)

    def _connect(self):
        _, streamable_http_client, httpx2 = self._sdk
        client = _build_guard_client(self._guard, httpx2=httpx2, **self._opts)
        return _owned_http(streamable_http_client, self._target.url, client)


def _owned_http(streamable_http_client, url: str, client):
    @asynccontextmanager
    async def cm():
        async with client:
            async with streamable_http_client(url, http_client=client) as streams:
                yield streams[0], streams[1]

    return cm()


def open_http_caller(
    target: HttpTarget, *, allow_loopback: bool = False, allow_cleartext: bool = False,
    resolver=None, transport=None, byte_cap: int = HTTP_BYTE_CAP,
    total_timeout: float = HTTP_TOTAL_TIMEOUT,
) -> HttpToolCaller:
    """Build the HTTP ToolCaller. Raises ``McpSdkMissingError`` or
    ``McpHttpRefusedError`` before any request is made."""
    sdk = _load_http_sdk()
    guard = _make_guard(target, allow_loopback=allow_loopback,
                        allow_cleartext=allow_cleartext, resolver=resolver)
    return HttpToolCaller(target, sdk, guard, allow_cleartext=allow_cleartext,
                          byte_cap=byte_cap, total_timeout=total_timeout, transport=transport)


def open_caller(target, *, allow_loopback: bool = False, allow_cleartext: bool = False,
                environ=None):
    """Dispatch on the target type; the flags apply to the HTTP leg only."""
    if isinstance(target, HttpTarget):
        return open_http_caller(target, allow_loopback=allow_loopback,
                                allow_cleartext=allow_cleartext)
    return open_stdio_caller(target, environ)
