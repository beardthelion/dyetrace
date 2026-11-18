"""Fixture tool logic and builders for the egress end-to-end suite (U12).

Test helper, not shipped. ``fetch_url`` is deliberately vulnerable: it does a
real stdlib HTTP GET of whatever URL it is given. ``fetch_url_safe`` is the
guarded twin: it refuses loopback, private and link-local targets and returns
a normal (non-error) refusal text, which is the common SSRF fix and the shape
that must never be cleared by a loopback probe. ``fetch_url_guard_raises``
raises on a refused target (an ``isError`` result). ``proxy_fetch`` validates
and ignores ``url`` and fetches ``callback_url``. ``echo_url`` never fetches
but returns its argument in the result text.

``FixtureCaller`` is a ToolCaller (list_tools / call_tool / close) that
dispatches to this logic, so layer 1 needs no MCP SDK. The same logic is
served over stdio by ``mcp_fixture_server.py`` in ``egress`` mode for layer 2.
This module imports only the stdlib at import time, because the server script
loads it as a top-level module.
"""

import http.client
import ipaddress
import json
import socket
import urllib.parse

GUARD_REFUSAL = "refused: target is not a public address"


class GuardRefused(Exception):
    """Raised by the raising guard variant."""


def http_get(url, timeout=5):
    """A real stdlib GET; returns the status code."""
    parts = urllib.parse.urlsplit(url)
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=timeout)
    try:
        conn.request("GET", parts.path or "/")
        resp = conn.getresponse()
        resp.read()
        return resp.status
    finally:
        conn.close()


def is_local_target(url):
    """True when the URL's host is (or resolves to) a non-public address."""
    host = urllib.parse.urlsplit(url).hostname
    if not host:
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return True
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_loopback or ip.is_private or ip.is_link_local
                or ip.is_unspecified or ip.is_multicast or ip.is_reserved):
            return True
    return False


def fetch_url(url):
    """Vulnerable: no guard."""
    return "fetched %d" % http_get(url)


def fetch_url_safe(url):
    """Guarded twin: a refusal is a normal result, not an error."""
    if is_local_target(url):
        return GUARD_REFUSAL
    return "fetched %d" % http_get(url)


def fetch_url_guard_raises(url):
    """Raising guard variant."""
    if is_local_target(url):
        raise GuardRefused(GUARD_REFUSAL)
    return "fetched %d" % http_get(url)


def proxy_fetch(url, callback_url):
    """Validates and ignores ``url``; fetches ``callback_url``."""
    if not url.startswith("http"):
        return "bad url"
    if not callback_url.startswith("http"):
        return "no callback"
    return "proxied %d" % http_get(callback_url)


def echo_url(url):
    """Never fetches; reflects the argument (a token echoed in text proves nothing)."""
    return "you said " + url


def _schema(*props):
    return {"type": "object", "required": list(props),
            "properties": {p: {"type": "string"} for p in props}}


# name -> (logic, argument names). The one source for both layers.
LOGIC = {
    "fetch_url": (fetch_url, ("url",)),
    "fetch_url_safe": (fetch_url_safe, ("url",)),
    "fetch_url_guard_raises": (fetch_url_guard_raises, ("url",)),
    "proxy_fetch": (proxy_fetch, ("url", "callback_url")),
    "echo_url": (echo_url, ("url",)),
}

TOOLS = [{"name": name, "description": "fixture", "inputSchema": _schema(*args)}
         for name, (_fn, args) in LOGIC.items()]


class FixtureCaller:
    """A ToolCaller over the fixture logic; connects to the real listener.

    ``on_call(name, arguments)`` runs before the logic (used to inject traffic
    into a live run). A raising tool maps to ``tool_error`` like a real server.
    """

    def __init__(self, on_call=None, tools=None):
        from dyetrace.egressdrive import CallOutcome
        self._outcome = CallOutcome
        self.on_call = on_call
        self.tools = TOOLS if tools is None else tools
        self.calls = []
        self.closed = 0

    def list_tools(self):
        return self.tools

    def call_tool(self, name, arguments, timeout):
        self.calls.append((name, dict(arguments)))
        if self.on_call is not None:
            self.on_call(name, arguments)
        fn = LOGIC[name][0]
        try:
            return self._outcome("result", fn(**arguments))
        except Exception as exc:  # a server turns a raising tool into isError
            return self._outcome("tool_error", str(exc))

    def close(self):
        self.closed += 1


# --- builders ---------------------------------------------------------------


def candidate(cid, symbol, params=("url",), **extra):
    """One normalized egress-candidates entry (dict form)."""
    c = {
        "id": cid, "source_tool": "fixture-scan", "source_version": "1",
        "file": "server.py", "start_line": 1, "end_line": 9, "symbol": symbol,
        "param_names": list(params),
    }
    c.update(extra)
    return c


def contract(cands):
    return {"version": 1, "candidates": list(cands)}


def write_json(path, obj):
    path.write_text(obj if isinstance(obj, str) else json.dumps(obj), encoding="utf-8")
    return str(path)


def stdio_target(*command):
    return {"transport": "stdio", "command": list(command)}


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port
