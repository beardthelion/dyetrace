"""Stdio MCP fixture server for the U9 adapter tests (test helper, not shipped).

Run as ``python mcp_fixture_server.py [mode ...]``. Modes:

- ``stderr``: write ANSI and OSC escape sequences to stderr at startup.
- ``stderr_flood``: write far more than the capture cap to stderr.
- ``many_tools``: advertise more tools than the adapter's count cap.
- ``long_string``: advertise a tool whose property name exceeds the string cap.
- ``many_props``: advertise a tool with more properties than the per-tool cap.
- ``huge_catalog``: advertise a catalog above the byte cap.
- ``egress``: serve the egress end-to-end tools from ``egress_fixtures``
  (``fetch_url``, ``fetch_url_safe``, ``fetch_url_guard_raises``,
  ``proxy_fetch``, ``echo_url``) instead of the default catalog.
- ``sampling``: the ``poke`` tool sends a sampling request, a roots request and
  an elicitation request to the client and reports how the client answered.

Tools: ``echo(text)``, ``needs_url(url)`` (url required, string), ``boom`` (an
isError result), ``slow(seconds)``, ``big(n)`` (n characters), ``env_names``
(sorted names of the process environment), ``pid``, ``argv``, ``poke``.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import warnings

import mcp_types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import MCPError

MODES = set(sys.argv[1:])

_STR = {"type": "string"}


def _tool(name: str, props: dict, required: list[str]) -> types.Tool:
    return types.Tool(
        name=name,
        description="fixture",
        input_schema={"type": "object", "properties": props, "required": required},
    )


def _catalog() -> list[types.Tool]:
    if "egress" in MODES:
        import egress_fixtures

        return [
            _tool(name, {a: _STR for a in args}, list(args))
            for name, (_fn, args) in egress_fixtures.LOGIC.items()
        ]
    if "many_tools" in MODES:
        return [_tool(f"t{i}", {"url": _STR}, []) for i in range(1200)]
    if "long_string" in MODES:
        return [_tool("long", {"p" * 5000: _STR}, [])]
    if "many_props" in MODES:
        return [_tool("props", {f"p{i}": _STR for i in range(400)}, [])]
    if "huge_catalog" in MODES:
        return [_tool(f"h{i}", {"q" * 40 + str(j): _STR for j in range(150)}, []) for i in range(80)]
    return [
        _tool("echo", {"text": _STR}, ["text"]),
        _tool("needs_url", {"url": _STR, "n": {"type": "integer"}}, ["url"]),
        _tool("boom", {}, []),
        _tool("slow", {"seconds": {"type": "number"}}, []),
        _tool("big", {"n": {"type": "integer"}}, []),
        _tool("env_names", {}, []),
        _tool("poke", {}, []),
        _tool("pid", {}, []),
        _tool("argv", {}, []),
    ]


def _text(s: str, is_error: bool = False) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(text=s)], is_error=is_error)


async def on_list_tools(ctx, params):  # noqa: ANN001
    return types.ListToolsResult(tools=_catalog())


async def on_call_tool(ctx, params):  # noqa: ANN001
    name, args = params.name, params.arguments or {}
    if "egress" in MODES:
        import egress_fixtures

        entry = egress_fixtures.LOGIC.get(name)
        if entry is None:
            raise MCPError(types.METHOD_NOT_FOUND, "no such tool")
        try:
            return _text(await asyncio.to_thread(entry[0], **args))
        except Exception as exc:  # noqa: BLE001
            return _text(str(exc), is_error=True)
    if name == "echo":
        if "text" not in args:
            raise MCPError(types.INVALID_PARAMS, "text is required")
        return _text(str(args["text"]))
    if name == "needs_url":
        if "url" not in args:
            raise MCPError(types.INVALID_PARAMS, "url is required")
        return _text("fetched " + str(args["url"]))
    if name == "boom":
        return _text("it broke", is_error=True)
    if name == "slow":
        await asyncio.sleep(float(args.get("seconds", 30)))
        return _text("slow done")
    if name == "big":
        return _text("x" * int(args.get("n", 0)))
    if name == "env_names":
        return _text(json.dumps(sorted(os.environ)))
    if name == "pid":
        return _text(str(os.getpid()))
    if name == "argv":
        return _text(json.dumps(sys.argv))
    if name == "poke":
        seen = {}
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            try:
                r = await ctx.session.create_message(
                    [types.SamplingMessage(role="user", content=types.TextContent(text="hi"))],
                    max_tokens=5,
                )
                seen["sampling"] = "answered:" + type(r).__name__
            except MCPError as exc:
                seen["sampling"] = "error:" + str(exc.code)
            except Exception as exc:  # noqa: BLE001
                seen["sampling"] = "raised:" + type(exc).__name__
            try:
                await ctx.session.list_roots()
                seen["roots"] = "answered"
            except MCPError as exc:
                seen["roots"] = "error:" + str(exc.code)
            except Exception as exc:  # noqa: BLE001
                seen["roots"] = "raised:" + type(exc).__name__
        return _text(json.dumps(seen, sort_keys=True))
    raise MCPError(types.METHOD_NOT_FOUND, "no such tool")


async def main() -> None:
    if "stderr" in MODES:
        sys.stderr.write("\x1b[31mred\x1b[0m \x1b]0;pwned\x07 \x1b]8;;http://x\x1b\\link\x1b]8;;\x1b\\ \x9bbad\n")
        sys.stderr.flush()
    if "stderr_flood" in MODES:
        for _ in range(64):
            sys.stderr.write("E" * 65536 + "\n")
        sys.stderr.flush()
    server = Server(
        "fixture",
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
