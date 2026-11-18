"""Tests for U5 socket and process confinement (KTD13).

`scan_directory` is an AST-based scan over a directory (a text search would
trip on comments: egressnet.py has a comment that says "import socket").
Policy: only listener.py may import socket, socketserver or http.server and
call bind/listen/server-creation; net.py may import socket (DNS only) but may
not bind, listen or create a server; no module may import subprocess,
multiprocessing or ctypes, nor call os.system/popen/exec*/spawn*/fork*, nor
asyncio server or subprocess creation, nor import a banned module through
importlib or __import__ (a non-literal dynamic import is refused too). The scan
is run GREEN on the real source and RED on temp directories holding one
violator per banned form, which is what makes it load-bearing.
"""

import ast
import pathlib

import pytest

SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "dyetrace"

_NET_MODULES = ("socket", "_socket", "socketserver", "http.server")
_PROC_MODULES = ("subprocess", "multiprocessing", "ctypes", "_ctypes")
_BANNED_ALWAYS = ("subprocess", "multiprocessing", "ctypes", "_ctypes")
_SERVER_ATTRS = frozenset(
    {
        "bind",
        "listen",
        "create_server",
        "create_unix_server",
        "start_server",
        "start_unix_server",
        "create_datagram_endpoint",
    }
)
_OS_BANNED_EXACT = frozenset({"system", "popen", "fork", "forkpty", "posix_spawn", "posix_spawnp"})
_OS_BANNED_PREFIX = ("exec", "spawn")
_ASYNCIO_BANNED = frozenset(
    {
        "start_server",
        "start_unix_server",
        "create_subprocess_exec",
        "create_subprocess_shell",
    }
)
# File-level allowances: which network modules / server calls a file may use.
_ALLOW_NET_IMPORT = {"listener.py": {"socket", "socketserver", "http.server"}, "net.py": {"socket"}}
_ALLOW_SERVER_CALLS = {"listener.py"}


def _under(name, mods):
    return any(name == m or name.startswith(m + ".") for m in mods)


def _os_banned(attr):
    return attr in _OS_BANNED_EXACT or attr.startswith(_OS_BANNED_PREFIX)


class _Scanner(ast.NodeVisitor):
    def __init__(self, fname):
        self.fname = fname
        self.out = []
        self.alias = {}  # local name -> dotted origin
        self.allowed_net = _ALLOW_NET_IMPORT.get(fname, set())
        self.server_ok = fname in _ALLOW_SERVER_CALLS

    def flag(self, node, what):
        self.out.append("%s:%d: %s" % (self.fname, getattr(node, "lineno", 0), what))

    def check_module(self, node, name):
        if _under(name, _BANNED_ALWAYS):
            self.flag(node, "import of banned module %s" % name)
        elif _under(name, _NET_MODULES) and not any(_under(name, [a]) for a in self.allowed_net):
            self.flag(node, "import of network module %s outside its allowlist" % name)

    def visit_Import(self, node):
        for a in node.names:
            self.check_module(node, a.name)
            self.alias[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        mod = node.module or ""
        self.check_module(node, mod)
        for a in node.names:
            full = mod + "." + a.name if mod else a.name
            # `from http import server`, `from os import system`, ...
            if a.name != "*":
                self.check_module(node, full)
            self.alias[a.asname or a.name] = full
            if mod == "os" and _os_banned(a.name):
                self.flag(node, "import of os.%s" % a.name)
            if mod == "asyncio" and a.name in _ASYNCIO_BANNED:
                self.flag(node, "import of asyncio.%s" % a.name)
            if mod in ("importlib", "importlib.util") and a.name in ("import_module", "find_spec"):
                pass  # judged at the call site
        self.generic_visit(node)

    def dotted(self, node):
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(self.alias.get(node.id, node.id))
            return ".".join(reversed(parts))
        return None

    def visit_Call(self, node):
        fn = node.func
        name = self.dotted(fn)
        attr = fn.attr if isinstance(fn, ast.Attribute) else None
        if name:
            head, _, tail = name.rpartition(".")
            if head == "os" and _os_banned(tail):
                self.flag(node, "call to os.%s" % tail)
            if head == "asyncio" and tail in _ASYNCIO_BANNED:
                self.flag(node, "call to asyncio.%s" % tail)
            if name in ("importlib.import_module", "__import__", "builtins.__import__") or (
                name == "import_module"
            ):
                self.dynamic_import(node)
        if attr in _SERVER_ATTRS and not self.server_ok:
            self.flag(node, "call to .%s() outside listener.py" % attr)
        elif isinstance(fn, ast.Name) and fn.id in _SERVER_ATTRS and not self.server_ok:
            self.flag(node, "call to %s() outside listener.py" % fn.id)
        self.generic_visit(node)

    def dynamic_import(self, node):
        arg = node.args[0] if node.args else None
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            mod = arg.value
            if _under(mod, _BANNED_ALWAYS) or _under(mod, _NET_MODULES):
                self.flag(node, "dynamic import of banned module %s" % mod)
        else:
            self.flag(node, "dynamic import with a non-literal module name")


def scan_directory(directory):
    """Return a sorted list of violation strings for every .py file under directory."""
    found = []
    for path in sorted(pathlib.Path(directory).rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        sc = _Scanner(path.name)
        sc.visit(tree)
        found.extend(sc.out)
    return found


# ------------------------------------------------------------------ GREEN

def test_real_source_is_clean():
    assert scan_directory(SRC) == []


def test_real_source_scan_actually_sees_the_files():
    names = {p.name for p in SRC.glob("*.py")}
    assert {"listener.py", "net.py", "egressnet.py", "marker.py"} <= names
    # net.py really imports socket and listener.py really does, so the
    # allowlist is exercised and not vacuous.
    for fname in ("net.py", "listener.py"):
        assert "import socket" in (SRC / fname).read_text()


def test_comments_and_strings_do_not_trip_the_scan(tmp_path):
    (tmp_path / "ok.py").write_text(
        '# import socket\n"""import subprocess; os.system(x)"""\nx = "import socket"\n'
    )
    assert scan_directory(tmp_path) == []


def test_allowed_forms_are_clean(tmp_path):
    (tmp_path / "listener.py").write_text(
        "import socket\nimport socketserver\nfrom http.server import HTTPServer\n"
        "s = socket.socket()\ns.bind(('127.0.0.1', 0))\ns.listen(1)\n"
    )
    (tmp_path / "net.py").write_text("import socket\nsocket.getaddrinfo('h', None)\n")
    assert scan_directory(tmp_path) == []


# -------------------------------------------------------------------- RED

VIOLATORS = {
    "import_socket": "import socket\n",
    "from_socket": "from socket import socket\n",
    "import_socketserver": "import socketserver\n",
    "import_http_server": "import http.server\n",
    "from_http_server": "from http.server import HTTPServer\n",
    "from_http_import_server": "from http import server\n",
    "import_subprocess": "import subprocess\n",
    "from_subprocess": "from subprocess import Popen\n",
    "os_system": "import os\nos.system('x')\n",
    "os_system_alias": "import os as o\no.system('x')\n",
    "from_os_system": "from os import system\nsystem('x')\n",
    "os_popen": "import os\nos.popen('x')\n",
    "os_execv": "import os\nos.execv('/bin/sh', ['sh'])\n",
    "os_execvp": "import os\nos.execvp('sh', ['sh'])\n",
    "os_spawnl": "import os\nos.spawnl(0, 'sh')\n",
    "os_fork": "import os\nos.fork()\n",
    "asyncio_start_server": "import asyncio\nasyncio.start_server(None, 'h', 1)\n",
    "asyncio_start_unix_server": "import asyncio\nasyncio.start_unix_server(None, 'p')\n",
    "asyncio_create_subprocess_exec": "import asyncio\nasyncio.create_subprocess_exec('x')\n",
    "asyncio_create_subprocess_shell": "import asyncio\nasyncio.create_subprocess_shell('x')\n",
    "from_asyncio_start_server": "from asyncio import start_server\n",
    "loop_create_server": "def f(loop):\n    loop.create_server(None, 'h', 1)\n",
    "import_multiprocessing": "import multiprocessing\n",
    "from_multiprocessing": "from multiprocessing import Process\n",
    "import_ctypes": "import ctypes\n",
    "from_ctypes": "from ctypes import CDLL\n",
    "importlib_socket": "import importlib\nimportlib.import_module('socket')\n",
    "importlib_subprocess": "import importlib\nimportlib.import_module('subprocess')\n",
    "importlib_dotted": "import importlib\nimportlib.import_module('http.server')\n",
    "importlib_nonliteral": "import importlib\nn = 'so' + 'cket'\nimportlib.import_module(n)\n",
    "dunder_import_socket": "__import__('socket')\n",
    "dunder_import_ctypes": "__import__('ctypes')\n",
    "dunder_import_nonliteral": "n = 'so' + 'cket'\n__import__(n)\n",
}


@pytest.mark.parametrize("name", sorted(VIOLATORS))
def test_each_violator_form_is_red(tmp_path, name):
    (tmp_path / "violator.py").write_text(VIOLATORS[name])
    found = scan_directory(tmp_path)
    assert found, "scan missed %s" % name
    assert all(f.startswith("violator.py:") for f in found)


def test_bind_listen_in_other_module_is_red(tmp_path):
    (tmp_path / "other.py").write_text("def f(s):\n    s.bind(('h', 1))\n    s.listen(1)\n")
    assert len(scan_directory(tmp_path)) == 2


def test_net_py_may_import_socket_but_not_bind_or_listen(tmp_path):
    (tmp_path / "net.py").write_text("import socket\ns = socket.socket()\ns.bind(('h', 1))\n")
    found = scan_directory(tmp_path)
    assert len(found) == 1 and "bind" in found[0]
    (tmp_path / "net.py").write_text("import socketserver\n")
    assert scan_directory(tmp_path)


def test_listener_py_still_may_not_use_subprocess_or_system(tmp_path):
    (tmp_path / "listener.py").write_text("import socket\nimport subprocess\nimport os\nos.system('x')\n")
    assert len(scan_directory(tmp_path)) == 2


def test_violator_in_nested_directory_is_found(tmp_path):
    sub = tmp_path / "pkg" / "inner"
    sub.mkdir(parents=True)
    (sub / "v.py").write_text("import socket\n")
    assert scan_directory(tmp_path)


def test_real_source_plus_violator_copy_is_red(tmp_path):
    for p in SRC.glob("*.py"):
        (tmp_path / p.name).write_text(p.read_text())
    assert scan_directory(tmp_path) == []
    (tmp_path / "egressnet.py").write_text(
        (tmp_path / "egressnet.py").read_text() + "\nimport socket\n"
    )
    assert scan_directory(tmp_path)
