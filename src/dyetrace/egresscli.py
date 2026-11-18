"""U11 `dyetrace egress` subcommand (R6, R7, R9, R11, R13, KTD5, KTD6, KTD12).

``dyetrace.cli.main`` hands off here when ``argv[0] == "egress"``; nothing else
about the black-box CLI changes. ``main`` runs one fixed pipeline so a refusal
causes no side effect:

1. parse flags; load the operator target config; load candidates (in the chosen
   format) and binds; a candidates file with zero candidates is a stop;
2. validate the advertised URL, the port contract and the bind policy (no
   socket exists yet); check the attestation and the timing flags;
3. only then build the caller (a missing SDK stops here, before any spawn),
   list tools, build the catalog and map; a bind that names a tool or argument
   absent from the live catalog stops; the call cap stops before any send;
4. zero mapped candidates: render all-unmapable verdicts and exit 3 without
   starting a listener;
5. otherwise start the listener on the exact ``--listen`` port (which must equal
   the ``--advertise`` port), drive, drain, close the listener and the caller,
   build verdicts and render. The listener and the caller are closed in
   ``finally``, also when something unexpected is raised.

Exit codes: 0 only when the run completed and every candidate was exercised
(PROVEN, new_flow or KILL); 3 for a completed run with any unmapable or
unexercised candidate, or when nothing mapped; 2 for every stop and for an
incomplete run (the INCOMPLETE report is still written). Each stop prints a
distinct ``dyetrace: stopped: ...`` reason on stderr. The JSON report carries
the machine-readable ``coverage`` block in every case, so exit 0 is never the
only signal.

Port contract. ``--advertise`` carries its own explicit nonzero port and
``--listen`` must bind that exact port; a missing port, port 0 or a mismatch is
its own stop. Port 0 is reachable only through the ``listener_factory`` test
seam and never together with ``--advertise``. With no ``--advertise`` the
advertised URL is derived from the address the listener actually bound
(loopback still needs ``--allow-local-advertise``).

Seams (keyword-only, in the style of ``cli.main``'s resolver and transport):
``resolver``, ``caller_factory(target, allow_loopback=, allow_cleartext=)``,
``listener_factory(bind, key, run_id)``, ``clock``, ``sleep``, and
``address_class_override``. The last is TEST-ONLY: it forces the advertised
address class recorded on every send (for an IP-literal target) so a loopback
listener can stand in for a public canary in the end-to-end suite. It is
deliberately not a CLI flag.

A stdio target's stderr excerpt (neutralized by
``mcpclient.render_stderr_excerpt``) is added to the report's adapter limits
strings; the HTTP caller has none.
"""

import argparse
import dataclasses
import math
import sys

from . import marker
from .egresscand import FORMATS, EgressCandidatesError, load_egress_candidates
from .egressdrive import DriveResult, run_driver
from .egressmap import (
    EgressBindsError,
    EgressCatalogError,
    build_catalog,
    load_egress_binds,
    map_egress,
)
from .egressnet import (
    AdvertisedURLError,
    BindError,
    BindPortError,
    HttpsNotSupportedError,
    format_hostport,
    parse_listen,
    validate_advertised,
    validate_bind,
)
from .egressreport import coverage, render
from .egressverdict import (
    VERDICT_UNEXERCISED,
    VERDICT_UNMAPABLE,
    egress_verdicts,
)
from .listener import Listener, ListenerSnapshot
from .mcpclient import (
    McpCatalogLimitError,
    McpClientError,
    McpSdkMissingError,
    TargetConfigError,
    load_target,
    open_caller,
    render_stderr_excerpt,
)
from .masking import terminal_safe

__all__ = ["main", "build_parser"]

_CLASSES = ("public", "private", "loopback")
_DETAIL_CAP = 300


def build_parser():
    p = argparse.ArgumentParser(
        prog="dyetrace egress",
        description="Egress prover: call MCP tools with a tracer URL aimed at "
                    "a listener you control, for authorized testing only.",
    )
    p.add_argument("--candidates", required=True, help="saved candidates file")
    p.add_argument("--candidates-format", choices=FORMATS, default="normalized",
                   help="candidates file format (default normalized)")
    p.add_argument("--binds", help="operator binds JSON: candidate id -> tool, "
                                   "argument, optional static arguments")
    p.add_argument("--target", required=True,
                   help="operator target config JSON (stdio command or HTTP URL)")
    p.add_argument("--listen", default="127.0.0.1:0", metavar="HOST:PORT",
                   help="listener bind (IP literal; default 127.0.0.1:0, which "
                        "needs an explicit nonzero port in a real run)")
    p.add_argument("--advertise", metavar="URL",
                   help="http base URL the target is told to fetch; carries its "
                        "own nonzero port, and --listen must bind that exact port")
    p.add_argument("--allow-exposed-bind", action="store_true",
                   help="permit a non-loopback (or wildcard) listener bind")
    p.add_argument("--allow-local-advertise", action="store_true",
                   help="permit a loopback or private advertised address")
    p.add_argument("--redirect-hop", metavar="URL",
                   help="base URL the listener 302-redirects to; must bind the "
                        "--listen port. A tracer that resurfaces there proves "
                        "the redirect hop was fetched without re-validation")
    p.add_argument("--attest-listener-reachable", metavar="NOTE",
                   help="operator note that the listener is reachable from the "
                        "target; recorded verbatim, operator-asserted and "
                        "unverified; required for any KILL")
    p.add_argument("--settle", type=float, default=5.0,
                   help="seconds to wait for the token after each call (default 5)")
    p.add_argument("--drain", type=float, default=5.0,
                   help="final drain window in seconds (default 5)")
    p.add_argument("--call-timeout", type=float, default=30.0,
                   help="per-call timeout in seconds (default 30)")
    p.add_argument("--rate", type=float, default=1.0,
                   help="calls per second (default 1.0)")
    p.add_argument("--max-calls", type=int, default=500,
                   help="call-count cap (default 500)")
    p.add_argument("--target-commit", default="", metavar="TEXT",
                   help="target commit or version, recorded verbatim")
    p.add_argument("--allow-cleartext", action="store_true",
                   help="permit a plain http MCP target (HTTP leg)")
    p.add_argument("--allow-loopback", action="store_true",
                   help="permit a loopback MCP target (HTTP leg)")
    p.add_argument("--output", choices=("terminal", "html", "json"),
                   default="terminal", help="output surface (default terminal)")
    p.add_argument("--out", help="output file path (default stdout)")
    return p


def _fail(reason):
    """Print a stop reason to stderr and return the stop exit code."""
    print(f"dyetrace: stopped: {terminal_safe(str(reason))}", file=sys.stderr)
    return 2


def _short(exc):
    text = f"{type(exc).__name__}: {exc}"
    return text if len(text) <= _DETAIL_CAP else text[:_DETAIL_CAP] + "..."


def _safe_close(obj):
    if obj is None:
        return
    try:
        obj.close()
    except Exception:
        pass


class _NoListener:
    """Stands in for a listener when none was started (nothing mapped)."""

    def snapshot(self):
        return ListenerSnapshot(
            verified_hits=(), arrival_counts={}, verified_dropped=0,
            noise_count=0, noise_samples=(), refused_count=0, refused_offsets=(),
            deadline_close_count=0, deadline_close_offsets=(),
            unattributed_count=0, unattributed_offsets=(),
            offsets_truncated=False, oversize_closed=0, malformed_closed=0,
            peak_connections=0, active_connections=0, health="ok")

    def hits_for(self, entry_id):
        return ()


def _timing_error(args):
    for name in ("settle", "drain", "call_timeout", "rate"):
        v = getattr(args, name)
        if not math.isfinite(v):
            return f"--{name.replace('_', '-')} must be a finite number"
    if args.settle < 0 or args.drain < 0:
        return "--settle and --drain must be >= 0"
    if args.call_timeout <= 0 or args.rate <= 0:
        return "--call-timeout and --rate must be > 0"
    if args.max_calls < 1:
        return "--max-calls must be >= 1"
    return None


def _exit_code(report):
    cov = coverage(report)["counts"]
    if cov.get(VERDICT_UNMAPABLE, 0) or cov.get(VERDICT_UNEXERCISED, 0):
        return 3
    return 0


def _emit(text, args):
    """Write the report; return None on success or a stop exit code."""
    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
        except OSError as exc:
            return _fail(f"cannot write output file: {exc}")
    else:
        print(text)
    return None


def main(argv=None, *, resolver=None, caller_factory=None, listener_factory=None,
         clock=None, sleep=None, address_class_override=None):
    args = build_parser().parse_args(argv)
    if address_class_override is not None and address_class_override not in _CLASSES:
        raise ValueError(f"address_class_override must be one of {_CLASSES}")

    try:
        target_cfg = load_target(args.target)
    except TargetConfigError as exc:
        return _fail(f"target error: {exc}")
    try:
        cand_set = load_egress_candidates(args.candidates, args.candidates_format)
    except EgressCandidatesError as exc:
        return _fail(f"candidates error: {exc}")
    candidates = cand_set.candidates
    if not candidates:
        return _fail("candidates file held zero candidates (nothing to prove)")
    binds = None
    if args.binds is not None:
        try:
            binds = load_egress_binds(args.binds)
        except EgressBindsError as exc:
            return _fail(f"binds error: {exc}")

    # Advertised URL, port contract and bind policy: nothing is opened yet.
    target = None
    if args.advertise is not None:
        try:
            target = validate_advertised(
                args.advertise, allow_local=args.allow_local_advertise,
                resolver=resolver)
        except HttpsNotSupportedError as exc:
            return _fail(f"advertised URL refused (https is not supported): {exc}")
        except AdvertisedURLError as exc:
            return _fail(f"advertised URL refused: {exc}")
        if target.port is None:
            return _fail("port contract: --advertise must carry an explicit port")
    try:
        listen_host, listen_port = parse_listen(args.listen)
    except BindError as exc:
        return _fail(f"listen address error: {exc}")
    if target is not None:
        if listen_port == 0:
            return _fail("port contract: --listen port 0 cannot be combined "
                         "with --advertise")
        if listen_port != target.port:
            return _fail(f"port contract: --listen port {listen_port} differs "
                         f"from --advertise port {target.port}")
    try:
        bind = validate_bind(
            listen_host, listen_port, allow_exposed=args.allow_exposed_bind,
            allow_port_zero=listener_factory is not None,
            advertised=target is not None)
    except BindPortError as exc:
        return _fail(f"bind port error: {exc}")
    except BindError as exc:
        return _fail(f"bind policy: {exc}")
    redirect = None
    if args.redirect_hop is not None:
        try:
            redirect = validate_advertised(
                args.redirect_hop, allow_local=args.allow_local_advertise,
                resolver=resolver)
        except HttpsNotSupportedError as exc:
            return _fail(f"redirect-hop URL refused (https is not supported): {exc}")
        except AdvertisedURLError as exc:
            return _fail(f"redirect-hop URL refused: {exc}")
        if redirect.base_path:
            return _fail("--redirect-hop must be an authority-only URL (no path)")
        if bind.port == 0:
            return _fail("port contract: --listen port 0 cannot be combined "
                         "with --redirect-hop")
        if redirect.port is None or redirect.port != bind.port:
            return _fail("redirect hop contract: --redirect-hop must carry "
                         "the --listen port (one listener serves both hops)")
    if target is None:
        # Derived advertised URL: apply the same policy now, with a placeholder
        # port, so a refusal happens before any caller or listener exists.
        try:
            validate_advertised(
                "http://" + format_hostport(bind.host, 1),
                allow_local=args.allow_local_advertise, resolver=resolver)
        except AdvertisedURLError as exc:
            return _fail(f"advertised URL refused (derived from --listen): {exc}")

    note = args.attest_listener_reachable
    if note is not None and not note.strip():
        return _fail("attestation note must be non-empty when "
                     "--attest-listener-reachable is used")
    bad = _timing_error(args)
    if bad:
        return _fail(f"timing flags: {bad}")

    open_one = caller_factory or open_caller
    try:
        caller = open_one(target_cfg, allow_loopback=args.allow_loopback,
                          allow_cleartext=args.allow_cleartext)
    except McpSdkMissingError as exc:
        return _fail(f"MCP SDK is not installed (pip install 'dyetrace[mcp]'): {exc}")
    except McpClientError as exc:
        return _fail(f"cannot open the MCP target: {exc}")

    lis = None
    limits = []
    if cand_set.coverage_verdict:
        limits.append(f"candidate source coverage: {cand_set.coverage_verdict}")
    try:
        try:
            tools = caller.list_tools()
        except McpCatalogLimitError as exc:
            return _fail(f"tools/list exceeded a bound: {exc}")
        except Exception as exc:
            return _fail(f"tools/list failed: {_short(exc)}")
        try:
            catalog = build_catalog(tools)
        except EgressCatalogError as exc:
            return _fail(f"tools/list result malformed: {exc}")
        try:
            mapped = map_egress(candidates, catalog, binds)
        except EgressBindsError as exc:
            return _fail(f"binds do not match the live tools: {exc}")

        if not mapped.mapped:
            report = egress_verdicts(
                mapped, DriveResult([], True, settle=args.settle, drain=args.drain),
                _NoListener(), attestation=note)
            _attach_stderr(caller, limits)
            text = render(report, surface=args.output, snapshot=None,
                          advertised=args.advertise, bind_addr=args.listen,
                          target_commit=args.target_commit, adapter_limits=limits,
                          redirect_hop=args.redirect_hop)
            return _emit(text, args) or _exit_code(report)

        if len(mapped.plans) > args.max_calls:
            return _fail(f"call cap exceeded: {len(mapped.plans)} sends planned, "
                         f"--max-calls is {args.max_calls}")

        key = marker.mint_key()
        run_id = marker.new_nonce()
        factory = listener_factory or Listener
        lis = (factory(bind, key, run_id) if redirect is None
               else factory(bind, key, run_id, redirect=redirect))
        try:
            address = lis.start()
        except Exception as exc:
            return _fail(f"listener failed to start: {_short(exc)}")
        bound_port = address[1]
        if target is not None:
            if bound_port != target.port:
                return _fail(f"listener bound port {bound_port}, expected "
                             f"the --advertise port {target.port}")
        else:
            try:
                target = validate_advertised(
                    "http://" + format_hostport(address[0], bound_port),
                    allow_local=args.allow_local_advertise, resolver=resolver)
            except AdvertisedURLError as exc:
                return _fail(f"advertised URL refused (derived from listener): {exc}")
        if address_class_override is not None:
            target = dataclasses.replace(target, address_class=address_class_override)

        seams = {}
        if clock is not None:
            seams["clock"] = clock
        if sleep is not None:
            seams["sleep"] = sleep
        drive = run_driver(
            mapped.plans, caller=caller, listener=lis, key=key, run_id=run_id,
            target=target, settle=args.settle, drain=args.drain,
            call_timeout=args.call_timeout, max_calls=args.max_calls,
            rate=args.rate, resolver=resolver, **seams)
        _safe_close(lis)
        _safe_close(caller)
        _attach_stderr(caller, limits)
        report = egress_verdicts(mapped, drive, lis, attestation=note,
                                 bound_port=bound_port)
        text = render(report, surface=args.output, snapshot=lis.snapshot(),
                      advertised=target.url, bind_addr=format_hostport(*address),
                      target_commit=args.target_commit, adapter_limits=limits,
                      redirect_hop=args.redirect_hop)
        stop = _emit(text, args)
        if stop is not None:
            return stop
        if not report.complete:
            return _fail(f"run incomplete: {report.incomplete_reason}")
        return _exit_code(report)
    finally:
        _safe_close(lis)
        _safe_close(caller)


def _attach_stderr(caller, limits):
    """Add the stdio child's neutralized stderr excerpt, when the caller has one."""
    getter = getattr(caller, "stderr_excerpt", None)
    if not callable(getter):
        return
    try:
        ex = getter()
        if ex is not None and (ex.text or ex.total_bytes):
            limits.append("target stderr: " + render_stderr_excerpt(ex))
    except Exception:
        pass
