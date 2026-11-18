"""U8 CLI entry point (R16, R28, KTD20, KTD11).

Headless console command ``dyetrace`` (declared as ``dyetrace.cli:main`` in
pyproject). It defines and validates the R28 run inputs, wires the pipeline
(load -> plant -> drive -> observe -> render), and enforces fail-closed exit
discipline: every stop condition returns a non-zero code with a distinct stated
reason on stderr, while a completed run (including a clean zero-hit run) returns
0 and prints output that is labeled as a finished no-leak run, not a stop
(KTD11). A per-request failure never changes the exit code; U6 already records
it and the run continues.

``resolver`` and ``transport`` are injectable test seams, matching the net
core's own injectable resolver and transport, so a unit test drives the whole
pipeline with no real DNS and no byte on the wire.
"""

import argparse
import sys

import httpx

from . import marker
from .binds import BindsError, apply_binds, load_binds
from .candidates import CandidatesError, load_candidates
from .net import HostGuard, NetError, RateGate, IdentityClient
from .observe import observe
from .ossmap import map_candidates
from .ossverdict import OssReport, verdicts
from .plant import plant
from .propagate import PropagateError, drive
from .report import render
from .session import SessionError, load_session

__all__ = ["main", "build_parser"]


def build_parser():
    p = argparse.ArgumentParser(
        prog="dyetrace",
        description="Black-box dataflow tracer for authorized testing.",
    )
    p.add_argument("--session", required=True, help="path to the session JSON")
    p.add_argument("--second-session", help="optional second-identity session JSON")
    p.add_argument("--host", required=True, help="allowlist host (exact match)")
    p.add_argument("--rate", type=float, default=2.0,
                   help="requests per second (default 2.0)")
    p.add_argument("--raw-only", action="store_true",
                   help="plant only the raw tracer variant")
    p.add_argument("--allow-cleartext", action="store_true",
                   help="permit plain HTTP targets (no transport encryption)")
    p.add_argument("--allow-loopback", action="store_true",
                   help="permit loopback target addresses (127.0.0.0/8, ::1) "
                        "for local OSS harnesses; off by default")
    p.add_argument("--confirm-mutating", action="store_true",
                   help="replay recorded mutating requests (destructive)")
    p.add_argument("--exclude", type=int, action="append", default=[],
                   metavar="INDEX", help="recorded-request index to skip (repeatable)")
    p.add_argument("--post-read", type=int, action="append", default=[],
                   metavar="INDEX",
                   help="recorded POST index to treat as a read surface (repeatable)")
    p.add_argument("--output", choices=("terminal", "html", "json"),
                   default="terminal", help="output surface (default terminal)")
    p.add_argument("--out", help="output file path (default stdout)")
    p.add_argument("--candidates",
                   help="jevsec candidates.json or single run dir; enables "
                        "OSS mode (candidate-driven plant list)")
    p.add_argument("--binds",
                   help="operator binds JSON: candidate_id -> request_index, "
                        "optional path_id and predicted surface "
                        "(requires --candidates)")
    p.add_argument("--route-prefix", action="append", default=[],
                   metavar="PREFIX",
                   help="mount prefix to try against route candidates "
                        "(repeatable, e.g. --route-prefix /api)")
    p.add_argument("--predicted-surface", default="plant",
                   help="default predicted surface for OSS candidates: "
                        "'plant', 'propagate:<index>', or 'identity:<n>' "
                        "(per-candidate binds.predicted overrides)")
    return p


def _validate_predicted(value):
    if value != "plant":
        head, sep, tail = value.partition(":")
        if not (sep and tail.isdigit() and head in ("propagate", "identity")):
            raise ValueError(
                f"{value!r} must be 'plant', 'propagate:<index>', or "
                "'identity:<n>'")


def _fail(reason):
    """Print a stop reason to stderr and return a non-zero exit code."""
    print(f"dyetrace: stopped: {reason}", file=sys.stderr)
    return 2


def main(argv=None, *, resolver=None, transport=None):
    tokens = sys.argv[1:] if argv is None else argv
    if tokens and tokens[0] == "egress":
        from .egresscli import main as egress_main

        return egress_main(list(tokens[1:]), resolver=resolver)
    args = build_parser().parse_args(argv)

    # Load the primary session (fail-closed on schema / zero-plantable / unreadable).
    try:
        session = load_session(args.session, args.host)
    except SessionError as exc:
        return _fail(f"session error: {exc}")

    second = None
    if args.second_session:
        try:
            second = load_session(args.second_session, args.host)
        except SessionError as exc:
            return _fail(f"second session error: {exc}")

    # OSS mode (SPEC-OSS): a supplied candidates path must be readable and
    # schema-valid (fail closed); a valid file with zero candidates falls back
    # to the black-box pipeline with the switch visible in the output.
    oss_map = None
    oss = None
    if args.candidates is None and args.binds is not None:
        return _fail("--binds requires --candidates")
    if args.candidates is not None:
        try:
            cands = load_candidates(args.candidates)
        except CandidatesError as exc:
            return _fail(f"candidates error: {exc}")
        if cands:
            oss_map = map_candidates(
                cands, session.recorded_requests,
                route_prefixes=args.route_prefix)
            if args.binds is not None:
                try:
                    binds = load_binds(args.binds)
                    apply_binds(oss_map, binds, session.recorded_requests)
                except BindsError as exc:
                    return _fail(f"binds error: {exc}")
            try:
                _validate_predicted(args.predicted_surface)
            except ValueError as exc:
                return _fail(f"predicted-surface error: {exc}")
        else:
            oss = OssReport(fell_back=True)
            print(
                "dyetrace: candidates file held zero candidates; "
                "running black-box mode",
                file=sys.stderr,
            )

    # One shared allowlist choke point and one shared rate gate for the run.
    try:
        guard = HostGuard([args.host], resolver=resolver,
                          allow_loopback=args.allow_loopback)
        gate = RateGate(args.rate)
    except (NetError, ValueError) as exc:
        return _fail(f"allowlist/rate setup error: {exc}")

    key = marker.mint_key()
    run_id = marker.new_nonce()

    # Build both per-identity clients inside the guarded block, so a client that
    # fails to construct (e.g. a malformed base_url httpx rejects) is a clean
    # fail-closed stop and the first client is always closed, never leaked.
    client1 = None
    client2 = None
    try:
        try:
            client1 = IdentityClient.from_session(
                session, host_guard=guard, gate=gate,
                allow_cleartext=args.allow_cleartext, transport=transport,
            )
            if second is not None:
                client2 = IdentityClient.from_session(
                    second, host_guard=guard, gate=gate,
                    allow_cleartext=args.allow_cleartext, transport=transport,
                )
        except (NetError, httpx.InvalidURL, ValueError) as exc:
            return _fail(f"client setup error: {exc}")

        targets = oss_map.plant_targets() if oss_map is not None else None

        plant_result = plant(
            session, key, run_id,
            raw_only=args.raw_only, confirm_mutating=args.confirm_mutating,
            targets=targets,
        )
        if oss_map is None and not plant_result.mapping:
            return _fail(
                "no tracers planted: every recorded request was skipped "
                "(mutating requests require --confirm-mutating)"
            )

        observations = []
        if plant_result.mapping:
            try:
                observations = drive(
                    session, plant_result, client1,
                    read_surface_indices=tuple(args.post_read),
                    excluded_indices=tuple(args.exclude),
                    identity2=(2 if client2 is not None else None),
                    client2=client2,
                    allow_empty_surfaces=oss_map is not None,
                )
            except PropagateError as exc:
                return _fail(f"propagation stopped: {exc}")

        report = observe(observations, plant_result, key, run_id)
        if oss_map is not None:
            oss = OssReport(
                candidate_verdicts=verdicts(
                    report, observations, plant_result, oss_map,
                    predicted_default=args.predicted_surface,
                )
            )
        text = render(report, surface=args.output, oss=oss)
    finally:
        if client1 is not None:
            client1.close()
        if client2 is not None:
            client2.close()

    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
        except OSError as exc:
            return _fail(f"cannot write output file: {exc}")
    else:
        print(text)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
