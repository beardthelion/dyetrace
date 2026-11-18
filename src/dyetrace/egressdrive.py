"""U6 egress driver, send records and the ToolCaller seam (R3, R9, R11, KTD2, KTD10-KTD12).

A sequential driver. For each send plan, in order: rate-gate wait, recheck of
the advertised target adjacent to the call (KTD11; the rate gate and the
previous settle window are blocking waits between validation and the act), mint
a fresh entry_id (lowercase hex counter) and nonce, build the token, write the
send record, call, record the outcome, and wait up to the settle window for the
token. After the last send it waits the drain window. Listener health is
checked before the first send and after every wait.

Attribution comes from the send record only (KTD10): the record holds the
exact arguments passed (deep-copied, so a caller mutating its dict later cannot
rewrite history), the token and the candidate ids it serves. The driver never
inspects tool result text for a token; a token echoed there is not evidence.

Each send record carries the advertised address class (public, private or
loopback, from the recheck just before the call) and the send's window
start/end offsets in the `Listener.offset()` timebase. The window is opened
just before the call and closed after the settle wait, so an unverified arrival
landing inside it is counted unattributed by the listener; U7 compares the
listener's refused, deadline-close and unattributed offsets against these
windows and must treat `offsets_truncated` as interference. The drain window is
recorded on the result the same way.

Stops (KTD11, KTD12): more plans than `max_calls` stops before anything is
sent; a failed recheck (any exception, a resolver error included) or a listener
that is not healthy stops the run, the remaining sends become `not_called`
and the run is incomplete. The driver owns no socket and no process; the
caller and listener are passed in and not closed here.
"""

import copy
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from dyetrace import marker
from dyetrace.egressmap import SendPlan
from dyetrace.egressnet import AdvertisedTarget, recheck_advertised
from dyetrace.net import RateGate

__all__ = [
    "RESULT_TEXT_CAP",
    "OUTCOME_KINDS",
    "OUTCOME_NOT_CALLED",
    "STOP_MAX_CALLS",
    "STOP_RECHECK_FAILED",
    "STOP_LISTENER_UNHEALTHY",
    "CallOutcome",
    "ToolCaller",
    "SendRecord",
    "DriveResult",
    "run_driver",
]

RESULT_TEXT_CAP = 64 * 1024

OUTCOME_KINDS = ("result", "tool_error", "invalid_params", "transport_error", "timeout")
OUTCOME_NOT_CALLED = "not_called"

STOP_MAX_CALLS = "max_calls_exceeded"
STOP_RECHECK_FAILED = "advertised_recheck_failed"
STOP_LISTENER_UNHEALTHY = "listener_unhealthy"


@dataclass
class CallOutcome:
    """What a ToolCaller returns for one call. `text` is untrusted."""

    kind: str
    text: str = ""


class ToolCaller(Protocol):
    """The seam (KTD2). Implementations may raise; the driver records that.

    `call_tool` returns a CallOutcome of one of OUTCOME_KINDS. Raising
    TimeoutError is recorded as `timeout`, any other Exception as
    `transport_error`.
    """

    def list_tools(self) -> list[dict]: ...

    def call_tool(self, name: str, arguments: dict, timeout: float) -> CallOutcome: ...

    def close(self) -> None: ...


@dataclass
class SendRecord:
    index: int
    tool: str
    argument: str
    candidate_ids: tuple[str, ...]
    outcome: str  # one of OUTCOME_KINDS or "not_called"
    arguments: dict = field(default_factory=dict)  # exact arguments passed, URL included
    entry_id: str | None = None
    nonce: str | None = None
    token: str | None = None
    url: str | None = None
    address_class: str | None = None
    advertised_host: str | None = None
    advertised_port: int | None = None
    sent_wall: float | None = None
    window_start: float | None = None
    window_end: float | None = None
    result_text: str = ""
    result_truncated: bool = False
    error: str = ""


@dataclass
class DriveResult:
    sends: list[SendRecord]
    complete: bool
    stop_reason: str | None = None
    stop_detail: str = ""
    drain_start: float | None = None
    drain_end: float | None = None
    settle: float = 0.0
    drain: float = 0.0


def _not_called(i: int, plan: SendPlan) -> SendRecord:
    return SendRecord(
        index=i,
        tool=plan.tool,
        argument=plan.argument,
        candidate_ids=tuple(plan.candidate_ids),
        outcome=OUTCOME_NOT_CALLED,
        arguments=copy.deepcopy(plan.arguments),
    )


_URL_PLACEHOLDER = "{url}"


def _inject_url(arguments, url):
    """Return a copy of arguments with every {url} placeholder leaf substituted,
    or None when no placeholder exists (the caller then writes the top-level
    argument). Template binds carry exactly one placeholder by contract."""
    found = []

    def walk(o):
        if isinstance(o, dict):
            return {k: walk(v) for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        if isinstance(o, str) and _URL_PLACEHOLDER in o:
            found.append(o)
            return o.replace(_URL_PLACEHOLDER, url)
        return o

    out = walk(arguments)
    return out if found else None


def _listener_problem(listener: Any) -> str | None:
    """Why the listener cannot be trusted, or None. A listener closed by anyone
    before the driver returns is unhealthy: ``health()`` alone reports ok after
    a close, so a driver that kept sending would reach KILL on a dead listener.
    The CLI closes the listener only after the driver has returned."""
    health = listener.health()
    if health != "ok":
        return "listener health %s" % health
    if getattr(listener, "closed", False) is True:
        return "listener closed"
    return None


def run_driver(
    plans: Sequence[SendPlan],
    *,
    caller: ToolCaller,
    listener: Any,
    key: bytes,
    run_id: str,
    target: AdvertisedTarget,
    settle: float = 5.0,
    drain: float = 5.0,
    call_timeout: float = 30.0,
    max_calls: int | None = None,
    rate: float | None = None,
    gate: Any = None,
    resolver: Callable[[str], list[str]] | None = None,
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
) -> DriveResult:
    """Drive every plan in order and return the send records (see module docstring)."""
    if not isinstance(target, AdvertisedTarget):
        raise TypeError("target must be a validated egressnet.AdvertisedTarget")
    if settle < 0 or drain < 0 or call_timeout <= 0:
        raise ValueError("settle and drain must be >= 0 and call_timeout > 0")
    if gate is None and rate is not None:
        gate = RateGate(rate, sleep=sleep)

    plans = list(plans)
    records = [_not_called(i, p) for i, p in enumerate(plans)]
    result = DriveResult(records, True, settle=settle, drain=drain)

    def stop(reason: str, detail: str = "") -> DriveResult:
        result.complete = False
        result.stop_reason = reason
        result.stop_detail = detail
        return result

    if max_calls is not None and len(plans) > max_calls:
        return stop(STOP_MAX_CALLS, "%d sends planned, max_calls is %d" % (len(plans), max_calls))
    problem = _listener_problem(listener)
    if problem:
        return stop(STOP_LISTENER_UNHEALTHY, problem)

    for i, plan in enumerate(plans):
        if gate is not None:
            gate.wait()
        try:
            current = recheck_advertised(target, resolver=resolver)
        except Exception as exc:  # fail closed: any failure to prove the target stops the run
            return stop(STOP_RECHECK_FAILED, "%s: %s" % (type(exc).__name__, exc))
        # Adjacent to the act: the rate gate and the previous settle window sit
        # between the earlier health check and this call.
        problem = _listener_problem(listener)
        if problem:
            return stop(STOP_LISTENER_UNHEALTHY, problem)
        entry_id = format(i + 1, "x")
        nonce = marker.new_nonce()
        token = marker.build_token(key, run_id, entry_id, nonce)
        url = current.url.rstrip("/") + "/" + token
        sent = _inject_url(plan.arguments, url)
        if sent is None:
            sent = dict(plan.arguments)
            sent[plan.argument] = url
        rec = records[i]
        rec.entry_id, rec.nonce, rec.token, rec.url = entry_id, nonce, token, url
        rec.arguments = copy.deepcopy(sent)
        rec.address_class = current.address_class
        rec.advertised_host, rec.advertised_port = current.host, current.port
        rec.sent_wall = clock()
        rec.outcome = "transport_error"  # overwritten below; set first in case of a hard stop
        window = listener.open_window()
        rec.window_start = listener.offset()
        try:
            try:
                out = caller.call_tool(plan.tool, copy.deepcopy(sent), call_timeout)
                kind, text = out.kind, out.text
                if kind not in OUTCOME_KINDS:
                    kind, text, rec.error = "transport_error", "", "unknown outcome kind %r" % (kind,)
            except TimeoutError as exc:
                kind, text, rec.error = "timeout", "", str(exc)[:200]
            except Exception as exc:
                kind, text, rec.error = "transport_error", "", "%s: %s" % (type(exc).__name__, exc)
                rec.error = rec.error[:200]
            rec.outcome = kind
            text = text if isinstance(text, str) else str(text)
            rec.result_truncated = len(text) > RESULT_TEXT_CAP
            rec.result_text = text[:RESULT_TEXT_CAP]
            listener.wait_for_entry(entry_id, settle)
        finally:
            rec.window_end = listener.offset()
            listener.close_window(window)
        problem = _listener_problem(listener)
        if problem:
            return stop(STOP_LISTENER_UNHEALTHY, problem)

    window = listener.open_window()
    result.drain_start = listener.offset()
    try:
        sleep(drain)
    finally:
        result.drain_end = listener.offset()
        listener.close_window(window)
    problem = _listener_problem(listener)
    if problem:
        return stop(STOP_LISTENER_UNHEALTHY, problem)
    return result
