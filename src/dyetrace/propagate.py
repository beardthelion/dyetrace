"""U6 drive and propagate.

Drives the U4 planted descriptors as identity 1, then auto-replays the recorded
read-shaped surfaces as identity 1 (and as identity 2 when a second session plus
its own client are supplied). The auto-replay set is an explicit allowlist:
{GET, HEAD} plus operator-marked POST read surfaces, minus operator-excluded
indices (R8, R24, KTD9). Every other or unknown method (PUT, DELETE, PATCH,
unmarked POST, custom verbs) is plant-only and never auto-fired.

Fail-closed (KTD11): a propagate step that reached zero surfaces stops with an
error before anything is sent (R17). A per-request failure is never a
fail-closed stop: a connection error, timeout, unsafe/allowlist rejection,
over-cap response, or non-success status on one request is recorded against that
observation and the run continues (R20). A planted send that returned a
non-success status also sets ``plant_rejected`` for the verdict stage
(R5(d), KTD16).

Headless (R16). Nothing here builds httpx objects or opens a client; it drives
whatever ``IdentityClient``-shaped object exposes ``.send(...)``. The emitted
``Observation`` list is the uniform surface the verdict stage (U7) consumes.
"""

from dataclasses import dataclass

import httpx

from .net import (
    AllowlistError,
    CleartextError,
    NetError,
    ResolutionError,
    ResponseTooLargeError,
    UnsafeAddressError,
)
from .plant import MultipartBody, RawBody, _multipart_body
from .masking import is_sensitive_header

__all__ = [
    "PropagateError",
    "EmptyPropagationError",
    "MarkedMethodError",
    "PlantSource",
    "PropagateSource",
    "Observation",
    "drive",
]

# Explicit allowlist: the only methods auto-replayed without an operator mark.
_READ_METHODS = frozenset({"GET", "HEAD"})


class PropagateError(Exception):
    """Base class for propagate-stage failures (fail-closed family)."""


class EmptyPropagationError(PropagateError):
    """The selected propagation set is empty; stop fail-closed (R17, KTD11)."""


class MarkedMethodError(PropagateError):
    """An operator marked a non-POST method as a read surface (R24 allows POST only)."""


@dataclass
class PlantSource:
    """Attributes a plant observation back to its descriptor (R7, R19)."""

    entry_id: str
    variant: str
    path_id: str


@dataclass
class PropagateSource:
    """Attributes a propagate observation to its recorded-request index."""

    index: int


@dataclass
class Observation:
    identity: int                 # 1 or 2
    kind: str                     # "plant" or "propagate"
    url: str                      # sink url this response came from
    status: int | None            # response status, or None if it failed first
    body: bytes                   # response body bytes (b"" when failed/over-cap)
    headers: list                 # response headers as ordered (name, value) tuples
    source: object                # PlantSource or PropagateSource
    error: str | None             # typed failure reason, else None
    plant_rejected: bool = False  # plant whose status was non-success (>=400)


def _classify_error(exc: Exception) -> str:
    """Map a net/httpx exception to its stable typed ``error`` string (R20)."""
    if isinstance(exc, AllowlistError):
        return "allowlist"
    if isinstance(exc, CleartextError):
        return "cleartext"
    if isinstance(exc, ResponseTooLargeError):
        return "too-large"
    if isinstance(exc, UnsafeAddressError):
        return "unsafe-address"
    if isinstance(exc, ResolutionError):
        return "resolution"
    if isinstance(exc, httpx.TimeoutException):
        return "timeout"
    if isinstance(exc, httpx.ConnectError):
        return "connection"
    if isinstance(exc, NetError):
        return "net"
    return "request"


def _response_headers(resp: httpx.Response) -> list:
    return list(resp.headers.items())


def _planted_send_kwargs(body) -> dict:
    """Map a PlantedRequest body to httpx send kwargs (KTD7)."""
    if body is None:
        return {}
    if isinstance(body, RawBody):
        return {"content": body.data}
    if isinstance(body, MultipartBody):
        return {"data": list(body.data_fields), "files": list(body.file_parts)}
    raise TypeError(f"unsupported planted body: {type(body)!r}")


def _recorded_send_kwargs(body) -> dict:
    """Map a recorded Body to httpx send kwargs for an unplanted replay.

    The multipart split is plant's `_multipart_body(parts, None)` (no injection),
    so the field/file partition stays single-sourced with the plant path (KTD7).
    """
    if body is None:
        return {}
    if body.parts is not None:
        return _planted_send_kwargs(_multipart_body(body.parts, None))
    return {"content": body.data}


def _recorded_headers(body, headers) -> list:
    """Headers for replaying a recorded read surface.

    Drops a multipart Content-Type so httpx owns the boundary and
    Content-Length (KTD7), and drops identity-bearing headers (Cookie,
    Authorization, and the wider sensitive set) so each IdentityClient supplies
    its own credentials. Otherwise an identity-2 replay would carry identity-1's
    recorded Cookie/Authorization and the cross-context comparison would be
    contaminated.
    """
    multipart = body is not None and body.parts is not None
    out = []
    for name, value in headers:
        if is_sensitive_header(name):
            continue
        if multipart and name.lower() == "content-type":
            continue
        out.append((name, value))
    return out


def _send_observation(
    client,
    *,
    identity: int,
    kind: str,
    method: str,
    url: str,
    headers: list,
    send_kwargs: dict,
    source: object,
    is_plant: bool,
) -> Observation:
    """One send plus its typed capture. Never raises for a request failure."""
    try:
        resp = client.send(method, url, headers=headers, **send_kwargs)
    except (
        NetError,
        httpx.HTTPError,
        httpx.InvalidURL,
        httpx.CookieConflict,
        httpx.StreamError,
    ) as exc:
        return Observation(
            identity=identity,
            kind=kind,
            url=url,
            status=None,
            body=b"",
            headers=[],
            source=source,
            error=_classify_error(exc),
            plant_rejected=False,
        )
    return Observation(
        identity=identity,
        kind=kind,
        url=url,
        status=resp.status_code,
        body=resp.content,
        headers=_response_headers(resp),
        source=source,
        error=None,
        plant_rejected=is_plant and resp.status_code >= 400,
    )


def _select_surfaces(session, read_surface_indices, excluded_indices) -> list:
    """The read-shaped indices to replay: {GET,HEAD} plus operator-marked POST
    read surfaces, minus operator-excluded indices (R8, R24, KTD9).

    A mark only ever promotes a POST to a read surface. Marking a mutating
    non-POST method (PUT/DELETE/PATCH/custom) would auto-fire it, so reject that
    up front rather than silently replaying a destructive request.
    """
    marked = set(read_surface_indices)
    excluded = set(excluded_indices)
    for index in marked:
        if 0 <= index < len(session.recorded_requests):
            method = session.recorded_requests[index].method.upper()
            if method not in _READ_METHODS and method != "POST":
                raise MarkedMethodError(
                    f"cannot mark index {index} ({method}) as a read surface; "
                    "only a recorded POST may be marked (R24)"
                )
    selected = []
    for index, req in enumerate(session.recorded_requests):
        if index in excluded:
            continue
        method = req.method.upper()
        if method in _READ_METHODS or (index in marked and method == "POST"):
            selected.append(index)
    return selected


def drive(
    session,
    plant_result,
    client1,
    *,
    read_surface_indices=(),
    excluded_indices=(),
    identity2=None,
    client2=None,
    allow_empty_surfaces=False,
) -> list:
    """Drive plants (identity 1), then replay read surfaces (identity 1, and 2).

    Phase 1 sends every ``plant_result.planted`` descriptor through ``client1``.
    Phase 2 replays the selected recorded read surfaces UNPLANTED through
    ``client1`` and, when ``identity2`` and ``client2`` are supplied, the SAME
    surfaces through ``client2`` (KTD13). Returns one uniform ``Observation`` per
    send. Raises ``EmptyPropagationError`` (and only then) when the selected
    propagation set is empty, before any request is sent (R17, KTD11) - unless
    ``allow_empty_surfaces`` is set, the OSS-mode carve-out where the plants
    themselves are the predicted surfaces and no read replay is required.
    """
    selected = _select_surfaces(session, read_surface_indices, excluded_indices)
    if not selected and not allow_empty_surfaces:
        raise EmptyPropagationError(
            "propagation reached zero read-shaped surfaces; stopping fail-closed"
        )

    observations: list = []

    # Phase 1: drive the planted descriptors as identity 1.
    for planted in plant_result.planted:
        observations.append(
            _send_observation(
                client1,
                identity=1,
                kind="plant",
                method=planted.method,
                url=planted.url,
                headers=list(planted.headers),
                send_kwargs=_planted_send_kwargs(planted.body),
                source=PlantSource(
                    entry_id=planted.entry_id,
                    variant=planted.variant,
                    path_id=planted.path_id,
                ),
                is_plant=True,
            )
        )

    # Phase 2: replay the selected surfaces unplanted, per identity.
    passes = [(1, client1)]
    if identity2 is not None and client2 is not None:
        passes.append((2, client2))

    for identity, client in passes:
        for index in selected:
            req = session.recorded_requests[index]
            observations.append(
                _send_observation(
                    client,
                    identity=identity,
                    kind="propagate",
                    method=req.method,
                    url=req.url,
                    headers=_recorded_headers(req.body, req.headers),
                    send_kwargs=_recorded_send_kwargs(req.body),
                    source=PropagateSource(index=index),
                    is_plant=False,
                )
            )

    return observations
