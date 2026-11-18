"""U5 network core.

One long-lived httpx client per identity (KTD5). Every request validates and
pins its host at a single choke point (R13, KTD8), is paced through one shared
rate gate (R14, KTD10), runs headless (R16), uses HTTPS with cert verification
unless an explicit allow_cleartext flag with a warning is set (R21, KTD5), and
is capped at a hard response-byte limit before buffering or scanning (R25,
KTD17). An over-cap response ends that observation as a typed failure, never an
empty success.

The resolver and the clock are injectable so the whole module is testable with
no real network and no real DNS.
"""

import ipaddress
import socket
import time
import warnings
from collections.abc import Callable, Iterable, Mapping

import httpx

__all__ = [
    "NetError",
    "AllowlistError",
    "ResolutionError",
    "UnsafeAddressError",
    "CleartextError",
    "CleartextWarning",
    "ResponseTooLargeError",
    "HostGuard",
    "RateGate",
    "IdentityClient",
]

# One choke point, one gate. Finite timeout: no request may hang the run.
_DEFAULT_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=30.0, pool=10.0)
_DEFAULT_BYTE_CAP = 8 * 1024 * 1024


class NetError(Exception):
    """Base class for every network-core failure (fail-closed family)."""


class AllowlistError(NetError):
    """A request host is not on the allowlist; reject at the choke point."""


class ResolutionError(NetError):
    """An allowlisted host resolved to nothing; cannot pin, so reject."""


class UnsafeAddressError(NetError):
    """An allowlisted host resolved into a forbidden range (SSRF guard)."""


class CleartextError(NetError):
    """A plain-HTTP target was requested without the allow_cleartext flag."""


class ResponseTooLargeError(NetError):
    """A response exceeded the hard byte cap; a failed, non-clean result."""


class CleartextWarning(UserWarning):
    """Emitted once per plain-HTTP send permitted by allow_cleartext."""


def _normalize_host(host: str) -> str:
    """Lowercase and strip a trailing dot so the compare is exact (KTD8)."""
    return host.strip().rstrip(".").lower()


def _is_unsafe_address(addr: str, *, allow_loopback: bool = False) -> bool:
    """True for any address a target host must never resolve into.

    Covers loopback (127.0.0.0/8, ::1), private (10/8, 172.16/12, 192.168/16,
    fc00::/7), link-local (169.254/16 incl. the 169.254.169.254 metadata
    endpoint, fe80::/10), multicast, reserved, and unspecified ranges.

    ``allow_loopback`` exempts only the loopback property for OSS harness
    runs; every other forbidden range stays forbidden.
    """
    ip = ipaddress.ip_address(addr)
    return (
        (ip.is_private and not ip.is_loopback)
        or (ip.is_loopback and not allow_loopback)
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def default_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    # Deduplicate while keeping order; sockaddr[0] is the address string.
    return list(dict.fromkeys(info[4][0] for info in infos))


_default_resolver = default_resolver


class HostGuard:
    """The single allowlist choke point plus resolver and address pinner.

    At construction every allowlisted host is resolved once, each resolved
    address is checked against the forbidden ranges, and the safe addresses are
    pinned for the run so DNS rebinding cannot swing a later send onto a private
    target. ``check`` validates one request host against the allowlist on every
    send; the match is exact (no implicit subdomains, no base_url rescue).
    """

    def __init__(
        self,
        allowlist: Iterable[str],
        resolver: Callable[[str], Iterable[str]] | None = None,
        allow_loopback: bool = False,
    ) -> None:
        self._resolver = resolver or _default_resolver
        self._allow_loopback = allow_loopback
        self._allow: set[str] = set()
        self.pinned_addresses: dict[str, list[str]] = {}
        for raw in allowlist:
            host = _normalize_host(raw)
            if not host:
                raise AllowlistError("allowlist host must be a non-empty string")
            self._allow.add(host)
            self.pinned_addresses[host] = self._resolve_and_pin(host)
        if not self._allow:
            raise AllowlistError("allowlist must contain at least one host")

    def _resolve_and_pin(self, host: str) -> list[str]:
        addrs = list(self._resolver(host))
        if not addrs:
            raise ResolutionError(f"host did not resolve: {host!r}")
        for addr in addrs:
            if _is_unsafe_address(addr, allow_loopback=self._allow_loopback):
                raise UnsafeAddressError(
                    f"host {host!r} resolved into a forbidden range: {addr}"
                )
        return addrs

    def check(self, host: str | None) -> None:
        """Enforce the allowlist and the pinned resolution on every send (KTD8).

        The exact-host match is necessary but not sufficient: a host pinned at
        construction can be rebound to a new address mid-run, so re-resolve here
        and reject any current address that is unsafe or was not pinned. This
        enforces the pin instead of only recording it. A connect-time window
        remains, because httpx resolves again when it dials; closing it fully
        needs connection-level address binding, left as a hardening follow-up.
        """
        if not host:
            raise AllowlistError(f"host not on allowlist: {host!r}")
        norm = _normalize_host(host)
        if norm not in self._allow:
            raise AllowlistError(f"host not on allowlist: {host!r}")
        current = list(self._resolver(norm))
        if not current:
            raise ResolutionError(f"host did not resolve: {norm!r}")
        pinned = self.pinned_addresses[norm]
        for addr in current:
            if _is_unsafe_address(addr, allow_loopback=self._allow_loopback):
                raise UnsafeAddressError(
                    f"host {norm!r} now resolves into a forbidden range: {addr}"
                )
            if addr not in pinned:
                raise UnsafeAddressError(
                    f"host {norm!r} resolution changed since pinning: {addr}"
                )


class RateGate:
    """One shared, sequential rate gate (KTD10).

    Monotonic clock only; no semaphore, no wall clock, no jitter or backoff.
    One instance is shared across every identity's client so the whole run is
    paced as a single stream.
    """

    def __init__(
        self,
        rate: float,
        *,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if rate <= 0:
            raise ValueError("rate must be positive requests per second")
        self._interval = 1.0 / rate
        self._monotonic = monotonic
        self._sleep = sleep
        self._next_allowed: float | None = None

    def wait(self) -> None:
        now = self._monotonic()
        scheduled = now if self._next_allowed is None else max(now, self._next_allowed)
        delay = scheduled - now
        if delay > 0:
            self._sleep(delay)
        self._next_allowed = scheduled + self._interval


class IdentityClient:
    """One long-lived httpx client for a single identity (KTD5).

    Initialized only from this identity's cookies and auth headers, so two
    identities never share mutable session state. Every ``send`` runs the shared
    host-allowlist choke point, the transport policy, the shared rate gate, the
    send, and the hard byte-cap check, in that order.
    """

    def __init__(
        self,
        *,
        host_guard: HostGuard,
        gate: RateGate,
        base_url: str = "",
        cookies: Mapping[str, str] | None = None,
        auth_headers: Mapping[str, str] | None = None,
        allow_cleartext: bool = False,
        byte_cap: int = _DEFAULT_BYTE_CAP,
        timeout: httpx.Timeout = _DEFAULT_TIMEOUT,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._guard = host_guard
        self._gate = gate
        self._allow_cleartext = allow_cleartext
        self._byte_cap = byte_cap
        self._client = httpx.Client(
            base_url=base_url,
            cookies=dict(cookies or {}),
            # Accept-Encoding: identity so the byte cap bounds real work: a
            # compressed body could decode past the cap after the wire bytes
            # were under it (decompression amplification). An auth header may
            # override it, though a credential named accept-encoding is absurd.
            headers={"accept-encoding": "identity", **dict(auth_headers or {})},
            follow_redirects=False,
            http2=False,
            verify=True,
            timeout=timeout,
            transport=transport,
        )

    @classmethod
    def from_session(
        cls,
        session,
        *,
        host_guard: HostGuard,
        gate: RateGate,
        allow_cleartext: bool = False,
        byte_cap: int = _DEFAULT_BYTE_CAP,
        timeout: httpx.Timeout = _DEFAULT_TIMEOUT,
        transport: httpx.BaseTransport | None = None,
    ) -> "IdentityClient":
        """Build a client from a loaded U3 Session (cookies + auth headers)."""
        return cls(
            host_guard=host_guard,
            gate=gate,
            base_url=session.base_url,
            cookies=session.cookies,
            auth_headers=session.auth_headers,
            allow_cleartext=allow_cleartext,
            byte_cap=byte_cap,
            timeout=timeout,
            transport=transport,
        )

    @property
    def follow_redirects(self) -> bool:
        return self._client.follow_redirects

    @property
    def cookies_jar(self) -> httpx.Cookies:
        return self._client.cookies

    def send(
        self,
        method: str,
        url: str,
        *,
        headers=None,
        content=None,
        data=None,
        files=None,
    ) -> httpx.Response:
        req = self._client.build_request(
            method,
            url,
            headers=headers,
            content=content,
            data=data,
            files=files,
        )
        # The byte cap bounds DECODED bytes only, so every send must ask for an
        # identity body. A recorded accept-encoding (a captured browser or
        # client default like "gzip, deflate") would override the client-level
        # header and invite a compressed response the cap refuses - keep the
        # recorded header for fidelity everywhere but this one.
        req.headers["accept-encoding"] = "identity"
        # Choke point, before anything leaves the process or costs a rate slot.
        self._guard.check(req.url.host)
        self._check_scheme(req.url.scheme)
        self._gate.wait()
        # Re-validate immediately before the dial. The rate gate above can sleep
        # for seconds at a low rate, and a DNS rebind during that sleep would
        # otherwise slip past the pre-gate check; re-resolving here collapses
        # that window to the gap before httpcore's own dial-time resolution.
        self._guard.check(req.url.host)
        return self._send_capped(req)

    def _check_scheme(self, scheme: str) -> None:
        if scheme == "https":
            return
        if scheme == "http":
            if not self._allow_cleartext:
                raise CleartextError(
                    "plain HTTP requires the allow_cleartext flag"
                )
            warnings.warn(
                "sending over plain HTTP (allow_cleartext is set): "
                "no transport encryption or cert verification",
                CleartextWarning,
                stacklevel=3,
            )
            return
        raise CleartextError(f"unsupported URL scheme: {scheme!r}")

    def _send_capped(self, req: httpx.Request) -> httpx.Response:
        """Send, then enforce the byte cap before buffering the whole body."""
        resp = self._client.send(req, stream=True)
        try:
            encoding = resp.headers.get("content-encoding", "").strip().lower()
            if encoding and encoding != "identity":
                raise ResponseTooLargeError(
                    f"refusing compressed response (content-encoding {encoding!r}): "
                    "the byte cap bounds decoded size only on identity encoding"
                )
            declared = resp.headers.get("content-length")
            if declared is not None and declared.isdigit():
                if int(declared) > self._byte_cap:
                    raise ResponseTooLargeError(
                        f"declared content-length {declared} exceeds cap "
                        f"{self._byte_cap}"
                    )
            chunks: list[bytes] = []
            total = 0
            # Non-identity encodings are rejected above, so decoded size equals
            # wire size and iter_bytes cannot be amplified past the cap.
            for chunk in resp.iter_bytes():
                total += len(chunk)
                if total > self._byte_cap:
                    raise ResponseTooLargeError(
                        f"response body exceeds cap {self._byte_cap}"
                    )
                chunks.append(chunk)
            body = b"".join(chunks)
        finally:
            resp.close()
        return httpx.Response(
            status_code=resp.status_code,
            headers=resp.headers,
            content=body,
            request=req,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "IdentityClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
