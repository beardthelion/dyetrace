"""Tests for the U5 network core.

Test-first: these are written before src/dyetrace/net.py exists, so the import
fails RED until the module is implemented. No real network and no real DNS: the
resolver and the clock are injected, and httpx.MockTransport stands in for the
wire.

Invariants under test: one allowlist choke point validates every request host
before send (R13/KTD8), unsafe resolutions are rejected and the address pinned
(KTD8), one shared rate gate paces every send (R14/KTD10), transport is HTTPS
with cert verification unless allow_cleartext is set with a warning (R21/KTD5),
and a response over the byte cap ends as a typed failure, never an empty
success (R25/KTD17).
"""

import httpx
import pytest

from dyetrace.net import (
    AllowlistError,
    CleartextError,
    CleartextWarning,
    HostGuard,
    IdentityClient,
    NetError,
    RateGate,
    ResponseTooLargeError,
    UnsafeAddressError,
)

ALLOW_HOST = "app.example.com"
PUBLIC_IP = "93.184.216.34"  # public, outside every rejected range


def safe_resolver(host):
    return [PUBLIC_IP]


def _handler_recording(calls, *, status=200, content=b"ok", headers=None):
    def handler(request):
        calls.append(request)
        return httpx.Response(status, content=content, headers=headers or {})

    return handler


def _guard(resolver=safe_resolver, allowlist=(ALLOW_HOST,)):
    return HostGuard(allowlist, resolver=resolver)


def _client(
    *,
    guard=None,
    gate=None,
    base_url="https://app.example.com",
    cookies=None,
    auth_headers=None,
    allow_cleartext=False,
    byte_cap=1024,
    calls=None,
    handler=None,
):
    if guard is None:
        guard = _guard()
    if gate is None:
        gate = RateGate(1000.0)
    if handler is None:
        handler = _handler_recording(calls if calls is not None else [])
    return IdentityClient(
        host_guard=guard,
        gate=gate,
        base_url=base_url,
        cookies=cookies or {},
        auth_headers=auth_headers or {},
        allow_cleartext=allow_cleartext,
        byte_cap=byte_cap,
        transport=httpx.MockTransport(handler),
    )


# --- Happy path -----------------------------------------------------------


def test_https_allowlisted_send_returns_and_no_redirects():
    calls = []
    with _client(calls=calls) as client:
        assert client.follow_redirects is False
        resp = client.send("GET", "https://app.example.com/thing")
        assert resp.status_code == 200
        assert resp.content == b"ok"
    assert len(calls) == 1
    assert calls[0].url.host == "app.example.com"


# --- Allowlist choke point ------------------------------------------------


def test_non_allowlisted_host_raises_and_is_never_sent():
    calls = []
    with _client(calls=calls) as client:
        with pytest.raises(AllowlistError):
            client.send("GET", "https://evil.example.com/x")
    assert calls == []  # the request never reached the transport


def test_absolute_url_to_non_allowlisted_not_rescued_by_base_url():
    # base_url is the allowlisted host, but an absolute URL to a different host
    # must not be rescued by it.
    calls = []
    with _client(calls=calls, base_url="https://app.example.com") as client:
        with pytest.raises(AllowlistError):
            client.send("GET", "https://evil.example.com/steal")
    assert calls == []


def test_host_match_is_exact_no_implicit_subdomain():
    calls = []
    with _client(calls=calls) as client:
        with pytest.raises(AllowlistError):
            client.send("GET", "https://sub.app.example.com/x")
    assert calls == []


def test_trailing_dot_and_case_are_normalized():
    calls = []
    with _client(calls=calls) as client:
        resp = client.send("GET", "https://APP.Example.com./thing")
        assert resp.status_code == 200
    assert len(calls) == 1


# --- Resolution / pinning safety ------------------------------------------


@pytest.mark.parametrize(
    "addr",
    ["127.0.0.1", "169.254.169.254", "10.0.0.1", "192.168.1.1", "172.16.0.1"],
)
def test_unsafe_resolution_is_rejected_at_construction(addr):
    def resolver(host):
        return [addr]

    with pytest.raises(UnsafeAddressError):
        HostGuard([ALLOW_HOST], resolver=resolver)


def test_pinned_address_is_recorded_for_the_run():
    guard = _guard()
    assert guard.pinned_addresses[ALLOW_HOST] == [PUBLIC_IP]


def test_empty_resolution_is_a_failure_not_a_pass():
    def resolver(host):
        return []

    with pytest.raises(NetError):
        HostGuard([ALLOW_HOST], resolver=resolver)


# --- Transport policy (R21) -----------------------------------------------


def test_plain_http_without_flag_raises_and_is_never_sent():
    calls = []
    with _client(calls=calls, base_url="http://app.example.com") as client:
        with pytest.raises(CleartextError):
            client.send("GET", "http://app.example.com/thing")
    assert calls == []


def test_plain_http_with_flag_is_allowed_and_warns():
    calls = []
    with _client(
        calls=calls, base_url="http://app.example.com", allow_cleartext=True
    ) as client:
        with pytest.warns(CleartextWarning):
            resp = client.send("GET", "http://app.example.com/thing")
        assert resp.status_code == 200
    assert len(calls) == 1


# --- Rate gate (R14/KTD10) ------------------------------------------------


class FakeClock:
    def __init__(self, start=1000.0):
        self.t = start

    def monotonic(self):
        return self.t

    def sleep(self, seconds):
        assert seconds >= 0
        self.t += seconds


def test_rate_gate_spaces_back_to_back_sends():
    clock = FakeClock()
    rate = 5.0  # interval 0.2
    gate = RateGate(rate, monotonic=clock.monotonic, sleep=clock.sleep)
    seen = []

    def handler(request):
        seen.append(clock.monotonic())
        return httpx.Response(200, content=b"ok")

    with _client(gate=gate, handler=handler) as client:
        client.send("GET", "https://app.example.com/a")
        client.send("GET", "https://app.example.com/b")

    assert len(seen) == 2
    assert seen[1] - seen[0] >= 1.0 / rate


def test_single_gate_shared_across_two_identities():
    clock = FakeClock()
    rate = 4.0  # interval 0.25
    gate = RateGate(rate, monotonic=clock.monotonic, sleep=clock.sleep)
    guard = _guard()
    seen = []

    def handler(request):
        seen.append(clock.monotonic())
        return httpx.Response(200, content=b"ok")

    transport = httpx.MockTransport(handler)
    user = IdentityClient(
        host_guard=guard,
        gate=gate,
        base_url="https://app.example.com",
        cookies={"sid": "u"},
        auth_headers={},
        byte_cap=1024,
        transport=transport,
    )
    admin = IdentityClient(
        host_guard=guard,
        gate=gate,
        base_url="https://app.example.com",
        cookies={"sid": "a"},
        auth_headers={},
        byte_cap=1024,
        transport=transport,
    )
    with user, admin:
        user.send("GET", "https://app.example.com/a")
        admin.send("GET", "https://app.example.com/b")

    assert len(seen) == 2
    assert seen[1] - seen[0] >= 1.0 / rate


# --- Byte cap (R25/KTD17) -------------------------------------------------


def test_response_over_cap_fails_not_empty_success():
    calls = []
    handler = _handler_recording(calls, content=b"x" * 5000)
    with _client(byte_cap=100, handler=handler) as client:
        with pytest.raises(ResponseTooLargeError):
            client.send("GET", "https://app.example.com/big")


def test_response_at_or_under_cap_returns_body():
    calls = []
    handler = _handler_recording(calls, content=b"y" * 100)
    with _client(byte_cap=100, handler=handler) as client:
        resp = client.send("GET", "https://app.example.com/small")
        assert resp.content == b"y" * 100


def test_declared_oversize_content_length_is_rejected():
    # An honest, oversized Content-Length is rejected before the body streams.
    calls = []
    handler = _handler_recording(
        calls, content=b"z" * 5000, headers={"content-length": "5000"}
    )
    with _client(byte_cap=100, handler=handler) as client:
        with pytest.raises(ResponseTooLargeError):
            client.send("GET", "https://app.example.com/big")


# --- Per-identity isolation (KTD5) ----------------------------------------


def test_each_identity_has_its_own_cookies():
    guard = _guard()
    gate = RateGate(1000.0)
    transport = httpx.MockTransport(lambda r: httpx.Response(200, content=b"ok"))
    user = IdentityClient(
        host_guard=guard,
        gate=gate,
        base_url="https://app.example.com",
        cookies={"sid": "user-cookie"},
        auth_headers={"authorization": "Bearer U"},
        byte_cap=1024,
        transport=transport,
    )
    admin = IdentityClient(
        host_guard=guard,
        gate=gate,
        base_url="https://app.example.com",
        cookies={"sid": "admin-cookie"},
        auth_headers={"authorization": "Bearer A"},
        byte_cap=1024,
        transport=transport,
    )
    with user, admin:
        assert user.cookies_jar.get("sid") == "user-cookie"
        assert admin.cookies_jar.get("sid") == "admin-cookie"
        assert user.cookies_jar.get("sid") != admin.cookies_jar.get("sid")


# --- Pin enforcement against DNS rebinding (hardening) ---------------------


def _rebinding_resolver(first, later):
    """Return ``first`` on the construction call, ``later`` on every call after."""
    state = {"n": 0}

    def resolver(host):
        state["n"] += 1
        return first if state["n"] == 1 else later

    return resolver


def test_check_passes_when_resolution_is_stable():
    guard = _guard()
    guard.check(ALLOW_HOST)  # safe_resolver is stable; no raise


def test_rebinding_to_forbidden_range_is_rejected_at_check():
    # Pinned safe at construction, then the host is rebound to the metadata IP.
    guard = HostGuard(
        [ALLOW_HOST], resolver=_rebinding_resolver([PUBLIC_IP], ["169.254.169.254"])
    )
    with pytest.raises(UnsafeAddressError):
        guard.check(ALLOW_HOST)


def test_rebinding_to_unpinned_address_is_rejected_at_check():
    # Rebound to a different public IP that was never pinned for this run.
    guard = HostGuard(
        [ALLOW_HOST], resolver=_rebinding_resolver([PUBLIC_IP], ["198.51.100.7"])
    )
    with pytest.raises(UnsafeAddressError):
        guard.check(ALLOW_HOST)


def test_rebinding_during_rate_gate_window_is_caught_before_dial():
    # The rate gate can sleep for seconds between the pre-gate allowlist check
    # and the dial. A rebind that lands in that window (safe at construction and
    # at the pre-gate check, forbidden by the time the gate releases) must be
    # caught by the pre-dial re-check, so nothing ever reaches the transport.
    state = {"n": 0}

    def resolver(host):
        state["n"] += 1
        # call 1: construction pin; call 2: pre-gate check -> both safe.
        # call 3: pre-dial check, after the gate slept -> rebound to metadata IP.
        return [PUBLIC_IP] if state["n"] <= 2 else ["169.254.169.254"]

    guard = HostGuard([ALLOW_HOST], resolver=resolver)
    gate = RateGate(1000.0, monotonic=lambda: 0.0, sleep=lambda s: None)
    sent = []

    def handler(request):
        sent.append(request)
        return httpx.Response(200, content=b"ok")

    client = IdentityClient(
        host_guard=guard, gate=gate, transport=httpx.MockTransport(handler)
    )
    with pytest.raises(UnsafeAddressError):
        client.send("GET", f"https://{ALLOW_HOST}/x")
    assert sent == []  # the rebind was caught before any byte left the process
    client.close()


# --- Compressed-response rejection (decompression amplification) -----------


def test_compressed_response_is_rejected():
    import gzip

    gzipped = gzip.compress(b"small")

    def handler(request):
        return httpx.Response(
            200, content=gzipped, headers={"content-encoding": "gzip"}
        )

    guard = _guard()
    gate = RateGate(1000.0, monotonic=lambda: 0.0, sleep=lambda s: None)
    client = IdentityClient(
        host_guard=guard, gate=gate, transport=httpx.MockTransport(handler)
    )
    with pytest.raises(ResponseTooLargeError):
        client.send("GET", f"https://{ALLOW_HOST}/x")
    client.close()


def test_streamed_body_over_cap_is_rejected_without_content_length():
    # The declared-Content-Length guard is tested elsewhere; this exercises the
    # streaming accumulation branch (the real amplification defense): a body with
    # no accurate Content-Length that exceeds the cap while streaming.
    def handler(request):
        return httpx.Response(200, content=(b"x" * 40 for _ in range(5)))  # 200 bytes, chunked

    guard = _guard()
    gate = RateGate(1000.0, monotonic=lambda: 0.0, sleep=lambda s: None)
    client = IdentityClient(
        host_guard=guard, gate=gate, byte_cap=100,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ResponseTooLargeError):
        client.send("GET", f"https://{ALLOW_HOST}/big")
    client.close()


class TestAllowLoopback:
    def test_loopback_blocked_by_default(self):
        from dyetrace.net import HostGuard, UnsafeAddressError
        with pytest.raises(UnsafeAddressError):
            HostGuard(["127.0.0.1"])

    def test_loopback_permitted_with_flag(self):
        from dyetrace.net import HostGuard
        guard = HostGuard(["127.0.0.1"], allow_loopback=True)
        guard.check("127.0.0.1")

    def test_private_non_loopback_still_blocked_with_flag(self):
        from dyetrace.net import HostGuard, UnsafeAddressError
        with pytest.raises(UnsafeAddressError):
            HostGuard(["host"], resolver=lambda h: ["10.0.0.5"],
                      allow_loopback=True)

    def test_loopback_rebind_still_blocked_on_send_check(self):
        """Even with the flag, a host pinned loopback then rebinding to a
        private non-loopback address is unsafe at check time."""
        from dyetrace.net import HostGuard, UnsafeAddressError
        addrs = {"h": ["127.0.0.1"]}
        guard = HostGuard(["h"], resolver=lambda h: addrs["h"],
                          allow_loopback=True)
        addrs["h"] = ["192.168.1.5"]
        with pytest.raises(UnsafeAddressError):
            guard.check("h")


def test_recorded_accept_encoding_is_forced_to_identity():
    """A captured session's accept-encoding (e.g. "gzip, deflate" from a
    browser/client default) must not win: the byte cap only bounds identity
    bodies, so sends always ask for identity."""
    seen = {}
    def handler(request):
        seen["ae"] = request.headers.get("accept-encoding")
        return httpx.Response(200, content=b"ok")
    with _client(handler=handler) as c:
        c.send("GET", "https://app.example.com/x",
               headers=[("accept-encoding", "gzip, deflate")])
    assert seen["ae"] == "identity"
