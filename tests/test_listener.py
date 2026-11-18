"""Tests for U5 listener (KTD1, KTD3, KTD10, KTD12, KTD13).

Test-first: written before src/dyetrace/listener.py exists. Real loopback
sockets on an ephemeral port (the validate_bind port-0 test seam). Deadlines
and caps are module constants, shrunk with monkeypatch so stall, flood and
overflow tests run fast. Waits are event-based (Listener.wait_for), never
polling sleeps. Client helpers are local to this file (no prior socket tests).
"""

import socket
import threading
import time

import pytest

from dyetrace import listener as L
from dyetrace import marker
from dyetrace.egressnet import validate_bind

KEY = b"\x01" * 32
OTHER_KEY = b"\x02" * 32
RUN = "abc123"
OTHER_RUN = "def456"
FIXED = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


def spec(host="127.0.0.1", port=0):
    return validate_bind(host, port, allow_port_zero=True)


def tok(entry="1", key=KEY, run=RUN, nonce="aa11"):
    return marker.build_token(key, run, entry, nonce)


@pytest.fixture
def lst():
    lis = L.Listener(spec(), KEY, RUN)
    lis.start()
    try:
        yield lis
    finally:
        lis.close()


def addr_of(lis):
    return lis.address


def connect(lis):
    s = socket.create_connection(addr_of(lis), timeout=5)
    return s


def read_all(s):
    out = b""
    while True:
        try:
            d = s.recv(65536)
        except (ConnectionResetError, socket.timeout):
            break
        if not d:
            break
        out += d
    return out


def raw(lis, data):
    s = connect(lis)
    try:
        s.sendall(data)
        return read_all(s)
    finally:
        s.close()


def get(lis, path, method="GET", extra=""):
    req = "%s %s HTTP/1.1\r\nHost: x\r\n%s\r\n" % (method, path, extra)
    return raw(lis, req.encode("latin-1"))


def wait_noise(lis, n):
    assert lis.wait_for(lambda: lis.snapshot().noise_count >= n, 5)


# ---------------------------------------------------------------- happy

def test_get_valid_token_fixed_reply_and_verified_hit(lst):
    t = tok("1")
    assert get(lst, "/" + t) == FIXED
    assert lst.wait_for_entry("1", 5)
    snap = lst.snapshot()
    assert len(snap.verified_hits) == 1
    h = snap.verified_hits[0]
    assert (h.entry_id, h.nonce, h.token) == ("1", "aa11", t)
    assert h.method == "GET" and h.target == "/" + t
    assert h.source[0] == "127.0.0.1" and isinstance(h.source[1], int)
    assert h.arrival_index == 1
    assert h.offset >= 0 and h.wall > 1e9
    assert dict(h.headers)["host"] == "x"
    assert snap.noise_count == 0


def test_wait_returns_promptly_when_hit_arrives_before_and_after(lst):
    get(lst, "/" + tok("1"))
    t0 = time.monotonic()
    assert lst.wait_for_entry("1", 5) is True
    assert time.monotonic() - t0 < 1.0
    # arrives after the wait has started
    res = {}

    def waiter():
        res["ok"] = lst.wait_for_entry("2", 5)

    th = threading.Thread(target=waiter)
    th.start()
    get(lst, "/" + tok("2"))
    th.join(6)
    assert res["ok"] is True


def test_wait_times_out_false_for_unseen_entry(lst):
    t0 = time.monotonic()
    assert lst.wait_for_entry("99", 0.2) is False
    assert 0.15 < time.monotonic() - t0 < 2.0


def test_head_then_get_both_stored_and_per_token_cap(lst):
    t = tok("1")
    get(lst, "/" + t, method="HEAD")
    get(lst, "/" + t)
    snap = lst.snapshot()
    assert [h.method for h in snap.verified_hits] == ["HEAD", "GET"]
    for _ in range(23):
        get(lst, "/" + t)
    snap = lst.snapshot()
    assert len(snap.verified_hits) == 20
    assert snap.arrival_counts[t] == 25
    assert snap.verified_dropped == 0  # per-token overflow is counted, not store overflow
    assert lst.health() == "ok"


def test_absolute_form_target_path_is_searched(lst):
    t = tok("1")
    assert get(lst, "http://host.example/pre/" + t + "/post") == FIXED
    assert len(lst.snapshot().verified_hits) == 1


def test_post_body_discarded_with_fixed_reply(lst):
    t = tok("1")
    s = connect(lst)
    head = ("POST /%s HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\n" % t).encode()
    s.sendall(head + b"A" * 20000)
    out = read_all(s)
    s.close()
    assert out == FIXED
    assert len(lst.snapshot().verified_hits) == 1


# ------------------------------------------------------- must-not: forge

def test_wrong_mac_is_noise(lst):
    t = tok("1")
    bad = t[:-1] + ("0" if t[-1] != "0" else "1")
    get(lst, "/" + bad)
    wait_noise(lst, 1)
    assert lst.snapshot().verified_hits == ()


def test_other_key_is_noise(lst):
    get(lst, "/" + tok("1", key=OTHER_KEY))
    wait_noise(lst, 1)
    assert lst.snapshot().verified_hits == ()


def test_same_key_other_run_id_is_noise(lst):
    t = tok("1", run=OTHER_RUN)
    assert marker.verify(t, KEY)  # the MAC passes; only the run-id check fails
    get(lst, "/" + t)
    wait_noise(lst, 1)
    assert lst.snapshot().verified_hits == ()


def test_altered_nonce_is_noise(lst):
    t = tok("1", nonce="aa11")
    forged = t.replace("-aa11-", "-aa12-")
    assert forged != t
    get(lst, "/" + forged)
    wait_noise(lst, 1)
    assert lst.snapshot().verified_hits == ()


def test_token_only_in_header_is_noise(lst):
    get(lst, "/x", extra="Referer: http://h/%s\r\n" % tok("1"))
    wait_noise(lst, 1)
    snap = lst.snapshot()
    assert snap.verified_hits == () and lst.wait_for_entry("1", 0.1) is False


def test_token_only_in_query_is_noise(lst):
    get(lst, "/x?u=" + tok("1"))
    wait_noise(lst, 1)
    assert lst.snapshot().verified_hits == ()


# ----------------------------------------------------------- must-not: size

def test_request_line_over_cap_closed_no_reply_no_record(lst):
    out = raw(lst, b"GET /" + b"a" * 9000 + b" HTTP/1.1\r\nHost: x\r\n\r\n")
    assert out == b""
    assert lst.wait_for(lambda: lst.snapshot().oversize_closed >= 1, 5)
    snap = lst.snapshot()
    assert snap.noise_count == 0 and snap.verified_hits == ()


def test_many_large_headers_over_cap_closed(lst):
    hdrs = "".join("X-%d: %s\r\n" % (i, "b" * 400) for i in range(30))
    out = raw(lst, ("GET / HTTP/1.1\r\n" + hdrs + "\r\n").encode())
    assert out == b""
    assert lst.wait_for(lambda: lst.snapshot().oversize_closed >= 1, 5)
    assert lst.snapshot().noise_count == 0


def test_malformed_request_line_closed_silently(lst):
    out = raw(lst, b"NOT A REQUEST\r\n\r\n")
    assert out == b""
    assert lst.wait_for(lambda: lst.snapshot().malformed_closed >= 1, 5)
    assert lst.snapshot().noise_count == 0


# ----------------------------------------------------------- must-not: stall

def test_silent_connection_closed_at_deadline_and_does_not_block(lst, monkeypatch):
    monkeypatch.setattr(L, "HEAD_DEADLINE", 0.5)
    silent = connect(lst)
    try:
        assert get(lst, "/" + tok("1")) == FIXED  # served while the other stalls
        assert lst.wait_for_entry("1", 5)
        assert read_all(silent) == b""  # closed by the server at the deadline
        assert lst.wait_for(lambda: lst.snapshot().deadline_close_count >= 1, 5)
    finally:
        silent.close()
    snap = lst.snapshot()
    assert snap.deadline_close_count == 1 and len(snap.deadline_close_offsets) == 1


def test_drip_feed_closed_at_total_deadline(lst, monkeypatch):
    monkeypatch.setattr(L, "HEAD_DEADLINE", 0.6)
    s = connect(lst)
    t0 = time.monotonic()
    closed = False
    try:
        # each byte arrives well inside any per-read timeout of 0.6 s
        while time.monotonic() - t0 < 4:
            try:
                s.sendall(b"G")
            except OSError:
                closed = True
                break
            time.sleep(0.1)
    finally:
        s.close()
    assert closed
    assert time.monotonic() - t0 < 3
    assert lst.wait_for(lambda: lst.snapshot().deadline_close_count >= 1, 5)


# ---------------------------------------------------------------- flood

def _open_n(lis, n):
    socks = []
    for _ in range(n):
        socks.append(socket.create_connection(addr_of(lis), timeout=5))
    return socks


def test_flood_caps_concurrency_counts_refusals_then_recovers(lst):
    socks = _open_n(lst, 100)
    try:
        assert lst.wait_for(lambda: lst.snapshot().refused_count >= 68, 10)
        snap = lst.snapshot()
        assert snap.peak_connections <= 32 and snap.active_connections <= 32
        assert snap.refused_count == 68
    finally:
        for s in socks:
            s.close()
    assert lst.wait_for(lambda: lst.snapshot().active_connections == 0, 10)
    assert get(lst, "/" + tok("1")) == FIXED
    assert lst.wait_for_entry("1", 5)
    assert lst.snapshot().peak_connections <= 32


def test_interference_refused_token_request_is_recorded_with_offset(lst):
    holders = _open_n(lst, 32)
    try:
        assert lst.wait_for(lambda: lst.snapshot().active_connections == 32, 10)
        out = get(lst, "/" + tok("1"))
        assert out == b""
        assert lst.wait_for(lambda: lst.snapshot().refused_count >= 1, 5)
        snap = lst.snapshot()
        assert snap.refused_count == 1 and len(snap.refused_offsets) == 1
        assert snap.refused_offsets[0] >= 0
        assert snap.verified_hits == ()
    finally:
        for s in holders:
            s.close()


def test_mangled_prefix_request_is_unattributed_with_offset(lst):
    mangled = ("/" + tok("1")[:20]).lower()
    assert mangled.startswith("/dye-" + RUN)
    get(lst, mangled)
    assert lst.wait_for(lambda: lst.snapshot().unattributed_count >= 1, 5)
    snap = lst.snapshot()
    assert snap.unattributed_count == 1 and len(snap.unattributed_offsets) == 1
    assert snap.noise_count == 1 and snap.verified_hits == ()


def test_unrelated_noise_is_not_unattributed_outside_window(lst):
    get(lst, "/favicon.ico")
    wait_noise(lst, 1)
    assert lst.snapshot().unattributed_count == 0


def test_any_unverified_request_inside_open_window_is_unattributed(lst):
    w = lst.open_window()
    get(lst, "/favicon.ico")
    wait_noise(lst, 1)
    assert lst.snapshot().unattributed_count == 1
    lst.close_window(w)
    get(lst, "/other")
    wait_noise(lst, 2)
    assert lst.snapshot().unattributed_count == 1


def test_verified_hit_in_window_is_not_unattributed(lst):
    w = lst.open_window()
    get(lst, "/" + tok("1"))
    lst.close_window(w)
    assert lst.snapshot().unattributed_count == 0


def test_noise_flood_bounded_and_verified_hits_survive(lst):
    get(lst, "/" + tok("1"))
    errs = []

    def worker(n):
        try:
            for i in range(n):
                s = socket.create_connection(addr_of(lst), timeout=5)
                s.sendall(b"GET /noise%d HTTP/1.1\r\nHost: x\r\n\r\n" % i)
                read_all(s)
                s.close()
        except Exception as e:  # pragma: no cover
            errs.append(e)

    ths = [threading.Thread(target=worker, args=(3750,)) for _ in range(4)]
    for t in ths:
        t.start()
    for t in ths:
        t.join(120)
    assert not errs
    get(lst, "/" + tok("2"))
    # refusals under load are possible (4 workers < 32 slots, so none expected)
    assert lst.wait_for(lambda: lst.snapshot().noise_count >= 15000, 30)
    snap = lst.snapshot()
    assert snap.noise_count == 15000
    assert len(snap.noise_samples) == 100
    assert all(len(s.target) <= 200 for s in snap.noise_samples)
    assert len(snap.unattributed_offsets) <= L.MAX_OFFSETS
    assert {h.entry_id for h in snap.verified_hits} == {"1", "2"}


# ------------------------------------------------------------- reflection

def test_reply_never_reflects_request_data(lst):
    nasty = "/<script>alert(1)</script>%0d%0aLocation:%20http://evil/\x1b[31mred/" + tok("1")
    out = get(lst, nasty)
    assert out == FIXED
    assert b"Location" not in out and b"evil" not in out and b"script" not in out
    assert b"\x1b" not in out


# --------------------------------------------------------------- overflow

def test_verified_store_cap_sets_overflowed_and_counts(lst, monkeypatch):
    monkeypatch.setattr(L, "VERIFIED_CAP", 3)
    for i in range(1, 6):
        get(lst, "/" + tok(str(i)))
    assert lst.wait_for(lambda: lst.snapshot().verified_dropped >= 2, 5)
    snap = lst.snapshot()
    assert len(snap.verified_hits) == 3 and snap.verified_dropped == 2
    assert lst.health() == "overflowed"


def test_health_ok_initially(lst):
    assert lst.health() == "ok"


# ---------------------------------------------------------------- failure

def test_socket_closed_from_outside_sets_failed(lst):
    lst._sock.close()
    assert lst.health() == "failed"
    assert lst.wait_for(lambda: lst.health() == "failed", 5)


# --------------------------------------------------------------- bind

@pytest.mark.parametrize("bad", [None, "127.0.0.1", ("127.0.0.1", 0), object()])
def test_cannot_construct_without_validated_bind(bad):
    with pytest.raises(TypeError):
        L.Listener(bad, KEY, RUN)


def test_loopback_spec_binds_127_0_0_1(lst):
    assert lst.address[0] == "127.0.0.1" and lst.address[1] > 0


def test_bad_key_or_run_id_rejected():
    with pytest.raises(ValueError):
        L.Listener(spec(), "notbytes", RUN)
    with pytest.raises(ValueError):
        L.Listener(spec(), KEY, "NOT-HEX")
    with pytest.raises(ValueError):
        L.Listener(spec(), KEY, "")


# -------------------------------------------------------------- lifecycle

def _listener_threads():
    return [t for t in threading.enumerate() if t.name.startswith("dye-listener") and t.is_alive()]


def test_close_releases_port_and_joins_workers():
    a = L.Listener(spec(), KEY, RUN)
    host, port = a.start()
    silent = socket.create_connection((host, port), timeout=5)
    assert a.wait_for(lambda: a.snapshot().active_connections == 1, 5)
    a.close()
    silent.close()
    assert _listener_threads() == []
    b = L.Listener(validate_bind(host, port), KEY, RUN)
    try:
        assert b.start() == (host, port)
    finally:
        b.close()
    assert _listener_threads() == []


def test_context_manager_and_idempotent_close():
    with L.Listener(spec(), KEY, RUN) as lis:
        assert lis.address[1] > 0
        assert lis.health() == "ok"
    lis.close()
    assert _listener_threads() == []


def test_start_twice_is_an_error(lst):
    with pytest.raises(RuntimeError):
        lst.start()


def test_hits_for_returns_arrival_order_per_entry(lst):
    a1, b1, a2 = tok("1", nonce="aa01"), tok("2", nonce="bb01"), tok("1", nonce="aa02")
    for t in (a1, b1, a2):
        get(lst, "/" + t)
    assert [h.token for h in lst.hits_for("1")] == [a1, a2]
    assert [h.token for h in lst.hits_for("2")] == [b1]
    assert isinstance(lst.hits_for("1"), tuple)
    assert lst.hits_for("missing") == ()


def test_prefixed_malformed_head_sets_prefixed_count_anonymous_does_not(lst):
    raw(lst, ("GET /%s\r\nHost: x\r\n\r\n" % tok("1")).encode("latin-1"))
    assert lst.wait_for(lambda: lst.snapshot().malformed_closed >= 1, 5)
    assert lst.snapshot().prefixed_count == 1
    raw(lst, b"GET /favicon.ico\r\nHost: x\r\n\r\n")
    assert lst.wait_for(lambda: lst.snapshot().malformed_closed >= 2, 5)
    assert lst.snapshot().prefixed_count == 1


# ---------------------------------------------------------------- redirect hop

def _redirect_target(port):
    from dyetrace.egressnet import validate_advertised
    return validate_advertised("http://127.0.0.1:%d" % port, allow_local=True)


def test_redirect_hop_redirects_foreign_host_marks_second_hop():
    lis = L.Listener(spec(), KEY, RUN)
    lis.start()
    try:
        port = lis.address[1]
        red = _redirect_target(port)
        lis.close()
        lis = L.Listener(spec(port=port), KEY, RUN, redirect=red)
        lis.start()
        t = tok("1")
        authority = "127.0.0.1:%d" % port
        # Hop 0: Host is the advertised authority (bypass form), gets a 302.
        resp = raw(lis, ("GET /%s HTTP/1.1\r\nHost: [::ffff:7f00:1]:%d\r\n\r\n"
                         % (t, port)).encode("latin-1"))
        assert resp.startswith(b"HTTP/1.1 302")
        assert ("Location: http://%s/%s" % (authority, t)).encode() in resp
        # Hop 1: the followed request carries the redirect authority -> 200 + flag.
        resp2 = raw(lis, ("GET /%s HTTP/1.1\r\nHost: %s\r\n\r\n"
                          % (t, authority)).encode("latin-1"))
        assert resp2 == FIXED
        hits = lst_hits(lis)
        assert len(hits) == 2
        assert hits[0].via_redirect is False
        assert hits[1].via_redirect is True
        assert lis.snapshot().redirected_count == 1
    finally:
        lis.close()


def test_redirect_hop_absolute_form_not_redirected():
    lis = L.Listener(spec(), KEY, RUN)
    lis.start()
    try:
        port = lis.address[1]
        lis.close()
        lis = L.Listener(spec(port=port), KEY, RUN,
                         redirect=_redirect_target(port))
        lis.start()
        resp = raw(lis, ("GET http://other.example/%s HTTP/1.1\r\nHost: other\r\n\r\n"
                         % tok("1")).encode("latin-1"))
        assert resp == FIXED
        assert lis.snapshot().redirected_count == 0
    finally:
        lis.close()


def lst_hits(lis):
    return list(lis.snapshot().verified_hits)
