"""U5 bounded in-process listener (R4, R5, R7, KTD1, KTD3, KTD10, KTD12, KTD13).

The one module that opens, binds or listens on a socket (KTD13). It takes a
validated `egressnet.BindSpec`, the run key and the run id, and it cannot be
built from anything else. Each connection gets a head cap, a total head
deadline (a per-read timeout alone lets a drip-feed client hold a slot), a body
discard cap, and one of at most MAX_CONNECTIONS slots; an extra connection is
closed at once and counted. The reply is always the fixed empty 200 with
`Connection: close`: no redirect, no body, no reflection. A malformed or
oversize head is closed with no reply; it is counted, its offset recorded, and the raw head scanned for this run's prefix.

Evidence bar (KTD5): a verified hit is a request whose PATH (never the query or
a header) contains a token that passes `marker.verify` and whose parsed run_id
equals this run's. Everything else is noise, counted and sampled, so a noise
flood cannot evict a verified hit. Verified hits are stored in full up to
VERIFIED_CAP, at most PER_TOKEN_CAP arrivals per token (later ones are counted).

Interference counters (KTD12) carry arrival offsets (seconds since start, on the
monotonic clock) so a verdict can ask whether one fell inside a settle or drain
window: connections refused by the cap, head-deadline closes, and unattributed
arrivals (an unverified request carrying this run's `DYE-<run_id>` prefix in its
target, case-insensitively, or any unverified request arriving while a window
opened by `open_window` is open). Offset lists are capped at MAX_OFFSETS; the
counts stay exact and `offsets_truncated` says when a list was cut.

Health is `ok`, `failed` (accept loop died or the socket was lost) or
`overflowed` (verified store cap reached). Offsets are measured at accept time.
Replay caveat: a network observer of the tracer URL could replay it during the
run; there is no token-to-source binding in v1.
"""

import collections
import dataclasses
import re
import socket
import threading
import time

from dyetrace import marker
from dyetrace.egressnet import AdvertisedTarget, BindSpec, format_hostport

__all__ = [
    "HEAD_CAP",
    "HEAD_DEADLINE",
    "BODY_DISCARD_CAP",
    "MAX_CONNECTIONS",
    "VERIFIED_CAP",
    "PER_TOKEN_CAP",
    "NOISE_SAMPLE_CAP",
    "MAX_OFFSETS",
    "FIXED_REPLY",
    "Hit",
    "NoiseSample",
    "ListenerSnapshot",
    "Listener",
]

HEAD_CAP = 8 * 1024
HEAD_DEADLINE = 5.0
BODY_DISCARD_CAP = 16 * 1024
MAX_CONNECTIONS = 32
VERIFIED_CAP = 10_000
PER_TOKEN_CAP = 20
NOISE_SAMPLE_CAP = 100
MAX_OFFSETS = 10_000

_TARGET_CAP = 2048
_NOISE_TARGET_CAP = 200
_HEADER_VALUE_CAP = 256
_SELECTED_HEADERS = (
    "host",
    "user-agent",
    "referer",
    "x-forwarded-for",
    "x-forwarded-host",
    "forwarded",
    "content-length",
    "content-type",
)
_BACKLOG = 128
_POLL = 0.1

FIXED_REPLY = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

_REQUEST_LINE = re.compile(r"([A-Z]{1,16}) ([^\s]+) HTTP/1\.[01]")
_TOKEN_RE = re.compile(r"DYE-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+-[0-9a-f]{64}(?![0-9a-f])")
_HEX_RE = re.compile(r"[0-9a-f]+")


@dataclasses.dataclass(frozen=True)
class Hit:
    """One verified arrival (KTD10): the full record a verdict credits by token."""

    entry_id: str
    nonce: str
    token: str
    method: str
    target: str
    headers: tuple[tuple[str, str], ...]
    source: tuple
    wall: float
    offset: float
    arrival_index: int
    # True when the request's Host matches the configured redirect-hop
    # authority: the only way it could arrive is by following our 302.
    via_redirect: bool = False


@dataclasses.dataclass(frozen=True)
class NoiseSample:
    target: str
    source: tuple
    offset: float


@dataclasses.dataclass(frozen=True)
class ListenerSnapshot:
    verified_hits: tuple[Hit, ...]
    arrival_counts: dict
    verified_dropped: int
    noise_count: int
    noise_samples: tuple[NoiseSample, ...]
    refused_count: int
    refused_offsets: tuple[float, ...]
    deadline_close_count: int
    deadline_close_offsets: tuple[float, ...]
    unattributed_count: int
    unattributed_offsets: tuple[float, ...]
    offsets_truncated: bool
    oversize_closed: int
    malformed_closed: int
    peak_connections: int
    active_connections: int
    health: str
    # Appended with defaults: heads closed silently, with their arrival offsets,
    # and unverified arrivals or bad heads carrying this run's DYE-<run_id>
    # prefix (counted wherever they land, window or not).
    oversize_offsets: tuple[float, ...] = ()
    malformed_offsets: tuple[float, ...] = ()
    prefixed_count: int = 0
    # 302 replies issued under redirect-hop mode.
    redirected_count: int = 0


def _target_path(target):
    """The path part of a request target: no scheme/authority, no query."""
    if not target.startswith("/"):
        sep = target.find("://")
        if sep >= 0:
            slash = target.find("/", sep + 3)
            target = target[slash:] if slash >= 0 else ""
    for ch in "?#":
        i = target.find(ch)
        if i >= 0:
            target = target[:i]
    return target


class Listener:
    """The run-window listener. Use as a context manager or start()/close()."""

    def __init__(self, bind, key, run_id, redirect=None):
        if not isinstance(bind, BindSpec):
            raise TypeError("Listener requires a validated egressnet.BindSpec")
        if not isinstance(key, (bytes, bytearray)) or not key:
            raise ValueError("key must be non-empty bytes")
        if not isinstance(run_id, str) or not _HEX_RE.fullmatch(run_id):
            raise ValueError("run_id must be non-empty lowercase hex")
        if redirect is not None and not isinstance(redirect, AdvertisedTarget):
            raise TypeError("redirect must be a validated egressnet.AdvertisedTarget")
        self._bind = bind
        self._key = bytes(key)
        self._run_id = run_id
        # Redirect-hop mode: requests whose Host does not already name the
        # redirect authority get a 302 to redirect_base + request-target;
        # requests that do get the fixed 200, so one listener serves both hops.
        self._redirect_base = None
        self._redirect_authority = None
        if redirect is not None:
            authority = format_hostport(redirect.host, redirect.port)
            self._redirect_base = "http://" + authority
            self._redirect_authority = authority.lower()
        self._prefix = ("dye-" + run_id).lower()
        self._cond = threading.Condition()
        self._sock = None
        self._thread = None
        self._workers = set()
        self._conns = set()
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self._stopping = False
        self._started = False
        self._failed = False
        self._t0 = 0.0
        self.address = None
        self.closed = False
        self._windows = set()
        self._next_window = 0
        # state under self._cond
        self._hits = []
        self._hits_by_entry = collections.defaultdict(list)
        self._by_token = collections.defaultdict(int)
        self._stored_by_token = collections.defaultdict(int)
        self._entries = set()
        self._dropped = 0
        self._noise = 0
        self._samples = []
        self._refused = []
        self._refused_n = 0
        self._dl = []
        self._dl_n = 0
        self._unattr = []
        self._unattr_n = 0
        self._truncated = False
        self._oversize = 0
        self._malformed = 0
        self._oversize_off = []
        self._malformed_off = []
        self._prefixed = 0
        self._active = 0
        self._peak = 0
        self._overflowed = False
        self._redirected = 0

    # ---------------------------------------------------------- lifecycle

    def start(self):
        """Bind, listen and start accepting; return the actual (host, port)."""
        if self._started:
            raise RuntimeError("listener already started")
        self._started = True
        fam = socket.AF_INET6 if ":" in self._bind.host else socket.AF_INET
        sock = socket.socket(fam, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self._bind.host, self._bind.port))
            sock.listen(_BACKLOG)
            sock.settimeout(_POLL)
        except OSError:
            sock.close()
            raise
        self._sock = sock
        self._t0 = time.monotonic()
        self.address = sock.getsockname()[:2]
        self._thread = threading.Thread(
            target=self._accept_loop, name="dye-listener-accept", daemon=True
        )
        self._thread.start()
        return self.address

    def close(self):
        """Stop accepting, close live connections, join every thread. Idempotent."""
        with self._cond:
            self._stopping = True
            conns = list(self._conns)
        sock = self._sock
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        for c in conns:
            try:
                c.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(10)
        with self._cond:
            workers = list(self._workers)
        for w in workers:
            w.join(10)
        self.closed = True

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    # -------------------------------------------------------------- query

    def offset(self):
        """Seconds since start on the monotonic clock (the offsets' base)."""
        return time.monotonic() - self._t0

    def health(self):
        sock = self._sock
        lost = sock is None or sock.fileno() == -1
        with self._cond:
            if self._failed or (lost and not self._stopping):
                return "failed"
            if self._overflowed:
                return "overflowed"
        return "ok"

    def snapshot(self):
        h = self.health()
        with self._cond:
            return ListenerSnapshot(
                verified_hits=tuple(self._hits),
                arrival_counts=dict(self._by_token),
                verified_dropped=self._dropped,
                noise_count=self._noise,
                noise_samples=tuple(self._samples),
                refused_count=self._refused_n,
                refused_offsets=tuple(self._refused),
                deadline_close_count=self._dl_n,
                deadline_close_offsets=tuple(self._dl),
                unattributed_count=self._unattr_n,
                unattributed_offsets=tuple(self._unattr),
                offsets_truncated=self._truncated,
                oversize_closed=self._oversize,
                malformed_closed=self._malformed,
                peak_connections=self._peak,
                active_connections=self._active,
                health=h,
                oversize_offsets=tuple(self._oversize_off),
                malformed_offsets=tuple(self._malformed_off),
                prefixed_count=self._prefixed,
                redirected_count=self._redirected,
            )

    def wait_for(self, predicate, timeout):
        """Block (no polling) until predicate() is true or timeout; return its value.

        The predicate runs without the lock held, so it may call snapshot().
        Every state change notifies.
        """
        deadline = time.monotonic() + timeout
        while True:
            if predicate():
                return True
            left = deadline - time.monotonic()
            if left <= 0:
                return False
            with self._cond:
                self._cond.wait(min(left, _POLL))

    def wait_for_entry(self, entry_id, timeout):
        """Wait up to timeout for a stored verified hit for entry_id."""
        with self._cond:
            return self._cond.wait_for(lambda: entry_id in self._entries, timeout)

    def hits_for(self, entry_id):
        with self._cond:
            return tuple(self._hits_by_entry.get(entry_id, ()))

    def open_window(self):
        """Open a settle/drain window; unverified arrivals inside are unattributed."""
        with self._cond:
            self._next_window += 1
            self._windows.add(self._next_window)
            return self._next_window

    def close_window(self, handle):
        with self._cond:
            self._windows.discard(handle)

    # ------------------------------------------------------------ internals

    def _append_offset(self, lst, off):
        # caller holds the lock
        if len(lst) < MAX_OFFSETS:
            lst.append(off)
        else:
            self._truncated = True

    def _accept_loop(self):
        sock = self._sock
        try:
            while not self._stopping:
                try:
                    conn, peer = sock.accept()
                except socket.timeout:
                    continue
                except (OSError, ValueError):
                    break
                off = self.offset()
                with self._cond:
                    in_window = bool(self._windows)
                if not self._slots.acquire(blocking=False):
                    with self._cond:
                        self._refused_n += 1
                        self._append_offset(self._refused, off)
                        self._cond.notify_all()
                    self._quiet_close(conn)
                    continue
                t = threading.Thread(
                    target=self._handle,
                    args=(conn, peer, off, in_window),
                    name="dye-listener-conn",
                    daemon=True,
                )
                with self._cond:
                    self._active += 1
                    self._peak = max(self._peak, self._active)
                    self._conns.add(conn)
                    self._workers.add(t)
                    self._cond.notify_all()
                t.start()
        finally:
            with self._cond:
                if not self._stopping:
                    self._failed = True
                self._cond.notify_all()

    @staticmethod
    def _quiet_close(conn):
        try:
            conn.close()
        except OSError:
            pass

    def _handle(self, conn, peer, arrival, in_window):
        try:
            self._serve(conn, peer, arrival, in_window)
        except Exception:
            pass  # a bad connection must never take the accept loop down
        finally:
            self._quiet_close(conn)
            self._slots.release()
            with self._cond:
                self._active -= 1
                self._conns.discard(conn)
                self._workers.discard(threading.current_thread())
                self._cond.notify_all()

    def _read_head(self, conn, arrival):
        """Return a (head, extra) tuple, or None after counting/closing a bad connection."""
        deadline = time.monotonic() + HEAD_DEADLINE
        buf = b""
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                self._deadline_close(arrival)
                self._partial_head(buf, arrival)
                return None
            conn.settimeout(left)
            try:
                data = conn.recv(4096)
            except socket.timeout:
                self._deadline_close(arrival)
                self._partial_head(buf, arrival)
                return None
            except OSError:
                self._partial_head(buf, arrival)
                return None
            if not data:
                self._partial_head(buf, arrival)
                return None
            buf += data
            end = buf.find(b"\r\n\r\n")
            if end >= 0:
                if end + 4 > HEAD_CAP:
                    break
                return buf[: end + 4], buf[end + 4 :]
            if len(buf) > HEAD_CAP:
                break
        self._bad_head(buf, arrival, oversize=True)
        return None

    def _bad_head(self, raw, arrival, oversize):
        """Count a silently closed head as interference with its arrival offset,
        and scan the raw (bounded) head for this run's prefix."""
        tagged = self._prefix.encode("latin-1") in bytes(raw[: HEAD_CAP + 4096]).lower()
        with self._cond:
            if oversize:
                self._oversize += 1
                self._append_offset(self._oversize_off, arrival)
            else:
                self._malformed += 1
                self._append_offset(self._malformed_off, arrival)
            if tagged:
                self._prefixed += 1
            self._cond.notify_all()

    def _partial_head(self, buf, arrival):
        """A head that ended before the blank line is a silently closed head
        like any other; a connection that sent nothing stays uncounted."""
        if buf:
            self._bad_head(buf, arrival, oversize=False)

    def _deadline_close(self, arrival):
        with self._cond:
            self._dl_n += 1
            self._append_offset(self._dl, arrival)
            self._cond.notify_all()

    def _serve(self, conn, peer, arrival, in_window):
        got = self._read_head(conn, arrival)
        if got is None:
            return
        head, extra = got
        lines = head[:-4].decode("latin-1").split("\r\n")
        m = _REQUEST_LINE.fullmatch(lines[0])
        headers = {}
        ok = m is not None
        if ok:
            for ln in lines[1:]:
                name, sep, value = ln.partition(":")
                if not sep or not name or name != name.strip():
                    ok = False
                    break
                headers.setdefault(name.lower(), value.strip())
        if not ok:
            self._bad_head(head, arrival, oversize=False)
            return
        method, target = m.group(1), m.group(2)
        self._record(method, target, headers, peer, arrival, in_window)
        reply = FIXED_REPLY
        if self._redirect_base is not None and target.startswith("/"):
            host = headers.get("host", "").strip().lower()
            if host != self._redirect_authority:
                location = self._redirect_base + target
                reply = (
                    b"HTTP/1.1 302 Found\r\nLocation: "
                    + location.encode("latin-1")
                    + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                with self._cond:
                    self._redirected += 1
                    self._cond.notify_all()
        try:
            conn.settimeout(HEAD_DEADLINE)
            conn.sendall(reply)
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            return
        self._discard_body(conn, headers, len(extra))

    def _discard_body(self, conn, headers, already):
        try:
            declared = int(headers.get("content-length", "0"))
        except ValueError:
            return
        todo = min(max(declared, 0), BODY_DISCARD_CAP) - already
        deadline = time.monotonic() + HEAD_DEADLINE
        while todo > 0:
            left = deadline - time.monotonic()
            if left <= 0:
                return
            conn.settimeout(left)
            try:
                d = conn.recv(min(4096, todo))
            except OSError:
                return
            if not d:
                return
            todo -= len(d)

    def _find_hit(self, target):
        """Return (token, parsed) for the first verified in-run token in the path."""
        for m in _TOKEN_RE.finditer(_target_path(target)):
            cand = m.group(0)
            if not marker.verify(cand, self._key):
                continue
            parsed = marker.parse(cand)
            if parsed is not None and parsed["run_id"] == self._run_id:
                return cand, parsed
        return None

    def _record(self, method, target, headers, peer, arrival, in_window=False):
        found = self._find_hit(target)
        source = tuple(peer[:2])
        wall = time.time()
        sel = tuple(
            (k, headers[k][:_HEADER_VALUE_CAP]) for k in _SELECTED_HEADERS if k in headers
        )
        via = (
            self._redirect_authority is not None
            and headers.get("host", "").strip().lower() == self._redirect_authority
        )
        with self._cond:
            if found is not None:
                token, p = found
                self._by_token[token] += 1
                if self._stored_by_token[token] >= PER_TOKEN_CAP:
                    pass  # counted in arrival_counts, not stored
                elif len(self._hits) >= VERIFIED_CAP:
                    self._dropped += 1
                    self._overflowed = True
                else:
                    self._stored_by_token[token] += 1
                    hit = Hit(
                        entry_id=p["entry_id"],
                        nonce=p["nonce"],
                        token=token,
                        method=method,
                        target=target[:_TARGET_CAP],
                        headers=sel,
                        source=source,
                        wall=wall,
                        offset=arrival,
                        arrival_index=len(self._hits) + 1,
                        via_redirect=via,
                    )
                    self._hits.append(hit)
                    self._hits_by_entry[hit.entry_id].append(hit)
                    self._entries.add(p["entry_id"])
            else:
                self._noise += 1
                if len(self._samples) < NOISE_SAMPLE_CAP:
                    self._samples.append(
                        NoiseSample(target[:_NOISE_TARGET_CAP], source, arrival)
                    )
                # A window open when the connection was accepted or when its
                # request completed covers the arrival; the offset recorded is
                # one inside that window (accept time, else now), so a slow
                # head or a pre-opened connection cannot slip past the window
                # comparison at either edge.
                prefixed = self._prefix in target.lower()
                if prefixed:
                    self._prefixed += 1
                if prefixed or in_window or self._windows:
                    self._unattr_n += 1
                    self._append_offset(
                        self._unattr, arrival if in_window or not self._windows else self.offset())
            self._cond.notify_all()
