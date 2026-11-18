"""U4 advertised URL validation and listener bind policy (R6, R7, KTD1, KTD3, KTD11).

A pure module: it uses no socket directly (KTD13; DNS goes through
`dyetrace.net`) and does string and `ipaddress` work otherwise. The resolver is injectable, so a hostname target is testable
with no real DNS, and `recheck_advertised` re-resolves a hostname adjacent to each call
(KTD11). `net._is_unsafe_address` is deliberately not the gate here (KTD3): it
forbids the private and loopback ranges an advertised URL may legitimately use
and misses 100.100.100.200 and 168.63.129.16.

Rules, in order, for an advertised URL: shape (http only; https is refused with
its own error because the listener has no TLS; no userinfo, fragment, query,
whitespace, control character, backslash or percent-encoding), host form (a
host is an IPv4 literal only as exactly four canonical decimal octets, any
other numeric-looking host is refused), embedded-IPv4 canonicalization (mapped,
compatible, NAT64, 6to4, ISATAP) before any range check, the always-refused
denylist (with or without opt-ins), then the local-address opt-in. The address
class (public, private or loopback; the least public across all resolved
addresses for a hostname) is computed and returned for the KILL gate (KTD5).

Bind policy: IP literals only, loopback by default, anything else (wildcard
included) needs the exposed-bind opt-in; port 0 is a test seam and never
combines with an advertised URL.
"""

import dataclasses
import ipaddress
import re
from collections.abc import Callable

from .net import default_resolver

__all__ = [
    "AdvertisedURLError",
    "MalformedURLError",
    "HttpsNotSupportedError",
    "MetadataAddressError",
    "LocalAddressError",
    "NonCanonicalHostError",
    "EmptyResolutionError",
    "BindError",
    "ExposedBindError",
    "HostnameBindError",
    "BindPortError",
    "AdvertisedTarget",
    "BindSpec",
    "validate_advertised",
    "recheck_advertised",
    "validate_bind",
    "parse_listen",
    "format_hostport",
]


class AdvertisedURLError(Exception):
    """Base class for every advertised-URL refusal (fail closed)."""


class MalformedURLError(AdvertisedURLError):
    """The URL shape is unacceptable (scheme, userinfo, query, port, ...)."""


class HttpsNotSupportedError(AdvertisedURLError):
    """An https advertised URL: the listener has no TLS, so refuse it (v1)."""


class MetadataAddressError(AdvertisedURLError):
    """The address is in an always-refused class (metadata, link-local, ...)."""


class LocalAddressError(AdvertisedURLError):
    """A loopback or private address was given without allow_local."""


class NonCanonicalHostError(AdvertisedURLError):
    """A numeric-looking host that is not four canonical decimal octets."""


class EmptyResolutionError(AdvertisedURLError):
    """A hostname resolved to no addresses."""


class BindError(Exception):
    """Base class for every listener bind refusal."""


class ExposedBindError(BindError):
    """A non-loopback bind without the exposed-bind opt-in."""


class HostnameBindError(BindError):
    """A bind host that is not an IP literal."""


class BindPortError(BindError):
    """A bind port out of range, or port 0 outside the test seam."""


_V4_NETS_DENY = tuple(
    ipaddress.ip_network(n)
    for n in (
        "169.254.0.0/16",
        "0.0.0.0/8",
        "192.0.0.0/24",
        "224.0.0.0/4",
        "100.100.100.200/32",
        "168.63.129.16/32",
        "255.255.255.255/32",
    )
)
_V6_NETS_DENY = tuple(
    ipaddress.ip_network(n)
    for n in (
        "fe80::/10",
        "fd00:ec2::254/128",
        "fd20:ce::254/128",
        "100::/64",
        "2001::/32",
        "64:ff9b:1::/48",
        "::/128",
        "ff00::/8",
    )
)
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_SIXTO4 = ipaddress.ip_network("2002::/16")

_OCTET = r"(?:0|[1-9][0-9]{0,2})"
_V4_RE = re.compile(rf"{_OCTET}(?:\.{_OCTET}){{3}}")
_LABEL_RE = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61})")
_RANK = {"public": 0, "private": 1, "loopback": 2}


@dataclasses.dataclass(frozen=True)
class AdvertisedTarget:
    """A validated advertised URL plus what the checks learned about it."""

    url: str
    host: str
    port: int | None
    base_path: str
    is_literal: bool
    addresses: tuple[str, ...]
    address_class: str
    allow_local: bool


@dataclasses.dataclass(frozen=True)
class BindSpec:
    host: str
    port: int
    exposed: bool


def _embedded_v4(addr: ipaddress.IPv6Address) -> list[ipaddress.IPv4Address]:
    """IPv4 addresses an IPv6 address embeds (mapped, compatible, NAT64, 6to4, ISATAP)."""
    out: list[ipaddress.IPv4Address] = []
    b = addr.packed
    if addr.ipv4_mapped is not None:
        out.append(addr.ipv4_mapped)
    if b[:12] == bytes(12) and int(addr) > 1:
        out.append(ipaddress.IPv4Address(b[12:]))
    if addr in _NAT64:
        out.append(ipaddress.IPv4Address(b[12:]))
    if addr in _SIXTO4:
        out.append(ipaddress.IPv4Address(b[2:6]))
    if b[:8] == bytes(8) and b[8:12] == b"\xff\xff\x00\x00":
        # SIIT-translated (::ffff:0:a.b.c.d)
        out.append(ipaddress.IPv4Address(b[12:]))
    # ISATAP interface id: 5efe in bytes 10-12; the u and g bits of byte 8
    # may be set, so mask them before the zero check.
    if (b[8] & ~0x03) == 0 and b[9] == 0 and b[10:12] == b"\x5e\xfe":
        out.append(ipaddress.IPv4Address(b[12:]))
    return out


def _class_of(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if ip.is_loopback:
        return "loopback"
    return "public" if ip.is_global else "private"


def _check_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Refuse a metadata-class address; return its class (embedded IPv4 wins)."""
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = _embedded_v4(ip)
        for v4 in embedded:
            _check_ip(v4)
        if any(ip in n for n in _V6_NETS_DENY):
            raise MetadataAddressError(f"always-refused address class: {ip}")
        if embedded:
            return max((_class_of(v) for v in embedded), key=_RANK.__getitem__)
    elif any(ip in n for n in _V4_NETS_DENY):
        raise MetadataAddressError(f"always-refused address class: {ip}")
    return _class_of(ip)


def _require_local_ok(cls: str, allow_local: bool) -> None:
    if cls != "public" and not allow_local:
        raise LocalAddressError(f"{cls} address needs allow_local")


def _check_addresses(
    addrs: list[str], allow_local: bool
) -> tuple[tuple[str, ...], str]:
    if not addrs:
        raise EmptyResolutionError("hostname resolved to no addresses")
    classes = []
    for a in addrs:
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            raise MalformedURLError(f"unparseable resolved address: {a!r}") from None
        classes.append(_check_ip(ip))
    cls = max(classes, key=_RANK.__getitem__)
    _require_local_ok(cls, allow_local)
    return tuple(addrs), cls


def validate_advertised(
    url: str,
    *,
    allow_local: bool = False,
    resolver: Callable[[str], list[str]] | None = None,
) -> AdvertisedTarget:
    """Validate an advertised URL (KTD3); raise a typed AdvertisedURLError."""
    if not isinstance(url, str) or not url:
        raise MalformedURLError("empty URL")
    for ch in url:
        if ord(ch) <= 0x20 or ord(ch) >= 0x7F or ch in "\\?#":
            raise MalformedURLError(f"forbidden character in URL: {ch!r}")
    scheme, sep, rest = url.partition("://")
    if not sep:
        raise MalformedURLError("missing scheme")
    scheme = scheme.lower()
    if scheme == "https":
        raise HttpsNotSupportedError("https is not supported in v1 (listener has no TLS)")
    if scheme != "http":
        raise MalformedURLError(f"unsupported scheme: {scheme!r}")
    slash = rest.find("/")
    authority, path = (rest, "") if slash < 0 else (rest[:slash], rest[slash:])
    if "%" in authority:
        raise MalformedURLError("percent-encoding or zone id in host")
    if "@" in authority:
        raise MalformedURLError("userinfo is not allowed")
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            raise MalformedURLError("unterminated IPv6 bracket")
        host, tail, bracketed = authority[1:end], authority[end + 1 :], True
        if tail and not tail.startswith(":"):
            raise MalformedURLError("junk after IPv6 bracket")
        port_text = tail[1:] if tail else None
    else:
        if authority.count(":") > 1:
            raise MalformedURLError("unbracketed IPv6 host")
        host, _, ptxt = authority.partition(":")
        bracketed, port_text = False, (ptxt if ":" in authority else None)
    if not host:
        raise MalformedURLError("empty host")
    port: int | None = None
    if port_text is not None:
        if not (port_text.isascii() and port_text.isdigit()):
            raise MalformedURLError(f"bad port: {port_text!r}")
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise MalformedURLError(f"port out of range: {port}")
    base_path = path.rstrip("/")

    def make(addrs: tuple[str, ...], cls: str, literal: bool, h: str) -> AdvertisedTarget:
        return AdvertisedTarget(url, h, port, base_path, literal, addrs, cls, allow_local)

    if bracketed:
        try:
            ip6 = ipaddress.IPv6Address(host)
        except ValueError:
            raise MalformedURLError(f"bad IPv6 literal: {host!r}") from None
        cls = _check_ip(ip6)
        _require_local_ok(cls, allow_local)
        return make((str(ip6),), cls, True, str(ip6))

    host = host.lower()
    if _V4_RE.fullmatch(host) and all(int(o) <= 255 for o in host.split(".")):
        ip4 = ipaddress.IPv4Address(host)
        cls = _check_ip(ip4)
        _require_local_ok(cls, allow_local)
        return make((host,), cls, True, host)
    last = host.rsplit(".", 1)[-1]
    if (last.isascii() and last.isdigit()) or last.startswith("0x"):
        raise NonCanonicalHostError(f"non-canonical numeric host: {host!r}")
    if len(host) > 253 or not all(_LABEL_RE.fullmatch(lb) for lb in host.split(".")):
        raise MalformedURLError(f"bad hostname: {host!r}")
    addrs, cls = _check_addresses((resolver or default_resolver)(host), allow_local)
    return make(addrs, cls, False, host)


def recheck_advertised(
    target: AdvertisedTarget,
    *,
    resolver: Callable[[str], list[str]] | None = None,
) -> AdvertisedTarget:
    """Re-resolve a hostname target and re-apply every check (KTD11).

    A no-op for IP literals. Raises the same typed errors as validation.
    """
    if target.is_literal:
        return target
    addrs, cls = _check_addresses(
        (resolver or default_resolver)(target.host), target.allow_local
    )
    return dataclasses.replace(target, addresses=addrs, address_class=cls)


def validate_bind(
    host: str,
    port: int,
    *,
    allow_exposed: bool = False,
    allow_port_zero: bool = False,
    advertised: bool = False,
) -> BindSpec:
    """Validate a listener bind (KTD1). `allow_port_zero` is the test seam."""
    if not isinstance(host, str) or "%" in host:
        raise HostnameBindError(f"bind host must be an IP literal: {host!r}")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise HostnameBindError(f"bind host must be an IP literal: {host!r}") from None
    if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
        raise BindPortError(f"bind port out of range: {port!r}")
    if port == 0:
        if not allow_port_zero:
            raise BindPortError("port 0 is allowed only through the test seam")
        if advertised:
            raise BindPortError("port 0 cannot be combined with an advertised URL")
    exposed = not ip.is_loopback
    if exposed and not allow_exposed:
        raise ExposedBindError(f"non-loopback bind {host} needs allow_exposed")
    return BindSpec(str(ip), port, exposed)


def parse_listen(text: str) -> tuple[str, int]:
    """Split a HOST:PORT (or [V6]:PORT) listen string; raise BindError if malformed."""
    if not isinstance(text, str):
        raise BindError("listen must be HOST:PORT")
    if text.startswith("["):
        end = text.find("]")
        if end < 0 or text[end + 1 : end + 2] != ":":
            raise BindError(f"listen must be [HOST]:PORT: {text!r}")
        host, ptxt = text[1:end], text[end + 2 :]
    else:
        if text.count(":") != 1:
            raise BindError(f"listen must be HOST:PORT: {text!r}")
        host, _, ptxt = text.partition(":")
    if not host or not (ptxt.isascii() and ptxt.isdigit()):
        raise BindError(f"listen must be HOST:PORT: {text!r}")
    return host, int(ptxt)


def format_hostport(host, port):
    """Render HOST:PORT, bracketing an IPv6 host; None host gives None, a None
    port gives the bare (bracketed if IPv6) host."""
    if host is None:
        return None
    h = "[%s]" % host if ":" in str(host) else str(host)
    return "%s:%s" % (h, port) if port is not None else h
