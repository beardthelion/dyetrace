"""Tests for U4 advertised URL validation and bind policy (KTD1, KTD3, KTD11).

Test-first: written before src/dyetrace/egressnet.py exists, so the import
fails RED until the module is implemented. Pure: no socket, no real DNS; the
resolver is injected. The matrix includes every refused row with every opt-in
set, because a happy-path pass cannot show the denylist is load-bearing.
"""

import pytest

from dyetrace.egressnet import (
    AdvertisedURLError,
    BindError,
    BindPortError,
    EmptyResolutionError,
    ExposedBindError,
    HostnameBindError,
    HttpsNotSupportedError,
    LocalAddressError,
    MalformedURLError,
    MetadataAddressError,
    NonCanonicalHostError,
    parse_listen,
    recheck_advertised,
    validate_advertised,
    validate_bind,
)


def _no_dns(host):
    raise AssertionError(f"resolver must not be called for {host!r}")


def _res(*addrs):
    return lambda host: list(addrs)


PUBLIC_OK = [
    "http://93.184.216.34:8080/",
    "http://[2606:4700:4700::1111]:8080/",
    "http://93.184.216.34:8080/dye/base",
]


@pytest.mark.parametrize("url", PUBLIC_OK)
def test_public_literals_validate(url):
    t = validate_advertised(url, resolver=_no_dns)
    assert t.address_class == "public"
    assert t.port == 8080


def test_base_path_preserved_and_bracketed_ipv6_parsed():
    t = validate_advertised("http://93.184.216.34:8080/dye/base", resolver=_no_dns)
    assert t.base_path == "/dye/base"
    t6 = validate_advertised("http://[2606:4700:4700::1111]:8080/", resolver=_no_dns)
    assert t6.host == "2606:4700:4700::1111"


def test_public_hostname_with_stub_resolver():
    t = validate_advertised(
        "http://canary.example.com:8080/", resolver=_res("93.184.216.34")
    )
    assert t.address_class == "public"
    assert t.addresses == ("93.184.216.34",)
    assert t.is_literal is False


LOCAL = [
    ("http://127.0.0.1:8080/", "loopback"),
    ("http://10.0.0.5:8080/", "private"),
    ("http://192.168.1.5:8080/", "private"),
    ("http://[::1]:8080/", "loopback"),
    ("http://[fc00::1]:8080/", "private"),
    ("http://100.64.0.5:8080/", "private"),
]


@pytest.mark.parametrize("url,cls", LOCAL)
def test_local_refused_without_opt_in_accepted_with(url, cls):
    with pytest.raises(LocalAddressError):
        validate_advertised(url, resolver=_no_dns)
    t = validate_advertised(url, allow_local=True, resolver=_no_dns)
    assert t.address_class == cls


METADATA = [
    "http://169.254.169.254:8080/",
    "http://169.254.0.1:8080/",
    "http://[fd00:ec2::254]:8080/",
    "http://100.100.100.200:8080/",
    "http://168.63.129.16:8080/",
    "http://[fe80::1]:8080/",
    "http://0.0.0.0:8080/",
    "http://[::]:8080/",
    "http://224.0.0.1:8080/",
    "http://255.255.255.255:8080/",
]

EXTRA = [
    "http://192.0.0.192:8080/",
    "http://0.1.2.3:8080/",
    "http://[2001:0:4136:e378:8000:63bf:3fff:fdd2]:8080/",
    "http://[64:ff9b:1::a9fe:a9fe]:8080/",
    "http://[fe80::1%eth0]:8080/",
    "http://[fe80::1%25eth0]:8080/",
    "http://[fe80::5efe:169.254.169.254]:8080/",
    "http://[2001:db8::5efe:a9fe:a9fe]:8080/",
    "http://[2001:db8::200:5efe:a9fe:a9fe]:8080/",
    "http://[fd20:ce::254]:8080/",
    "http://[100::1]:8080/",
]

CANON = [
    "http://[::ffff:169.254.169.254]:8080/",
    "http://[::169.254.169.254]:8080/",
    "http://[64:ff9b::a9fe:a9fe]:8080/",
    "http://[2002:a9fe:a9fe::]:8080/",
    "http://[::ffff:0:a9fe:a9fe]:8080/",
    "http://[2001:db8::100:5efe:a9fe:a9fe]:8080/",
    "http://[2001:db8::300:5efe:a9fe:a9fe]:8080/",
]


@pytest.mark.parametrize("url", METADATA + EXTRA + CANON)
@pytest.mark.parametrize("allow_local", [False, True])
def test_always_refused_with_every_opt_in(url, allow_local):
    with pytest.raises(AdvertisedURLError) as ei:
        validate_advertised(url, allow_local=allow_local, resolver=_no_dns)
    assert not isinstance(ei.value, LocalAddressError)


@pytest.mark.parametrize("url", METADATA + CANON)
def test_metadata_class_error_type(url):
    if "fe80::1%" in url:
        return
    with pytest.raises(MetadataAddressError):
        validate_advertised(url, allow_local=True, resolver=_no_dns)


@pytest.mark.parametrize(
    "url",
    [
        "http://2852039166:8080/",
        "http://0xa9fea9fe:8080/",
        "http://0251.0376.0251.0376:8080/",
        "http://169.254.43518:8080/",
        "http://1.2.3.4.5:8080/",
        "http://999.1.1.1:8080/",
        "http://0X7f.1:8080/",
    ],
)
def test_non_canonical_numeric_hosts_refused(url):
    with pytest.raises(NonCanonicalHostError):
        validate_advertised(url, allow_local=True, resolver=_no_dns)


@pytest.mark.parametrize(
    "url",
    [
        "http://user@93.184.216.34:8080/",
        "http://user:pw@93.184.216.34:8080/",
        "http://93.184.216.34:8080/#frag",
        "http://93.184.216.34:8080/?q=1",
        "http://93.184.216.34:8080/a b",
        " http://93.184.216.34:8080/",
        "http://93.184.216.34:8080/\n",
        "http://93.184.216.34:8080/\x00",
        "http://93.184.216.34:8080/\x7f",
        "http://93.184.216.34:8080\\@evil/",
        "http://93.184.216.34:8080/a\\b",
        "http://%31%32%37.0.0.1:8080/",
        "file:///etc/passwd",
        "ftp://93.184.216.34:8080/",
        "gopher://93.184.216.34:8080/",
        "http://:8080/",
        "http:///x",
        "http://93.184.216.34:0/",
        "http://93.184.216.34:70000/",
        "http://93.184.216.34:abc/",
        "http://[2606:4700:4700::1111/",
        "http://2606:4700:4700::1111:8080/",
        "",
        "93.184.216.34:8080",
    ],
)
def test_shape_refused(url):
    with pytest.raises(MalformedURLError):
        validate_advertised(url, allow_local=True, resolver=_res("93.184.216.34"))


def test_https_refused_with_distinct_error():
    with pytest.raises(HttpsNotSupportedError) as ei:
        validate_advertised("https://93.184.216.34:8080/", resolver=_no_dns)
    assert not isinstance(ei.value, MalformedURLError)
    assert isinstance(ei.value, AdvertisedURLError)


def test_hostname_with_one_safe_one_metadata_refused():
    r = _res("93.184.216.34", "169.254.169.254")
    with pytest.raises(MetadataAddressError):
        validate_advertised("http://h.example.com:80/", allow_local=True, resolver=r)


def test_hostname_empty_resolution_refused():
    with pytest.raises(EmptyResolutionError):
        validate_advertised("http://h.example.com:80/", resolver=_res())


def test_hostname_least_public_class_wins():
    r = _res("93.184.216.34", "10.0.0.5")
    with pytest.raises(LocalAddressError):
        validate_advertised("http://h.example.com:80/", resolver=r)
    t = validate_advertised("http://h.example.com:80/", allow_local=True, resolver=r)
    assert t.address_class == "private"
    r2 = _res("10.0.0.5", "127.0.0.1")
    t2 = validate_advertised("http://h.example.com:80/", allow_local=True, resolver=r2)
    assert t2.address_class == "loopback"


def test_hostname_resolving_to_embedded_metadata_refused():
    r = _res("::ffff:169.254.169.254")
    with pytest.raises(MetadataAddressError):
        validate_advertised("http://h.example.com:80/", allow_local=True, resolver=r)


def test_hostname_resolving_to_garbage_refused():
    with pytest.raises(AdvertisedURLError):
        validate_advertised(
            "http://h.example.com:80/", allow_local=True, resolver=_res("not-an-ip")
        )


def test_recheck_refuses_when_second_resolution_turns_metadata():
    answers = iter([["93.184.216.34"], ["93.184.216.34"], ["169.254.169.254"]])
    r = lambda host: next(answers)  # noqa: E731
    t = validate_advertised("http://h.example.com:80/", resolver=r)
    assert recheck_advertised(t, resolver=r).address_class == "public"
    with pytest.raises(MetadataAddressError):
        recheck_advertised(t, resolver=r)


def test_recheck_is_noop_for_ip_literals():
    t = validate_advertised("http://93.184.216.34:80/", resolver=_no_dns)
    assert recheck_advertised(t, resolver=_no_dns) == t


def test_recheck_reapplies_local_opt_in():
    answers = iter([["93.184.216.34"], ["10.0.0.5"]])
    r = lambda host: next(answers)  # noqa: E731
    t = validate_advertised("http://h.example.com:80/", resolver=r)
    with pytest.raises(LocalAddressError):
        recheck_advertised(t, resolver=r)


def test_module_has_no_socket_import():
    import ast
    import dyetrace.egressnet as m

    tree = ast.parse(open(m.__file__, encoding="utf-8").read())
    bad = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            bad += [a.name for a in node.names if a.name.split(".")[0] in ("socket", "_socket", "socketserver", "ssl")]
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            if (node.module or "").split(".")[0] in ("socket", "_socket", "socketserver", "ssl"):
                bad.append(node.module)
    assert not bad


# Bind policy.


def test_default_bind_ok():
    b = validate_bind("127.0.0.1", 8080)
    assert (b.host, b.port, b.exposed) == ("127.0.0.1", 8080, False)
    assert validate_bind("::1", 8080).exposed is False


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "10.0.0.5"])
def test_exposed_bind_needs_flag(host):
    with pytest.raises(ExposedBindError):
        validate_bind(host, 8080)
    assert validate_bind(host, 8080, allow_exposed=True).exposed is True


@pytest.mark.parametrize("host", ["localhost", "example.com", "", "0x7f.1", "127.1"])
def test_hostname_bind_refused_even_with_flag(host):
    with pytest.raises(HostnameBindError):
        validate_bind(host, 8080, allow_exposed=True)


def test_bind_zone_id_refused():
    with pytest.raises(HostnameBindError):
        validate_bind("fe80::1%eth0", 8080, allow_exposed=True)


def test_port_zero_only_through_test_seam_and_never_with_advertise():
    with pytest.raises(BindPortError):
        validate_bind("127.0.0.1", 0)
    assert validate_bind("127.0.0.1", 0, allow_port_zero=True).port == 0
    with pytest.raises(BindPortError):
        validate_bind("127.0.0.1", 0, allow_port_zero=True, advertised=True)
    with pytest.raises(BindPortError):
        validate_bind("127.0.0.1", 0, advertised=True)


@pytest.mark.parametrize("port", [-1, 65536, 70000])
def test_bind_port_out_of_range(port):
    with pytest.raises(BindPortError):
        validate_bind("127.0.0.1", port, allow_port_zero=True)


def test_bind_errors_share_base():
    assert issubclass(ExposedBindError, BindError)
    assert issubclass(HostnameBindError, BindError)
    assert issubclass(BindPortError, BindError)


def test_parse_listen():
    assert parse_listen("127.0.0.1:0") == ("127.0.0.1", 0)
    assert parse_listen("[::1]:9000") == ("::1", 9000)
    assert parse_listen("0.0.0.0:80") == ("0.0.0.0", 80)
    for bad in ["127.0.0.1", "host", ":80", "[::1]", "1.2.3.4:x", "::1:80"]:
        with pytest.raises(BindError):
            parse_listen(bad)


def test_format_hostport_brackets_ipv6_and_tolerates_missing_port():
    from dyetrace.egressnet import format_hostport
    assert format_hostport("1.2.3.4", 80) == "1.2.3.4:80"
    assert format_hostport("2001:db8::1", 80) == "[2001:db8::1]:80"
    assert format_hostport("example.com", None) == "example.com"
    assert format_hostport("::1", None) == "[::1]"
    assert format_hostport(None, 80) is None
