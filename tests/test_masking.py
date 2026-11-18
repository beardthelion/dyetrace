"""Tests for the shared masking module (R22, R27, KTD19).

The masking helpers were promoted out of ``session`` into their own named
module; these cover the module's public contract directly, and in particular
the new path-segment masking: a secret embedded in a URL path (a reset token, a
JWT, a capability id) must not reach a diagnostic or a report, while readable
endpoint segments and plain numeric ids stay legible so the report keeps its
value.
"""

from dyetrace.masking import MASK, is_sensitive_header, mask_headers, sanitize_url

_JWT = (
    "eyJhbGciOiJIUzI1NiJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ"
    ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)


# --- path-segment masking (R22) --------------------------------------------


def test_jwt_in_path_is_masked_but_shape_kept():
    out = sanitize_url(f"https://app.example.com/reset/{_JWT}")
    assert _JWT not in out
    assert out == f"https://app.example.com/reset/{MASK}"


def test_opaque_mixed_token_segment_is_masked():
    token = "a1b2c3d4e5f6a7b8c9d0e1f2"  # 24 chars, letters and digits
    out = sanitize_url(f"https://app.example.com/verify/{token}/done")
    assert token not in out
    assert out == f"https://app.example.com/verify/{MASK}/done"


def test_readable_path_segments_are_preserved():
    url = "https://app.example.com/users/profile/reset-password"
    assert sanitize_url(url) == url


def test_long_numeric_id_segment_is_preserved():
    # A plain numeric id is not a secret; keep it so the report stays readable.
    url = "https://app.example.com/orders/12345678901234567890"
    assert sanitize_url(url) == url


def test_dotted_filename_is_not_mistaken_for_a_jwt():
    url = "https://app.example.com/files/report.final.pdf"
    assert sanitize_url(url) == url


def test_query_fragment_and_userinfo_still_masked_alongside_path():
    out = sanitize_url(f"https://u:TOPSECRETPW@app.example.com/reset/{_JWT}?t=QS#F")
    assert "TOPSECRETPW" not in out  # userinfo stripped
    assert "QS" not in out           # query value masked
    assert "F" not in out.split("#")[-1] if "#" in out else True  # no live fragment
    assert _JWT not in out           # path secret masked
    assert "app.example.com" in out  # host preserved
    assert "t=" in out               # param name legible


def test_malformed_url_masks_whole():
    assert sanitize_url("http://[::1") == MASK


# --- header masking (public API) -------------------------------------------


def test_is_sensitive_header_matches_explicit_and_substring():
    assert is_sensitive_header("Cookie")
    assert is_sensitive_header("X-Api-Key")       # substring "key"
    assert is_sensitive_header("X-Session-Token")  # substring "token"/"session"
    assert not is_sensitive_header("Accept")


def test_mask_headers_masks_only_sensitive_values():
    masked = mask_headers([("Authorization", "Bearer X"), ("Accept", "text/html")])
    assert masked == [("Authorization", MASK), ("Accept", "text/html")]


def test_terminal_safe_strips_ansi_and_control_bytes():
    from dyetrace.masking import terminal_safe

    assert terminal_safe("a\x1b[31mred\x1b[0mb") == "aredb"
    assert terminal_safe("x\x00y\tz\n\x85w\x9f") == "xyzw"
    assert terminal_safe("plain text 123") == "plain text 123"


def test_mask_text_urls_and_lookalikes():
    from dyetrace.masking import mask_text

    assert mask_text("see http://u:pw@h/x done") == "see " + sanitize_url("http://u:pw@h/x") + " done"
    bare = "sk9Zq8Wx7Vc6Bn5Mm4Lk3Jh2Gf1Dd0Ss"
    for text in ("k=" + bare + "://x", "Bearer:" + bare + "://", "x," + bare + "://y/z"):
        assert bare not in mask_text(text)
    assert mask_text("plain words") == "plain words"


def test_sanitize_url_keeps_ipv6_brackets():
    assert sanitize_url("http://[2001:db8::1]:9000/p") == "http://[2001:db8::1]:9000/p"
    assert sanitize_url("http://[2001:db8::1]/p") == "http://[2001:db8::1]/p"


def test_sanitize_url_out_of_range_port_is_masked_not_raised():
    assert sanitize_url("https://host:99999/path") == MASK


def test_sanitize_url_ordinary_hosts_unchanged():
    assert sanitize_url("https://example.com:8443/a/b") == "https://example.com:8443/a/b"
    assert sanitize_url("http://example.com/a") == "http://example.com/a"
