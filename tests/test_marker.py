"""Tests for the marker core (U2).

Covers happy path, edge cases, and adversarial negatives for tracer
building, HMAC binding, encoding variants, parsing, and verification.
"""

from dyetrace import marker


RUN = "a1b2c3"
ENTRY = "00ff10"
NONCE = "deadbeef"


def test_happy_fresh_tracer_verifies_and_fields_round_trip():
    key = marker.mint_key()
    token = marker.build_token(key, RUN, ENTRY, NONCE)

    assert marker.verify(token, key) is True

    parsed = marker.parse(token)
    assert parsed is not None
    assert parsed["run_id"] == RUN
    assert parsed["entry_id"] == ENTRY
    assert parsed["nonce"] == NONCE
    assert len(parsed["mac"]) == 64


def test_happy_variant_ids_round_trip():
    key = marker.mint_key()
    planted = marker.build_variants(key, RUN, ENTRY, NONCE)
    tags = [p["variant"] for p in planted]
    assert tags == ["raw", "html", "js", "attr"]


def test_edge_raw_only_suppresses_variants_but_keeps_hmac():
    key = marker.mint_key()
    planted = marker.build_variants(key, RUN, ENTRY, NONCE, raw_only=True)
    assert [p["variant"] for p in planted] == ["raw"]

    raw_payload = planted[0]["payload"]
    # The HMAC is still present and authenticates.
    assert marker.verify(raw_payload, key) is True
    parsed = marker.parse(raw_payload)
    assert parsed is not None and len(parsed["mac"]) == 64


def test_edge_each_variant_yields_recoverable_parseable_token():
    key = marker.mint_key()
    token = marker.build_token(key, RUN, ENTRY, NONCE)
    planted = marker.build_variants(key, RUN, ENTRY, NONCE)

    for p in planted:
        # The full canonical token is recoverable from every variant payload.
        recovered = marker.extract_token(p["payload"])
        assert recovered == token, p["variant"]
        # And the recovered token parses and verifies.
        assert marker.parse(recovered) is not None, p["variant"]
        assert marker.verify(recovered, key) is True, p["variant"]


def test_edge_variant_payloads_are_markup_breaking_and_inert():
    key = marker.mint_key()
    planted = {p["variant"]: p["payload"] for p in marker.build_variants(key, RUN, ENTRY, NONCE)}
    # Breaking sequences are present but inert (no live script element).
    assert planted["html"].startswith('"><dye')
    assert planted["attr"].startswith('" dye=')
    assert planted["js"].startswith("';dye=")
    for payload in planted.values():
        assert "<script" not in payload.lower()


def test_negative_flipped_mac_fails_verify():
    key = marker.mint_key()
    token = marker.build_token(key, RUN, ENTRY, NONCE)
    parsed = marker.parse(token)
    mac = parsed["mac"]
    # Flip one hex digit of the MAC.
    flipped = ("0" if mac[0] != "0" else "1") + mac[1:]
    forged = "DYE-" + RUN + "-" + ENTRY + "-" + NONCE + "-" + flipped
    assert marker.parse(forged) is not None  # still structurally valid
    assert marker.verify(forged, key) is False


def test_negative_different_run_key_fails_verify():
    key1 = marker.mint_key()
    key2 = marker.mint_key()
    assert key1 != key2
    token = marker.build_token(key1, RUN, ENTRY, NONCE)
    assert marker.verify(token, key1) is True
    assert marker.verify(token, key2) is False


def test_negative_dash_in_field_rejected_on_build():
    key = marker.mint_key()
    for bad in ("a1-b2", "A1B2", "xyz", "g0", ""):
        try:
            marker.build_token(key, bad, ENTRY, NONCE)
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError for run_id=%r" % bad)


def test_negative_dash_or_nonhex_field_rejected_on_parse():
    # A DYE-shaped string whose fields carry a dash or uppercase cannot parse
    # cleanly into the three fields.
    key = marker.mint_key()
    good_mac = marker.parse(marker.build_token(key, RUN, ENTRY, NONCE))["mac"]
    # Uppercase run_id is not lowercase hex.
    assert marker.parse("DYE-A1B2-" + ENTRY + "-" + NONCE + "-" + good_mac) is None
    # Non-hex char in entry_id.
    assert marker.parse("DYE-" + RUN + "-00zz-" + NONCE + "-" + good_mac) is None


def test_negative_truncated_mac_fails_precheck_without_crash():
    key = marker.mint_key()
    short = "DYE-" + RUN + "-" + ENTRY + "-" + NONCE + "-abcdef"
    assert marker.parse(short) is None
    # verify on a malformed candidate must not crash, returns False.
    assert marker.verify(short, key) is False


def test_negative_non_dye_and_garbage_return_none():
    assert marker.parse("") is None
    assert marker.parse("hello world") is None
    assert marker.parse("DYE-only") is None
    assert marker.extract_token("no tracer here") is None
