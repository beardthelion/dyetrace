"""Tests for the U4 injection walkers and plant.

Test-first: these are written before src/dyetrace/plant.py exists, so the import
fails RED until plant is implemented.

House rules exercised here: one planted descriptor per injection site per enabled
variant (four by default, one in raw-only), stable structural path ids that do
not shift with leaf values, exact single decode / single encode re-serialization,
multipart ownership handed to the sender (recorded multipart Content-Type
dropped, per-part filename and content type preserved, filenames are sites), and
the mutating-method dry-run gate (a recorded POST is skipped, not fired, without
the confirm flag).
"""

from urllib.parse import parse_qsl, urlsplit

import pytest

from dyetrace import marker
from dyetrace.session import Body, MultipartPart, RecordedRequest, Session
from dyetrace.plant import (
    Attribution,
    MultipartBody,
    PlantResult,
    PlantedRequest,
    RawBody,
    SkippedRequest,
    plant,
)

RUN_ID = "abcd1234"


def _key_and_run():
    return marker.mint_key(), RUN_ID


def _session(requests):
    return Session(
        version="1",
        cookies={},
        auth_headers={},
        base_url="https://app.example.com",
        allowlist_host="app.example.com",
        recorded_requests=requests,
    )


def _json_req(data_bytes, method="GET", url="https://app.example.com/"):
    return RecordedRequest(
        method=method,
        url=url,
        headers=[("Content-Type", "application/json")],
        body=Body(content_type="application/json", data=data_bytes),
    )


def _planted_value(pr):
    """Pull the injected variant payload back out of a planted descriptor's body
    for a JSON leaf, so we can authenticate the embedded token."""
    import json

    obj = json.loads(pr.body.data.decode("utf-8"))
    # Resolve the json path id back to the leaf value.
    assert pr.path_id.startswith("json:$")
    return obj, pr


# --- Happy: three JSON leaves yield twelve descriptors ---------------------


def test_json_three_leaves_twelve_descriptors_by_default():
    key, run_id = _key_and_run()
    body = b'{"a":"1","b":{"c":"2"},"d":["3"]}'
    res = plant(_session([_json_req(body)]), key, run_id)

    assert isinstance(res, PlantResult)
    assert len(res.planted) == 12  # 3 sites x 4 variants
    assert res.skipped == []

    sites = {pr.path_id for pr in res.planted}
    assert sites == {"json:$.a", "json:$.b.c", "json:$.d[0]"}

    # Each site carries exactly the four variants, once each.
    for site in sites:
        variants = sorted(pr.variant for pr in res.planted if pr.path_id == site)
        assert variants == sorted(marker.VARIANTS)

    # Every descriptor is tagged and attributed in the mapping (R7, R19).
    for pr in res.planted:
        assert isinstance(pr, PlantedRequest)
        assert pr.variant in marker.VARIANTS
        attr = res.mapping[(pr.entry_id, pr.variant)]
        assert isinstance(attr, Attribution)
        assert attr.source_index == 0
        assert attr.path_id == pr.path_id


def test_raw_only_yields_one_per_site():
    key, run_id = _key_and_run()
    body = b'{"a":"1","b":{"c":"2"},"d":["3"]}'
    res = plant(_session([_json_req(body)]), key, run_id, raw_only=True)

    assert len(res.planted) == 3
    assert all(pr.variant == "raw" for pr in res.planted)
    assert {pr.path_id for pr in res.planted} == {
        "json:$.a",
        "json:$.b.c",
        "json:$.d[0]",
    }


def test_injected_token_authenticates_and_entry_id_round_trips():
    key, run_id = _key_and_run()
    body = b'{"a":"orig"}'
    res = plant(_session([_json_req(body)]), key, run_id, raw_only=True)

    (pr,) = res.planted
    assert pr.body.__class__ is RawBody
    import json

    obj = json.loads(pr.body.data.decode("utf-8"))
    payload = obj["a"]
    token = marker.extract_token(payload)
    assert token is not None
    assert marker.verify(token, key) is True
    parsed = marker.parse(token)
    assert parsed["run_id"] == run_id
    assert parsed["entry_id"] == pr.entry_id
    # Original value recorded for the site.
    assert pr.original_value == "orig"


def test_only_the_targeted_leaf_changes():
    key, run_id = _key_and_run()
    body = b'{"a":"1","b":"2"}'
    res = plant(_session([_json_req(body)]), key, run_id, raw_only=True)
    import json

    for pr in res.planted:
        obj = json.loads(pr.body.data.decode("utf-8"))
        if pr.path_id == "json:$.a":
            assert obj["b"] == "2"  # untouched
            assert obj["a"] != "1"
        else:
            assert obj["a"] == "1"
            assert obj["b"] != "2"


# --- Edge: query preserves order and duplicate keys ------------------------


def test_query_preserves_duplicate_keys_and_order():
    key, run_id = _key_and_run()
    req = RecordedRequest(
        method="GET",
        url="https://app.example.com/?a=1&a=2",
        headers=[],
        body=None,
    )
    res = plant(_session([req]), key, run_id, raw_only=True)

    assert {pr.path_id for pr in res.planted} == {"query:a[0]", "query:a[1]"}

    first = next(pr for pr in res.planted if pr.path_id == "query:a[0]")
    pairs = parse_qsl(urlsplit(first.url).query, keep_blank_values=True)
    assert [k for k, _ in pairs] == ["a", "a"]
    assert pairs[0][0] == "a" and pairs[1] == ("a", "2")
    assert pairs[0][1] != "1"  # first occurrence got the tracer

    second = next(pr for pr in res.planted if pr.path_id == "query:a[1]")
    pairs2 = parse_qsl(urlsplit(second.url).query, keep_blank_values=True)
    assert pairs2[0] == ("a", "1")
    assert pairs2[1][0] == "a" and pairs2[1][1] != "2"


def test_query_single_encode_round_trips_special_chars():
    key, run_id = _key_and_run()
    req = RecordedRequest(
        method="GET",
        url="https://app.example.com/?q=hi",
        headers=[],
        body=None,
    )
    res = plant(_session([req]), key, run_id)  # all variants, incl. attr with quotes
    attr = next(pr for pr in res.planted if pr.variant == "attr")
    pairs = parse_qsl(urlsplit(attr.url).query, keep_blank_values=True)
    assert len(pairs) == 1
    k, v = pairs[0]
    assert k == "q"
    # Single decode gives back exactly the planted payload (double-encoding would
    # corrupt the quotes / spaces in the attr variant).
    assert marker.extract_token(v) is not None
    assert marker.verify(marker.extract_token(v), key)


# --- Edge: path segment substituted and re-quoted within its own segment ---


def test_path_segment_substituted_slashes_survive():
    key, run_id = _key_and_run()
    req = RecordedRequest(
        method="GET",
        url="https://app.example.com/users/12-34/profile",
        headers=[],
        body=None,
    )
    res = plant(_session([req]), key, run_id, raw_only=True)

    ids = {pr.path_id for pr in res.planted}
    # three non-empty segments, each a site
    assert "path:/users/{seg2}/profile" in ids
    assert "path:/{seg1}/12-34/profile" in ids
    assert "path:/users/12-34/{seg3}" in ids

    mid = next(pr for pr in res.planted if pr.path_id == "path:/users/{seg2}/profile")
    split = urlsplit(mid.url)
    segs = split.path.split("/")
    # structure preserved: empty, users, <tracer>, profile
    assert len(segs) == 4
    assert segs[0] == "" and segs[1] == "users" and segs[3] == "profile"
    assert segs[2] not in ("", "12-34")
    # the tracer lives entirely inside its own segment: no stray slash leaked out
    assert mid.url.count("/users/") == 1
    assert mid.url.endswith("/profile")
    assert mid.original_value == "12-34"


# --- Edge: multipart plants into value and filename ------------------------


def _multipart_session():
    parts = [
        MultipartPart(
            name="caption", filename=None, content_type="text/plain", data=b"hi"
        ),
        MultipartPart(
            name="file", filename="a.png", content_type="image/png", data=b"PNGDATA"
        ),
    ]
    req = RecordedRequest(
        method="POST",
        url="https://app.example.com/",
        headers=[("Content-Type", "multipart/form-data; boundary=xyz")],
        body=Body(
            content_type="multipart/form-data; boundary=xyz",
            data=None,
            parts=parts,
        ),
    )
    return _session([req])


def test_multipart_sites_value_and_filename():
    key, run_id = _key_and_run()
    res = plant(_multipart_session(), key, run_id, raw_only=True, confirm_mutating=True)

    ids = {pr.path_id for pr in res.planted}
    assert ids == {
        "multipart:caption.value",
        "multipart:file.value",
        "multipart:file.filename",
    }
    for pr in res.planted:
        assert isinstance(pr.body, MultipartBody)
        # recorded multipart Content-Type header is dropped (httpx owns boundary)
        assert all(name.lower() != "content-type" for name, _ in pr.headers)


def test_multipart_filename_injection_preserves_other_parts():
    key, run_id = _key_and_run()
    res = plant(_multipart_session(), key, run_id, raw_only=True, confirm_mutating=True)

    fn = next(pr for pr in res.planted if pr.path_id == "multipart:file.filename")
    # caption stays a text field with its original value
    assert ("caption", "hi") in fn.body.data_fields
    # the file part keeps its bytes and content type; only the filename changed
    (name, (filename, content, ctype)) = fn.body.file_parts[0]
    assert name == "file"
    assert content == b"PNGDATA"
    assert ctype == "image/png"
    assert filename not in ("a.png", None)
    assert marker.extract_token(filename) is not None
    assert fn.original_value == "a.png"


def test_multipart_value_injection_keeps_filename_and_type():
    key, run_id = _key_and_run()
    res = plant(_multipart_session(), key, run_id, raw_only=True, confirm_mutating=True)

    val = next(pr for pr in res.planted if pr.path_id == "multipart:file.value")
    (name, (filename, content, ctype)) = val.body.file_parts[0]
    assert name == "file"
    assert filename == "a.png"
    assert ctype == "image/png"
    assert content != b"PNGDATA"
    assert marker.extract_token(content.decode("utf-8")) is not None
    # the caption text field is preserved untouched
    assert ("caption", "hi") in val.body.data_fields


# --- Negative: mutating dry-run gate ---------------------------------------


def _mixed_session():
    get_req = RecordedRequest(
        method="GET",
        url="https://app.example.com/?q=1",
        headers=[],
        body=None,
    )
    post_req = _json_req(b'{"a":"1"}', method="POST")
    return _session([get_req, post_req])


def test_mutating_skipped_without_confirm():
    key, run_id = _key_and_run()
    res = plant(_mixed_session(), key, run_id)

    # GET still plants (q x four variants); POST is skipped, not fired.
    assert len(res.planted) == 4
    assert all(pr.path_id == "query:q" for pr in res.planted)

    assert len(res.skipped) == 1
    skip = res.skipped[0]
    assert isinstance(skip, SkippedRequest)
    assert skip.method == "POST"
    assert skip.url == "https://app.example.com/"
    # nothing from the POST reached the planted set
    assert all(res.mapping[(pr.entry_id, pr.variant)].method == "GET" for pr in res.planted)


def test_mutating_planted_with_confirm():
    key, run_id = _key_and_run()
    res = plant(_mixed_session(), key, run_id, confirm_mutating=True)

    # GET (q) + POST (json leaf a), four variants each.
    assert len(res.planted) == 8
    assert res.skipped == []
    assert any(pr.path_id == "json:$.a" for pr in res.planted)
    assert any(pr.path_id == "query:q" for pr in res.planted)


# --- Negative: dash-heavy value does not shift other sites' path ids -------


def test_dash_heavy_value_does_not_shift_path_ids():
    key, run_id = _key_and_run()
    body = b'{"a":"---DYE---like---","b":"plain"}'
    res = plant(_session([_json_req(body)]), key, run_id, raw_only=True)

    assert {pr.path_id for pr in res.planted} == {"json:$.a", "json:$.b"}


# --- Negative: exactly one decode and one encode (no double-encoding) ------


def test_single_decode_single_encode_json():
    key, run_id = _key_and_run()
    body = b'{"a":"orig"}'
    res = plant(_session([_json_req(body)]), key, run_id)  # includes attr (quotes)
    import json

    attr = next(pr for pr in res.planted if pr.variant == "attr")
    # Body is valid JSON and a single json.loads returns the planted payload
    # verbatim; a double-encode would have escaped the attr variant's quotes.
    obj = json.loads(attr.body.data.decode("utf-8"))
    payload = obj["a"]
    assert '"' in payload  # the attr variant carries literal quotes
    token = marker.extract_token(payload)
    assert token is not None and marker.verify(token, key)
    # Canonical separators used for re-serialization (no spaces).
    assert b", " not in attr.body.data and b'": ' not in attr.body.data


# --- Descriptor repr masking (hardening) -----------------------------------


def test_planted_request_repr_masks_credentials_and_url():
    pr = PlantedRequest(
        entry_id="0a",
        variant="raw",
        method="GET",
        url="https://u:TOPSECRETPW@app.example.com/x?token=TOPSECRETQS",
        headers=[("Authorization", "Bearer TOPSECRETTOKEN"), ("Accept", "*/*")],
        body=None,
        path_id="json:$.a",
        original_value="plainvalue",
    )
    text = repr(pr)
    assert "TOPSECRETTOKEN" not in text  # sensitive header masked
    assert "TOPSECRETPW" not in text  # url userinfo stripped
    assert "TOPSECRETQS" not in text  # url query value masked
    assert "***" in text
    assert "*/*" in text  # non-sensitive header value survives


def test_planted_request_repr_masks_header_site_original_value():
    pr = PlantedRequest(
        entry_id="0b",
        variant="raw",
        method="GET",
        url="https://app.example.com/x",
        headers=[("X-Api-Key", "***")],
        body=None,
        path_id="header:X-Api-Key",
        original_value="THEREALAPIKEYVALUE",
    )
    text = repr(pr)
    assert "THEREALAPIKEYVALUE" not in text  # header-site original value masked


def test_planted_request_repr_redacts_every_original_value():
    # A query/form/body value can be a secret too, so original_value is shown
    # only as type and length, never the value, for any site kind.
    pr = PlantedRequest(
        entry_id="0c",
        variant="raw",
        method="GET",
        url="https://app.example.com/x",
        headers=[],
        body=None,
        path_id="query:token",
        original_value="SECRETQUERYVALUE",
    )
    text = repr(pr)
    assert "SECRETQUERYVALUE" not in text
    assert "<str len=16>" in text


def test_header_site_in_multipart_request_plants_without_misalignment():
    # Regression: a multipart request drops its Content-Type from the base header
    # list, so a header site must index the base list, not req.headers. Before the
    # fix this raised IndexError or overwrote the wrong header.
    key = marker.mint_key()
    part = MultipartPart(name="file", filename="a.txt", content_type="text/plain", data=b"hi")
    req = RecordedRequest(
        method="GET",
        url="https://app.example.com/upload",
        headers=[("Content-Type", "multipart/form-data; boundary=zzz"), ("X-Custom", "orig")],
        body=Body(content_type="multipart/form-data", data=None, parts=[part]),
    )
    session = Session(
        version="1", cookies={}, auth_headers={}, base_url="https://app.example.com",
        allowlist_host="app.example.com", recorded_requests=[req],
    )
    result = plant(session, key, "00", raw_only=True)
    header_descriptors = [p for p in result.planted if p.path_id == "header:X-Custom"]
    assert len(header_descriptors) == 1  # the one custom-header site
    pr = header_descriptors[0]
    # The planted header carries the tracer; the recorded multipart Content-Type
    # was dropped so httpx owns the boundary, and no other header was clobbered.
    names = [n for n, _ in pr.headers]
    assert "X-Custom" in names
    assert not any(n.lower() == "content-type" for n in names)
    xval = next(v for n, v in pr.headers if n == "X-Custom")
    assert marker.extract_token(xval) is not None  # tracer landed in X-Custom


# --- OSS mode: candidate-targeted planting (U3) ----------------------------


def _query_req(url):
    return RecordedRequest(method="GET", url=url, headers=[], body=None)


def test_targets_limits_planting_to_claimed_indices():
    key, run_id = _key_and_run()
    session = _session([
        _query_req("https://app.example.com/a?x=1"),
        _query_req("https://app.example.com/b?y=2"),
    ])
    res = plant(session, key, run_id, raw_only=True,
                targets={0: (("cand-1", None),)})
    assert len(res.planted) >= 1
    for attr in res.mapping.values():
        assert attr.url == "https://app.example.com/a?x=1"
        assert attr.candidate_ids == ("cand-1",)


def test_targets_shared_request_co_attributes_all_candidates():
    key, run_id = _key_and_run()
    session = _session([_query_req("https://app.example.com/a?x=1")])
    res = plant(session, key, run_id, raw_only=True,
                targets={0: (("cand-1", None), ("cand-2", None))})
    assert res.planted  # one planting per site, shared by both candidates
    assert {attr.candidate_ids for attr in res.mapping.values()} == {
        ("cand-1", "cand-2")
    }


def test_targets_mutating_gate_still_applies():
    key, run_id = _key_and_run()
    session = _session([
        RecordedRequest(method="POST", url="https://app.example.com/a?x=1",
                        headers=[], body=None),
    ])
    res = plant(session, key, run_id, raw_only=True, targets={0: (("cand-1", None),)})
    assert res.planted == []
    assert len(res.skipped) == 1


def test_no_targets_keeps_black_box_behavior():
    key, run_id = _key_and_run()
    session = _session([_query_req("https://app.example.com/a?x=1")])
    res = plant(session, key, run_id, raw_only=True)
    assert res.planted
    assert all(attr.candidate_ids == () for attr in res.mapping.values())


def test_targets_path_id_claims_only_that_leaf():
    """A bind-level path_id claim plants just the named leaf; other sites on
    the same request stay unplanted and unattributed."""
    key, run_id = _key_and_run()
    session = _session([
        _query_req("https://app.example.com/a?x=1&y=2"),
    ])
    res = plant(session, key, run_id, raw_only=True,
                targets={0: (("cand-1", "query:x"),)})
    path_ids = {attr.path_id for attr in res.mapping.values()}
    assert path_ids == {"query:x"}
    assert {attr.candidate_ids for attr in res.mapping.values()} == {
        ("cand-1",)
    }


def test_targets_mixed_claims_full_and_leaf_scoped():
    """One candidate claims the whole request, another claims a single leaf:
    the leaf plant attributes to both, the rest to the whole-claimant."""
    key, run_id = _key_and_run()
    session = _session([
        _query_req("https://app.example.com/a?x=1&y=2"),
    ])
    res = plant(session, key, run_id, raw_only=True,
                targets={0: (("cand-all", None), ("cand-leaf", "query:x"))})
    by_site = {attr.path_id: attr.candidate_ids
               for attr in res.mapping.values()}
    assert by_site["query:x"] == ("cand-all", "cand-leaf")
    assert by_site["query:y"] == ("cand-all",)
