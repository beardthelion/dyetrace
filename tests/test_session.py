"""Tests for the U3 session loader.

Test-first: these are written before src/dyetrace/session.py exists, so the
import fails RED until the loader is implemented.

House rules enforced here: the zero-plantable case and the schema-invalid case
each RAISE a dedicated exception (never an empty success), and no test asserts a
diagnostic line that contains a real cookie or auth-header value.
"""

import base64
import json
from pathlib import Path

import pytest

from dyetrace.session import (
    Body,
    NoPlantableInputError,
    RecordedRequest,
    SchemaError,
    Session,
    SessionError,
    load_session,
)

ALLOWLIST_HOST = "app.example.com"

# A secret cookie/header value used to prove masking never leaks it.
SECRET_COOKIE = "sessionid=TOPSECRETCOOKIEVALUE123"
SECRET_TOKEN = "Bearer TOPSECRETBEARERTOKEN456"


def _binary_body_b64():
    raw = bytes(range(256))  # not valid utf-8, forces a faithful byte path
    return raw, base64.b64encode(raw).decode("ascii")


def _valid_session_dict():
    raw_bytes, b64 = _binary_body_b64()
    return {
        "version": "1",
        "cookies": {"sessionid": "TOPSECRETCOOKIEVALUE123"},
        "auth_headers": {"Authorization": "Bearer TOPSECRETBEARERTOKEN456"},
        "base_url": "https://app.example.com",
        "recorded_requests": [
            {
                "method": "POST",
                "url": "https://app.example.com/api/items?draft=1",
                "headers": [
                    ["Content-Type", "application/json"],
                    ["X-Custom-Thing", "hello"],
                ],
                "body": {
                    "content_type": "application/json",
                    "encoding": "text",
                    "data": '{"title": "x"}',
                },
            },
            {
                "method": "PUT",
                "url": "https://app.example.com/upload/avatar",
                "headers": [["Content-Type", "application/octet-stream"]],
                "body": {
                    "content_type": "application/octet-stream",
                    "encoding": "base64",
                    "data": b64,
                },
            },
        ],
    }, raw_bytes


def _write(tmp_path, obj):
    p = tmp_path / "session.json"
    p.write_text(json.dumps(obj))
    return p


# --- Happy path ------------------------------------------------------------


def test_happy_loads_all_fields(tmp_path):
    obj, raw_bytes = _valid_session_dict()
    sess = load_session(_write(tmp_path, obj), allowlist_host=ALLOWLIST_HOST)

    assert isinstance(sess, Session)
    assert sess.version == "1"
    assert sess.cookies == {"sessionid": "TOPSECRETCOOKIEVALUE123"}
    assert sess.auth_headers == {"Authorization": "Bearer TOPSECRETBEARERTOKEN456"}
    assert sess.base_url == "https://app.example.com"
    assert len(sess.recorded_requests) == 2

    r0 = sess.recorded_requests[0]
    assert isinstance(r0, RecordedRequest)
    assert r0.method == "POST"
    assert r0.url == "https://app.example.com/api/items?draft=1"
    # ordered headers preserved as a list
    assert r0.headers == [
        ("Content-Type", "application/json"),
        ("X-Custom-Thing", "hello"),
    ]
    assert isinstance(r0.body, Body)
    assert r0.body.data == b'{"title": "x"}'


def test_happy_base64_body_round_trips(tmp_path):
    obj, raw_bytes = _valid_session_dict()
    sess = load_session(_write(tmp_path, obj), allowlist_host=ALLOWLIST_HOST)
    assert sess.recorded_requests[1].body.data == raw_bytes


def test_allowlist_host_comes_from_operator_not_base_url(tmp_path):
    obj, _ = _valid_session_dict()
    # Operator names a different host than base_url resolves to; theirs wins.
    sess = load_session(_write(tmp_path, obj), allowlist_host="scope.example.com")
    assert sess.allowlist_host == "scope.example.com"


def test_multipart_body_preserves_part_filename_and_type(tmp_path):
    part_raw = b"\x89PNG\r\n\x1a\n binary avatar"
    obj, _ = _valid_session_dict()
    obj["recorded_requests"].append(
        {
            "method": "POST",
            "url": "https://app.example.com/upload/form",
            "headers": [["Content-Type", "multipart/form-data; boundary=xyz"]],
            "body": {
                "content_type": "multipart/form-data; boundary=xyz",
                "encoding": "multipart",
                "parts": [
                    {
                        "name": "caption",
                        "filename": None,
                        "content_type": "text/plain",
                        "encoding": "text",
                        "data": "my pic",
                    },
                    {
                        "name": "file",
                        "filename": "avatar.png",
                        "content_type": "image/png",
                        "encoding": "base64",
                        "data": base64.b64encode(part_raw).decode("ascii"),
                    },
                ],
            },
        }
    )
    sess = load_session(_write(tmp_path, obj), allowlist_host=ALLOWLIST_HOST)
    body = sess.recorded_requests[-1].body
    assert body.parts is not None and len(body.parts) == 2
    assert body.parts[0].data == b"my pic"
    assert body.parts[1].filename == "avatar.png"
    assert body.parts[1].content_type == "image/png"
    assert body.parts[1].data == part_raw


# --- Fail-closed: zero plantable -------------------------------------------


def test_zero_plantable_raises(tmp_path):
    obj = {
        "version": "1",
        "cookies": {"sessionid": "TOPSECRETCOOKIEVALUE123"},
        "auth_headers": {"Authorization": "Bearer TOPSECRETBEARERTOKEN456"},
        "base_url": "https://app.example.com",
        "recorded_requests": [
            {
                "method": "GET",
                "url": "https://app.example.com/",
                "headers": [
                    ["Host", "app.example.com"],
                    ["User-Agent", "x"],
                    ["Accept", "*/*"],
                ],
                "body": None,
            }
        ],
    }
    with pytest.raises(NoPlantableInputError):
        load_session(_write(tmp_path, obj), allowlist_host=ALLOWLIST_HOST)


def test_no_plantable_is_a_session_error(tmp_path):
    # It must be in the fail-closed family, not a bare ValueError.
    assert issubclass(NoPlantableInputError, SessionError)
    assert issubclass(SchemaError, SessionError)


def test_a_single_plantable_leaf_is_enough(tmp_path):
    # One request with a query string is plantable even if another request is not.
    obj = {
        "version": "1",
        "cookies": {},
        "auth_headers": {},
        "base_url": "https://app.example.com",
        "recorded_requests": [
            {
                "method": "GET",
                "url": "https://app.example.com/",
                "headers": [["Accept", "*/*"]],
                "body": None,
            },
            {
                "method": "GET",
                "url": "https://app.example.com/search?q=cats",
                "headers": [["Accept", "*/*"]],
                "body": None,
            },
        ],
    }
    sess = load_session(_write(tmp_path, obj), allowlist_host=ALLOWLIST_HOST)
    assert len(sess.recorded_requests) == 2


# --- Schema-invalid: reject before use -------------------------------------


def test_missing_method_rejected(tmp_path):
    obj, _ = _valid_session_dict()
    del obj["recorded_requests"][0]["method"]
    with pytest.raises(SchemaError):
        load_session(_write(tmp_path, obj), allowlist_host=ALLOWLIST_HOST)


def test_malformed_base64_body_rejected(tmp_path):
    obj, _ = _valid_session_dict()
    obj["recorded_requests"][1]["body"]["data"] = "not valid base64 !!!"
    with pytest.raises(SchemaError):
        load_session(_write(tmp_path, obj), allowlist_host=ALLOWLIST_HOST)


def test_non_list_recorded_requests_rejected(tmp_path):
    obj, _ = _valid_session_dict()
    obj["recorded_requests"] = {"0": obj["recorded_requests"][0]}
    with pytest.raises(SchemaError):
        load_session(_write(tmp_path, obj), allowlist_host=ALLOWLIST_HOST)


def test_missing_required_top_level_field_rejected(tmp_path):
    obj, _ = _valid_session_dict()
    del obj["base_url"]
    with pytest.raises(SchemaError):
        load_session(_write(tmp_path, obj), allowlist_host=ALLOWLIST_HOST)


def test_not_json_rejected(tmp_path):
    p = tmp_path / "session.json"
    p.write_text("this is not json {")
    with pytest.raises(SchemaError):
        load_session(p, allowlist_host=ALLOWLIST_HOST)


def test_missing_file_raises_session_error(tmp_path):
    with pytest.raises(SessionError):
        load_session(tmp_path / "nope.json", allowlist_host=ALLOWLIST_HOST)


# --- Negative: diagnostics never leak secrets ------------------------------


def test_repr_masks_cookie_and_auth_values(tmp_path):
    obj, _ = _valid_session_dict()
    sess = load_session(_write(tmp_path, obj), allowlist_host=ALLOWLIST_HOST)
    text = repr(sess)
    assert "TOPSECRETCOOKIEVALUE123" not in text
    assert "TOPSECRETBEARERTOKEN456" not in text
    assert "***" in text
    # Names are fine to show; only values are secret.
    assert "sessionid" in text


def test_describe_masks_secrets(tmp_path):
    obj, _ = _valid_session_dict()
    sess = load_session(_write(tmp_path, obj), allowlist_host=ALLOWLIST_HOST)
    text = sess.describe()
    assert "TOPSECRETCOOKIEVALUE123" not in text
    assert "TOPSECRETBEARERTOKEN456" not in text


def test_recorded_request_repr_masks_sensitive_headers(tmp_path):
    obj, _ = _valid_session_dict()
    obj["recorded_requests"][0]["headers"].append(
        ["Cookie", SECRET_COOKIE]
    )
    obj["recorded_requests"][0]["headers"].append(
        ["Authorization", SECRET_TOKEN]
    )
    sess = load_session(_write(tmp_path, obj), allowlist_host=ALLOWLIST_HOST)
    text = repr(sess.recorded_requests[0])
    assert "TOPSECRETCOOKIEVALUE123" not in text
    assert "TOPSECRETBEARERTOKEN456" not in text
    assert "***" in text


# --- Broader credential masking (hardening) --------------------------------


def test_recorded_request_repr_masks_custom_auth_header():
    req = RecordedRequest(
        method="GET",
        url="https://app.example.com/x",
        headers=[("X-Api-Key", "TOPSECRETAPIKEY"), ("Accept", "application/json")],
        body=None,
    )
    text = repr(req)
    assert "TOPSECRETAPIKEY" not in text
    assert "***" in text
    assert "application/json" in text  # non-sensitive value survives


def test_recorded_request_repr_sanitizes_url_userinfo_and_query():
    req = RecordedRequest(
        method="GET",
        url="https://user:TOPSECRETPW@app.example.com/x?token=TOPSECRETQS&page=2",
        headers=[],
        body=None,
    )
    text = repr(req)
    assert "TOPSECRETPW" not in text  # userinfo stripped
    assert "TOPSECRETQS" not in text  # query value masked
    assert "app.example.com" in text  # host preserved


def test_recorded_request_repr_masks_url_fragment_and_bare_token():
    req = RecordedRequest(
        method="GET",
        url="https://app.example.com/x?SECRETBARE&page=2#SECRETFRAG",
        headers=[],
        body=None,
    )
    text = repr(req)
    assert "SECRETBARE" not in text  # bare (=-less) query token masked whole
    assert "SECRETFRAG" not in text  # fragment masked
    assert "app.example.com" in text  # host preserved
    assert "page" in text  # a normal param name stays legible


def test_malformed_recorded_url_raises_schema_error(tmp_path):
    # A url that urlsplit cannot parse must be a SchemaError (fail-closed family),
    # not an uncaught ValueError that crashes the run.
    obj, _ = _valid_session_dict()
    obj["recorded_requests"][0]["url"] = "http://[::1"
    with pytest.raises(SchemaError):
        load_session(_write(tmp_path, obj), "app.example.com")
