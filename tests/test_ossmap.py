"""Tests for U2: candidate -> recorded-request mapper (ossmap)."""

import pytest

from dyetrace.ossmap import map_candidates
from dyetrace.session import RecordedRequest
from tests.oss_fixtures import candidate as _cand


def _req(method, url, headers=None, body=None):
    return RecordedRequest(method=method, url=url,
                           headers=headers or [], body=body)


BASE = "https://example.test"


class TestDetailParsing:
    @pytest.mark.parametrize("detail,method,path", [
        ("get /x", "GET", "/x"),
        ("POST /x", "POST", "/x"),
        ("put /x", "PUT", "/x"),
        ("del /x", "DELETE", "/x"),
        ("options /x", "OPTIONS", "/x"),
        ("head /x", "HEAD", "/x"),
        ("patch /x", "PATCH", "/x"),
        ("route /x", None, "/x"),
        ("all /x", None, "/x"),
        ("ROUTE /x", None, "/x"),
        ("GET /x", "GET", "/x"),
    ])
    def test_verb_and_path_spellings(self, detail, method, path):
        methods = {"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"}
        reqs = [_req(m, f"{BASE}/x") for m in sorted(methods)]
        res = map_candidates([_cand(detail=detail)], reqs)
        assert res.mapped and not res.unmapable
        expected = [i for i, r in enumerate(reqs)
                    if method is None or r.method == method]
        assert res.mapped[0].request_indices == expected

    @pytest.mark.parametrize("detail", [
        "use",               # middleware registration, no path
        "use /x",            # mounted middleware: not a handler route
        "get",               # verb only, no path
        "GET route",         # pygraph no-arg decorator fallback
        "websocket /ws",     # unknown verb
        "trace /x",          # unknown verb
        "routes /x",         # unknown verb
        "",                  # empty detail
        "/x",                # path only, no verb
    ])
    def test_unparseable_details_unmapable(self, detail):
        res = map_candidates([_cand(detail=detail)], [_req("GET", f"{BASE}/x")])
        assert not res.mapped
        assert res.unmapable[0].reason


class TestPathMatching:
    def test_exact_path_match(self):
        reqs = [_req("GET", f"{BASE}/report"), _req("GET", f"{BASE}/other")]
        res = map_candidates([_cand(detail="get /report")], reqs)
        assert res.mapped[0].request_indices == [0]

    def test_flask_param_segment_matches_concrete(self):
        reqs = [_req("GET", f"{BASE}/user/42"), _req("GET", f"{BASE}/user")]
        res = map_candidates([_cand(detail="get /user/<int:id>")], reqs)
        assert res.mapped[0].request_indices == [0]

    def test_param_segment_matches_concrete(self):
        reqs = [_req("GET", f"{BASE}/user/42"), _req("GET", f"{BASE}/user")]
        res = map_candidates([_cand(detail="get /user/:id")], reqs)
        assert res.mapped[0].request_indices == [0]

    def test_segment_count_must_match(self):
        reqs = [_req("GET", f"{BASE}/user"), _req("GET", f"{BASE}/user/42/edit")]
        res = map_candidates([_cand(detail="get /user/:id")], reqs)
        assert not res.mapped

    def test_param_segment_does_not_match_empty(self):
        res = map_candidates([_cand(detail="get /user/:id")],
                             [_req("GET", f"{BASE}/user/")])
        assert not res.mapped

    def test_trailing_slash_is_distinct(self):
        res = map_candidates([_cand(detail="get /x/")], [_req("GET", f"{BASE}/x")])
        assert not res.mapped

    def test_root_path_matches(self):
        res = map_candidates([_cand(detail="get /")], [_req("GET", BASE + "/")])
        assert res.mapped[0].request_indices == [0]

    @pytest.mark.parametrize("path", ["/x/*", "/x(.*)", "/x[0-9]", "/x\\d"])
    def test_pattern_syntax_unmapable(self, path):
        res = map_candidates([_cand(detail=f"get {path}")],
                             [_req("GET", f"{BASE}/x1")])
        assert not res.mapped
        assert res.unmapable[0].reason

    def test_query_string_ignored_for_path_match(self):
        reqs = [_req("GET", f"{BASE}/x?a=1")]
        res = map_candidates([_cand(detail="get /report")], [_req("GET", f"{BASE}/other")])
        res2 = map_candidates([_cand(detail="get /x")], reqs)
        assert not res.mapped
        assert res2.mapped[0].request_indices == [0]


class TestMapping:
    def test_non_route_kinds_unmapable(self):
        for kind in ("exported", "cli-handler", "consumer", "module-init"):
            res = map_candidates([_cand(kind=kind)], [_req("GET", f"{BASE}/x")])
            assert not res.mapped
            assert res.unmapable[0].reason

    def test_zero_matches_unmapable(self):
        res = map_candidates([_cand(detail="get /report")], [_req("GET", f"{BASE}/other")])
        assert not res.mapped
        assert res.unmapable[0].candidate.id == "cand-1"

    def test_multiple_requests_map_all(self):
        reqs = [_req("GET", f"{BASE}/r"), _req("POST", f"{BASE}/r"),
                _req("GET", f"{BASE}/r")]
        res = map_candidates([_cand(detail="route /r")], reqs)
        assert res.mapped[0].request_indices == [0, 1, 2]

    def test_method_constraint(self):
        reqs = [_req("GET", f"{BASE}/r"), _req("POST", f"{BASE}/r")]
        res = map_candidates([_cand(detail="get /r")], reqs)
        assert res.mapped[0].request_indices == [0]

    def test_multiple_candidates_shared_route(self):
        reqs = [_req("GET", f"{BASE}/r")]
        res = map_candidates(
            [_cand("cand-a", detail="get /r"), _cand("cand-b", detail="get /r")],
            reqs,
        )
        assert len(res.mapped) == 2
        assert all(m.request_indices == [0] for m in res.mapped)

    def test_empty_request_list(self):
        res = map_candidates([_cand()], [])
        assert not res.mapped and res.unmapable


class TestEdgeInputs:
    def test_bare_origin_matches_root_route(self):
        res = map_candidates([_cand(detail="get /")], [_req("GET", BASE)])
        assert res.mapped[0].request_indices == [0]

    def test_percent_encoded_path_matches_decoded(self):
        res = map_candidates([_cand(detail="get /café")],
                             [_req("GET", f"{BASE}/caf%C3%A9")])
        assert res.mapped[0].request_indices == [0]

    @pytest.mark.parametrize("detail,concrete,expected", [
        ("get /user/<int:id>", "/user/42", True),
        ("get /user/<int:id>", "/user/profile", False),
        ("get /f/<float:x>", "/f/1.5", True),
        ("get /f/<path:rest>", "/f/a/b", False),  # multi-seg: unmapable
        ("get /u/<name>", "/u/anything", True),
    ])
    def test_flask_converters(self, detail, concrete, expected):
        res = map_candidates([_cand(detail=detail)],
                             [_req("GET", BASE + concrete)])
        assert bool(res.mapped) == expected

    def test_reason_masks_secret_shaped_single_token_detail(self):
        res = map_candidates([_cand(detail="AKIAIOSFODNN7EXAMPLE1234")],
                             [_req("GET", f"{BASE}/x")])
        assert "AKIAIOSFODNN7EXAMPLE1234" not in res.unmapable[0].reason

    def test_go_and_gin_registrations_map_generically(self):
        reqs = [_req("GET", f"{BASE}/exec"), _req("POST", f"{BASE}/exec")]
        for detail in ("handleFunc /exec", "handle /exec", "any /exec"):
            res = map_candidates([_cand(detail=detail)], reqs)
            assert res.mapped and not res.unmapable
            assert res.mapped[0].request_indices == [0, 1]


class TestRpcNames:
    def test_rpc_name_maps_by_last_segment(self):
        reqs = [_req("POST", f"{BASE}/api/collections.add_group"),
                _req("GET", f"{BASE}/api/collections.add_group")]
        res = map_candidates([_cand(detail="post collections.add_group")], reqs)
        assert res.mapped[0].request_indices == [0]

    def test_rpc_name_must_match_last_segment(self):
        res = map_candidates(
            [_cand(detail="post shares.create")],
            [_req("POST", f"{BASE}/api/shares.update")])
        assert not res.mapped

    def test_generic_verb_rpc_name_unmapable(self):
        res = map_candidates(
            [_cand(detail="route collections.add_group")],
            [_req("POST", f"{BASE}/api/collections.add_group")])
        assert not res.mapped


class TestRoutePrefix:
    def test_prefix_maps_mounted_route(self):
        reqs = [_req("GET", f"{BASE}/api/x")]
        res = map_candidates([_cand(detail="get /x")], reqs,
                             route_prefixes=("/api",))
        assert res.mapped[0].request_indices == [0]

    def test_without_prefix_stays_unmapable(self):
        res = map_candidates([_cand(detail="get /x")],
                             [_req("GET", f"{BASE}/api/x")])
        assert not res.mapped

    def test_prefix_normalizes_slashes(self):
        reqs = [_req("GET", f"{BASE}/api/x")]
        for prefix in ("api", "/api/", "/api"):
            res = map_candidates([_cand(detail="get /x")], reqs,
                                 route_prefixes=(prefix,))
            assert res.mapped, prefix

    def test_prefix_never_strips(self):
        """A recorded /x does not become /api/x: prefixes only join."""
        res = map_candidates([_cand(detail="get /api/x")],
                             [_req("GET", f"{BASE}/x")],
                             route_prefixes=("/api",))
        assert not res.mapped

    def test_double_prefix_no_match_no_crash(self):
        res = map_candidates([_cand(detail="get /api/x")],
                             [_req("GET", f"{BASE}/api/x")],
                             route_prefixes=("/api", "/api"))
        assert res.mapped  # direct path still matches
        res2 = map_candidates([_cand(detail="get /x")],
                              [_req("GET", f"{BASE}/api/api/x")],
                              route_prefixes=("/api",))
        # /api/api/x only matches if the operator records the doubled path;
        # /x alone stays unmapable against it.
        assert not res2.mapped

    def test_multiple_prefixes_tried(self):
        reqs = [_req("GET", f"{BASE}/v2/x")]
        res = map_candidates([_cand(detail="get /x")], reqs,
                             route_prefixes=("/api", "/v2"))
        assert res.mapped[0].request_indices == [0]

    def test_brace_param_segment_matches(self):
        reqs = [_req("GET", f"{BASE}/api/profiles/bob/open-terminal")]
        res = map_candidates(
            [_cand(detail="get /api/profiles/{name}/open-terminal")], reqs)
        assert res.mapped[0].request_indices == [0]
        # Literal equality still required on non-param segments.
        res2 = map_candidates(
            [_cand(detail="get /api/profiles/{name}/other")], reqs)
        assert not res2.mapped
