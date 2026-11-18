"""Tests for operator binds: load + merge into the OSS map (P0-1)."""

import json

import pytest

from dyetrace.binds import BindsError, apply_binds, load_binds
from dyetrace.ossmap import map_candidates
from dyetrace.session import RecordedRequest
from tests.oss_fixtures import candidate as _cand

BASE = "https://app.example.com"


def _req(url=BASE + "/x?q=1", method="GET"):
    return RecordedRequest(method=method, url=url, headers=[], body=None)


def _write(tmp_path, obj):
    p = tmp_path / "binds.json"
    p.write_text(json.dumps(obj))
    return str(p)


class TestLoadBinds:
    def test_loads_binds(self, tmp_path):
        binds = load_binds(_write(tmp_path, {
            "cand-1": {"request_index": 2},
            "cand-2": {"request_index": 0, "path_id": "query:q",
                       "predicted": "propagate:3"},
        }))
        assert binds["cand-1"].request_index == 2
        assert binds["cand-1"].path_id is None
        assert binds["cand-2"].path_id == "query:q"
        assert binds["cand-2"].predicted == "propagate:3"

    @pytest.mark.parametrize("obj", [
        ["not", "an", "object"],
        {"cand-1": "not a bind"},
        {"cand-1": {}},
        {"cand-1": {"request_index": "0"}},
        {"cand-1": {"request_index": -1}},
        {"cand-1": {"request_index": 0, "path_id": 5}},
        {"cand-1": {"request_index": 0, "predicted": 7}},
        {"cand-1": {"request_index": 0, "predicted": "propagate:nope"}},
        {"cand-1": {"request_index": 0, "predicted": "cookie"}},
    ])
    def test_malformed_fails_closed(self, tmp_path, obj):
        with pytest.raises(BindsError):
            load_binds(_write(tmp_path, obj))

    def test_bad_json_fails_closed(self, tmp_path):
        p = tmp_path / "binds.json"
        p.write_text("{ not json")
        with pytest.raises(BindsError):
            load_binds(str(p))

    def test_missing_file_fails_closed(self, tmp_path):
        with pytest.raises(BindsError):
            load_binds(str(tmp_path / "nope.json"))

    def test_bare_identity_predicted_accepted(self, tmp_path):
        binds = load_binds(_write(tmp_path, {
            "cand-1": {"request_index": 0, "predicted": "identity:2"},
        }))
        assert binds["cand-1"].predicted == "identity:2"


class TestApplyBinds:
    def test_bound_nonroute_candidate_becomes_mapped(self):
        cands = [_cand("cand-e", kind="exported", detail="x")]
        reqs = [_req()]
        mr = map_candidates(cands, reqs)
        apply_binds(mr, {"cand-e": _bind(reqs, 0)}, reqs)
        assert len(mr.mapped) == 1
        assert mr.mapped[0].request_indices == [0]
        assert mr.mapped[0].bind.request_index == 0
        assert not mr.unmapable

    def test_unbound_nonroute_stays_unmapable(self):
        cands = [_cand("cand-e", kind="exported", detail="x")]
        mr = map_candidates(cands, [_req()])
        apply_binds(mr, {}, [_req()])
        assert not mr.mapped and len(mr.unmapable) == 1

    def test_bind_overrides_route_mapping(self):
        cands = [_cand("cand-1", detail="get /x")]
        reqs = [_req(BASE + "/x?q=1"), _req(BASE + "/y")]
        mr = map_candidates(cands, reqs)
        apply_binds(mr, {"cand-1": _bind(reqs, 1)}, reqs)
        assert mr.mapped[0].request_indices == [1]

    def test_unknown_candidate_id_fails_closed(self):
        mr = map_candidates([_cand("cand-1")], [_req()])
        with pytest.raises(BindsError):
            apply_binds(mr, {"cand-ghost": _bind([_req()], 0)}, [_req()])

    def test_out_of_range_index_fails_closed(self):
        mr = map_candidates([_cand("cand-1")], [_req()])
        with pytest.raises(BindsError):
            apply_binds(mr, {"cand-1": _bind([_req()], 5)}, [_req()])


def _bind(reqs, index, path_id=None, predicted=None):
    from dyetrace.binds import OperatorBind
    return OperatorBind(candidate_id="",
                        request_index=index,
                        path_id=path_id,
                        predicted=predicted)
