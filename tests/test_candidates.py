"""Tests for U1: the jevsec candidate loader (OSS mode)."""

import json

import pytest

from dyetrace.candidates import (
    CandidatesError,
    load_candidates,
)
from tests.oss_fixtures import (
    candidate_dict as _candidate,
    candidates_doc as _doc,
)


def _write(tmp_path, obj, name="candidates.json"):
    p = tmp_path / name
    p.write_text(json.dumps(obj))
    return p




class TestLoadHappy:
    def test_loads_typed_candidates(self, tmp_path):
        p = _write(tmp_path, _doc([_candidate(), _candidate(cid="cand-bbb222")]))
        cands = load_candidates(p)
        assert [c.id for c in cands] == ["cand-aaa111", "cand-bbb222"]
        c = cands[0]
        assert c.entry.kind == "route"
        assert c.entry.detail == "get /report"
        assert c.entry.site_file == "a.py"
        assert c.entry.site_line == 1
        assert c.entry.node_name == "h"
        assert c.sink.callee == "os.system"
        assert c.sink.sink_class == "code-exec"
        assert c.sink.site_file == "b.py"
        assert c.sink.site_line == 2
        assert c.rank == 1

    def test_accepts_a_run_dir_containing_candidates_json(self, tmp_path):
        run_dir = tmp_path / "20261021T000000-abcd"
        run_dir.mkdir()
        _write(run_dir, _doc([_candidate()]))
        cands = load_candidates(run_dir)
        assert len(cands) == 1

    def test_extra_fields_are_ignored(self, tmp_path):
        c = _candidate()
        c["extra"] = {"nested": [1, 2, 3]}
        c["entry"]["surprise"] = True
        p = _write(tmp_path, _doc([c]))
        assert len(load_candidates(p)) == 1

    def test_empty_candidate_list_is_a_valid_load(self, tmp_path):
        p = _write(tmp_path, _doc([]))
        assert load_candidates(p) == []


class TestLoadRejections:
    def test_missing_path_fails_closed(self, tmp_path):
        with pytest.raises(CandidatesError):
            load_candidates(tmp_path / "nope.json")

    def test_directory_without_candidates_json_fails(self, tmp_path):
        with pytest.raises(CandidatesError) as exc:
            load_candidates(tmp_path)
        assert "candidates.json" in str(exc.value)

    def test_runs_root_with_multiple_run_dirs_fails(self, tmp_path):
        for name in ("run-a", "run-b"):
            d = tmp_path / name
            d.mkdir()
            _write(d, _doc([]))
        with pytest.raises(CandidatesError) as exc:
            load_candidates(tmp_path)
        assert "run dir" in str(exc.value)

    def test_non_json_fails(self, tmp_path):
        p = tmp_path / "candidates.json"
        p.write_text("{not json")
        with pytest.raises(CandidatesError):
            load_candidates(p)

    def test_non_object_root_fails(self, tmp_path):
        p = _write(tmp_path, [1, 2, 3])
        with pytest.raises(CandidatesError):
            load_candidates(p)

    def test_wrong_version_fails(self, tmp_path):
        doc = _doc([_candidate()])
        doc["version"] = 2
        with pytest.raises(CandidatesError):
            load_candidates(_write(tmp_path, doc))

    def test_missing_candidates_array_fails(self, tmp_path):
        doc = _doc([_candidate()])
        del doc["candidates"]
        with pytest.raises(CandidatesError):
            load_candidates(_write(tmp_path, doc))

    @pytest.mark.parametrize("mutate", [
        lambda c: c.pop("id"),
        lambda c: c.pop("entry"),
        lambda c: c.pop("sink"),
        lambda c: c["entry"].pop("kind"),
        lambda c: c["entry"].pop("detail"),
        lambda c: c["entry"].pop("site"),
        lambda c: c["sink"].pop("callee"),
        lambda c: c["sink"].pop("sinkClass"),
        lambda c: c["sink"].pop("site"),
        lambda c: c["entry"]["site"].pop("line"),
    ])
    def test_missing_required_fields_fail(self, tmp_path, mutate):
        c = _candidate()
        mutate(c)
        with pytest.raises(CandidatesError):
            load_candidates(_write(tmp_path, _doc([c])))


class TestBoundaryInputs:
    @pytest.mark.parametrize("version", [True, 1.0, "1", 2, None])
    def test_version_must_be_int_1(self, tmp_path, version):
        doc = _doc([_candidate()])
        doc["version"] = version
        with pytest.raises(CandidatesError):
            load_candidates(_write(tmp_path, doc))

    @pytest.mark.parametrize("mutate", [
        lambda c: c.update(id=7),
        lambda c: c["entry"]["site"].update(line="1"),
        lambda c: c["entry"]["site"].update(line=True),
        lambda c: c.update(rank=True),
        lambda c: c.update(entry=[]),
        lambda c: c["entry"]["node"].update(name=5),
    ])
    def test_wrong_typed_fields_fail(self, tmp_path, mutate):
        c = _candidate()
        mutate(c)
        with pytest.raises(CandidatesError):
            load_candidates(_write(tmp_path, _doc([c])))

    def test_non_dict_candidate_element_fails(self, tmp_path):
        with pytest.raises(CandidatesError):
            load_candidates(_write(tmp_path, _doc(["x"])))

    def test_duplicate_candidate_ids_fail(self, tmp_path):
        with pytest.raises(CandidatesError) as exc:
            load_candidates(_write(
                tmp_path, _doc([_candidate(), _candidate()])
            ))
        assert "duplicate" in str(exc.value)

    def test_non_utf8_file_fails_closed(self, tmp_path):
        p = tmp_path / "candidates.json"
        p.write_bytes(b"\xff\xfe{}")
        with pytest.raises(CandidatesError):
            load_candidates(p)

    def test_oversized_file_fails_closed(self, tmp_path):
        p = tmp_path / "candidates.json"
        p.write_bytes(b" " * (17 * 1024 * 1024))
        with pytest.raises(CandidatesError):
            load_candidates(p)


class TestRunsRootResolution:
    def test_runs_root_with_zero_run_dirs_fails(self, tmp_path):
        root = tmp_path / "runs"
        root.mkdir()
        with pytest.raises(CandidatesError) as exc:
            load_candidates(root)
        assert "no candidates.json" in str(exc.value)

    def test_runs_root_with_one_run_dir_resolves_it(self, tmp_path, capsys):
        root = tmp_path / "runs"
        (root / "run-a").mkdir(parents=True)
        (root / "run-a" / "candidates.json").write_text(
            json.dumps(_doc([_candidate()]))
        )
        cands = load_candidates(root)
        assert [c.id for c in cands] == ["cand-aaa111"]
        assert "run-a" in capsys.readouterr().err

    def test_runs_root_with_many_run_dirs_lists_them(self, tmp_path):
        root = tmp_path / "runs"
        for name in ("run-a", "run-b", "run-c"):
            (root / name).mkdir(parents=True)
            (root / name / "candidates.json").write_text(
                json.dumps(_doc([_candidate()]))
            )
        with pytest.raises(CandidatesError) as exc:
            load_candidates(root)
        msg = str(exc.value)
        assert "run-a" in msg and "run-b" in msg and "run-c" in msg
        assert "1." in msg and "3." in msg
