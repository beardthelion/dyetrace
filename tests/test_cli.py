"""Tests for the U8 CLI entry point and fail-closed exit discipline.

Test-first: written before src/dyetrace/cli.py exists, so the import fails RED
until the module is implemented. A session JSON fixture is written to a tmp file
and ``main([...])`` is invoked directly. Network is kept out of the unit by
injecting a fake resolver (so the HostGuard pins a safe address with no DNS) and
an httpx MockTransport (so no byte leaves the process).

Invariants under test: every stop condition returns a non-zero exit with a
distinct stated reason on stderr (R17/R12/KTD11) - a schema-invalid session, a
zero-plantable session, an unreadable file, a bad allowlist host, and an empty
propagation set; a completed run (including a clean zero-hit run) returns 0 and
its output is labeled as a completed no-leak run, not a stop (R17); the R28
arguments are defined and validated (KTD20).
"""

import json

import httpx
import pytest

from dyetrace.cli import main
from tests.oss_fixtures import candidate_dict as _cand, candidates_doc as _candidates_doc


def _write(tmp_path, obj, name="session.json"):
    p = tmp_path / name
    p.write_text(json.dumps(obj))
    return str(p)


def _plantable_get_session():
    return {
        "version": "1",
        "cookies": {},
        "auth_headers": {},
        "base_url": "https://app.example.com",
        "recorded_requests": [
            {
                "method": "GET",
                "url": "https://app.example.com/search?q=hello",
                "headers": [],
                "body": None,
            }
        ],
    }


def _resolver(_host):
    return ["93.184.216.34"]  # a safe (non-private) address, no real DNS


def _clean_transport():
    def handler(request):
        return httpx.Response(200, text="clean response, no dye here")

    return httpx.MockTransport(handler)


# --- Error (CLI, R17/R12): stop conditions exit non-zero with a reason ------


def test_zero_plantable_session_exits_nonzero_with_reason(tmp_path, capsys):
    session = {
        "version": "1",
        "cookies": {},
        "auth_headers": {},
        "base_url": "https://app.example.com",
        "recorded_requests": [
            {"method": "GET", "url": "https://app.example.com/",
             "headers": [], "body": None}
        ],
    }
    path = _write(tmp_path, session)
    rc = main(["--session", path, "--host", "app.example.com", "--rate", "1000"],
              resolver=_resolver, transport=_clean_transport())
    assert rc != 0
    err = capsys.readouterr().err
    assert "plantable" in err.lower()


def test_schema_invalid_session_exits_nonzero_with_reason(tmp_path, capsys):
    session = {  # missing required "version"
        "cookies": {},
        "auth_headers": {},
        "base_url": "https://app.example.com",
        "recorded_requests": [],
    }
    path = _write(tmp_path, session)
    rc = main(["--session", path, "--host", "app.example.com", "--rate", "1000"],
              resolver=_resolver, transport=_clean_transport())
    assert rc != 0
    err = capsys.readouterr().err
    assert "schema" in err.lower() or "version" in err.lower()


def test_unreadable_session_file_exits_nonzero(tmp_path, capsys):
    missing = str(tmp_path / "does-not-exist.json")
    rc = main(["--session", missing, "--host", "app.example.com", "--rate", "1000"],
              resolver=_resolver, transport=_clean_transport())
    assert rc != 0
    err = capsys.readouterr().err
    assert "session" in err.lower()


def test_bad_allowlist_host_exits_nonzero(tmp_path, capsys):
    path = _write(tmp_path, _plantable_get_session())
    rc = main(["--session", path, "--host", "", "--rate", "1000"],
              resolver=_resolver, transport=_clean_transport())
    assert rc != 0
    err = capsys.readouterr().err
    assert "host" in err.lower() or "allowlist" in err.lower()


def test_empty_propagation_exits_nonzero_with_reason(tmp_path, capsys):
    session = {
        "version": "1",
        "cookies": {},
        "auth_headers": {},
        "base_url": "https://app.example.com",
        "recorded_requests": [
            # Confirmed mutating POST so it is planted (non-empty mapping), but it
            # is not auto-replayed and not marked as a read surface, so the
            # propagation set is empty -> the empty-propagation fail-closed stop.
            {"method": "POST", "url": "https://app.example.com/write?q=1",
             "headers": [], "body": None}
        ],
    }
    path = _write(tmp_path, session)
    rc = main(["--session", path, "--host", "app.example.com", "--rate", "1000",
               "--confirm-mutating"],
              resolver=_resolver, transport=_clean_transport())
    assert rc != 0
    err = capsys.readouterr().err
    assert "propagation" in err.lower()


# --- Happy / clean: a completed run exits 0 and is labeled ------------------


def test_clean_zero_hit_run_exits_zero_and_is_labeled(tmp_path, capsys):
    path = _write(tmp_path, _plantable_get_session())
    rc = main(["--session", path, "--host", "app.example.com", "--rate", "1000"],
              resolver=_resolver, transport=_clean_transport())
    assert rc == 0
    out = capsys.readouterr().out
    assert "no verified leaks" in out
    assert "universe=" in out


def test_clean_run_writes_to_out_file(tmp_path):
    path = _write(tmp_path, _plantable_get_session())
    out_file = tmp_path / "report.txt"
    rc = main(
        ["--session", path, "--host", "app.example.com", "--rate", "1000",
         "--out", str(out_file)],
        resolver=_resolver, transport=_clean_transport(),
    )
    assert rc == 0
    assert "no verified leaks" in out_file.read_text()


def test_json_output_of_clean_run_is_valid(tmp_path, capsys):
    path = _write(tmp_path, _plantable_get_session())
    rc = main(
        ["--session", path, "--host", "app.example.com", "--rate", "1000",
         "--output", "json"],
        resolver=_resolver, transport=_clean_transport(),
    )
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["counts"]["resurfaced"] == 0
    assert doc["counts"]["universe"] >= 1


# --- Argument handling (R28/KTD20) ------------------------------------------


def test_missing_required_args_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code != 0


def test_invalid_output_choice_is_a_usage_error(tmp_path):
    path = _write(tmp_path, _plantable_get_session())
    with pytest.raises(SystemExit) as exc:
        main(["--session", path, "--host", "app.example.com",
              "--output", "pdf"])
    assert exc.value.code != 0


def test_all_plants_skipped_fails_closed(tmp_path, capsys):
    # Only a mutating POST, no --confirm-mutating -> it is skipped -> zero plants.
    # The run must fail closed, not report a clean no-leak success.
    session = {
        "version": "1", "cookies": {}, "auth_headers": {},
        "base_url": "https://app.example.com",
        "recorded_requests": [
            {"method": "POST", "url": "https://app.example.com/write?q=1",
             "headers": [], "body": None}
        ],
    }
    path = _write(tmp_path, session)
    rc = main(["--session", path, "--host", "app.example.com", "--rate", "1000"],
              resolver=_resolver, transport=_clean_transport())
    assert rc != 0
    assert "no tracers planted" in capsys.readouterr().err.lower()


def test_malformed_second_session_base_url_fails_closed(tmp_path, capsys):
    # A base_url that passes the loader's non-empty-string check but that httpx
    # rejects at client construction must be a clean fail-closed stop, not a
    # traceback or a leaked primary client.
    good = {
        "version": "1", "cookies": {}, "auth_headers": {},
        "base_url": "https://app.example.com",
        "recorded_requests": [
            {"method": "GET", "url": "https://app.example.com/a?q=1", "headers": [], "body": None}
        ],
    }
    bad = dict(good)
    bad = {**good, "base_url": "http://[::1"}
    gp = _write(tmp_path, good)
    bp = tmp_path / "second.json"
    bp.write_text(json.dumps(bad))
    rc = main(["--session", gp, "--second-session", str(bp), "--host", "app.example.com",
               "--rate", "1000"], resolver=_resolver, transport=_clean_transport())
    assert rc != 0
    assert "client setup" in capsys.readouterr().err.lower()


# --- OSS mode (--candidates) -------------------------------------------------


def _argv(session_path, extra):
    return ["--session", session_path, "--host", "app.example.com",
            "--rate", "1000", "--output", "json", *extra]


def test_candidates_missing_path_fails_closed(tmp_path, capsys):
    spath = _write(tmp_path, _plantable_get_session())
    rc = main(_argv(spath, ["--candidates", str(tmp_path / "nope.json")]),
              resolver=_resolver, transport=_clean_transport())
    assert rc != 0
    assert "candidates" in capsys.readouterr().err


def test_candidates_malformed_file_fails_closed(tmp_path, capsys):
    spath = _write(tmp_path, _plantable_get_session())
    bad = tmp_path / "candidates.json"
    bad.write_text("{nope")
    rc = main(_argv(spath, ["--candidates", str(bad)]),
              resolver=_resolver, transport=_clean_transport())
    assert rc != 0
    assert "candidates" in capsys.readouterr().err


def test_candidates_multi_run_dir_fails_closed(tmp_path, capsys):
    spath = _write(tmp_path, _plantable_get_session())
    for name in ("r1", "r2"):
        d = tmp_path / name
        d.mkdir()
        (d / "candidates.json").write_text(json.dumps(_candidates_doc([])))
    rc = main(_argv(spath, ["--candidates", str(tmp_path)]),
              resolver=_resolver, transport=_clean_transport())
    captured = capsys.readouterr()
    assert rc != 0
    assert "run dir" in captured.err


def test_empty_candidates_falls_back_to_blackbox(tmp_path, capsys):
    spath = _write(tmp_path, _plantable_get_session())
    cpath = _write(tmp_path, _candidates_doc([]), name="candidates.json")
    rc = main(_argv(spath, ["--candidates", cpath, "--raw-only"]),
              resolver=_resolver, transport=_clean_transport())
    captured = capsys.readouterr()
    assert rc == 0
    assert "black-box" in captured.err
    doc = json.loads(captured.out)
    assert doc["oss"]["fell_back"] is True
    assert doc["oss"]["candidate_verdicts"] == []
    assert doc["flow"] == []  # clean black-box run


def test_all_unmapable_renders_verdicts_exit_zero(tmp_path, capsys):
    spath = _write(tmp_path, _plantable_get_session())
    cands = _candidates_doc([_cand("cand-x", "get /never-recorded")])
    cpath = _write(tmp_path, cands, name="candidates.json")
    rc = main(_argv(spath, ["--candidates", cpath]),
              resolver=_resolver, transport=_clean_transport())
    captured = capsys.readouterr()
    assert rc == 0
    doc = json.loads(captured.out)
    v = doc["oss"]["candidate_verdicts"][0]
    assert v["verdict"] == "unmapable"
    assert "no recorded request" in v["reason"]


def test_all_gated_mapped_renders_unexercised_not_fail(tmp_path, capsys):
    session = _plantable_get_session()
    session["recorded_requests"] = [{
        "method": "POST", "url": "https://app.example.com/x?q=1",
        "headers": [], "body": None,
    }]
    spath = _write(tmp_path, session)
    cpath = _write(tmp_path, _candidates_doc([_cand("cand-x", "route /x")]),
                   name="candidates.json")
    rc = main(_argv(spath, ["--candidates", cpath]),
              resolver=_resolver, transport=_clean_transport())
    captured = capsys.readouterr()
    assert rc == 0
    doc = json.loads(captured.out)
    v = doc["oss"]["candidate_verdicts"][0]
    assert v["verdict"] == "unexercised"
    assert v["reason"] == "mutating_gate"


def test_candidates_empty_string_fails_closed(tmp_path, capsys):
    """--candidates "" is operator error, not 'flag absent': it must fail
    closed rather than silently widening to a black-box sweep."""
    spath = _write(tmp_path, _plantable_get_session())
    rc = main(_argv(spath, ["--candidates", ""]),
              resolver=_resolver, transport=_clean_transport())
    assert rc != 0
    assert "candidates" in capsys.readouterr().err


def test_blackbox_json_omits_oss_block(tmp_path, capsys):
    spath = _write(tmp_path, _plantable_get_session())
    rc = main(_argv(spath, ["--raw-only"]),
              resolver=_resolver, transport=_clean_transport())
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert "oss" not in doc


def test_binds_without_candidates_fails(tmp_path, capsys):
    spath = _write(tmp_path, _plantable_get_session())
    bpath = _write(tmp_path, {"cand-1": {"request_index": 0}},
                   name="binds.json")
    rc = main(_argv(spath, ["--binds", bpath]),
              resolver=_resolver, transport=_clean_transport())
    assert rc != 0
    assert "candidates" in capsys.readouterr().err


def test_binds_unknown_candidate_fails_closed(tmp_path, capsys):
    spath = _write(tmp_path, _plantable_get_session())
    cpath = _write(tmp_path,
                   _candidates_doc([_cand("cand-a", "get /ping")]),
                   name="candidates.json")
    bpath = _write(tmp_path, {"cand-ghost": {"request_index": 0}},
                   name="binds.json")
    rc = main(_argv(spath, ["--candidates", cpath, "--binds", bpath]),
              resolver=_resolver, transport=_clean_transport())
    assert rc != 0
    assert "unknown" in capsys.readouterr().err


def test_binds_bad_index_fails_closed(tmp_path, capsys):
    spath = _write(tmp_path, _plantable_get_session())
    cpath = _write(tmp_path,
                   _candidates_doc([_cand("cand-a", "get /ping")]),
                   name="candidates.json")
    bpath = _write(tmp_path, {"cand-a": {"request_index": 99}},
                   name="binds.json")
    rc = main(_argv(spath, ["--candidates", cpath, "--binds", bpath]),
              resolver=_resolver, transport=_clean_transport())
    assert rc != 0
    assert "outside" in capsys.readouterr().err


def test_bad_predicted_surface_fails_closed(tmp_path, capsys):
    spath = _write(tmp_path, _plantable_get_session())
    cpath = _write(tmp_path,
                   _candidates_doc([_cand("cand-a", "get /ping")]),
                   name="candidates.json")
    rc = main(_argv(spath, ["--candidates", cpath,
                            "--predicted-surface", "cookie:1"]),
              resolver=_resolver, transport=_clean_transport())
    assert rc != 0
    assert "predicted" in capsys.readouterr().err


# --- U11 egress dispatch (additive) -----------------------------------------


def test_egress_dispatches_to_egress_entry(capsys):
    with pytest.raises(SystemExit) as e:
        main(["egress", "--help"])
    assert e.value.code == 0
    out = capsys.readouterr().out
    assert "--advertise" in out and "--session" not in out


def test_egress_dispatch_reads_sys_argv_when_argv_is_none(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["dyetrace", "egress", "--help"])
    with pytest.raises(SystemExit) as e:
        main()
    assert e.value.code == 0
    assert "--advertise" in capsys.readouterr().out


def test_session_value_egress_is_not_a_subcommand(tmp_path, capsys):
    rc = main(["--session", "egress", "--host", "app.example.com"])
    assert rc == 2
    assert "session error" in capsys.readouterr().err


def test_top_level_help_unchanged_by_egress(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--help"])
    assert e.value.code == 0
    assert "--session" in capsys.readouterr().out
