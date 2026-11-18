"""Tests for U8 egress report and evidence pack (R12, KTD3, KTD5, KTD12).

Pure unit tests: EgressVerdictReport / Hit / SendRecord / ListenerSnapshot are
fabricated by hand, no sockets. The masking exception (the evidence token and
request path inside the PROVEN evidence field) is exercised in both directions,
and every surface is fed hostile strings.
"""

import html as htmllib
import json

import pytest

from dyetrace import egressdrive as D
from dyetrace import egressreport as R
from dyetrace import egressverdict as V
from dyetrace.egresscand import EgressCandidate
from dyetrace.listener import Hit, ListenerSnapshot

RUN = "abc123"
SURFACES = ("terminal", "html", "json")
NOTE = "probe --active from target env reached 10.0.0.5:9000"
SECRET = "Bearer sk9Zq8Wx7Vc6Bn5Mm4Lk3Jh2Gf1Dd0Ss"
SECRET_BARE = "sk9Zq8Wx7Vc6Bn5Mm4Lk3Jh2Gf1Dd0Ss"
EID = "1"
TOKEN = "DYE-%s-%s-n-%s" % (RUN, EID, "a1" * 32)


def cand(cid="c1", **kw):
    base = dict(
        id=cid, source_tool="ssrf-guard-audit", source_version="1.2", file="src/a.py",
        start_line=1, end_line=2, symbol="fetch", site_label=None, param_names=("url",),
        params_truncated=False, sinks=(), guard_classes=(), destination_kind=None,
        lead=False, tool_name=None, arg_name=None,
    )
    base.update(kw)
    return EgressCandidate(**base)


def send(i=0, ids=("c1",), arguments=None, outcome="result", cls="public", token=TOKEN,
         url="http://203.0.113.9:9000/" + TOKEN, tool="fetch", arg="url"):
    return D.SendRecord(
        index=i, tool=tool, argument=arg, candidate_ids=tuple(ids), outcome=outcome,
        arguments=arguments if arguments is not None else {arg: url},
        entry_id=str(i + 1), nonce="n", token=token, url=url, address_class=cls,
        advertised_host="203.0.113.9", advertised_port=9000, window_start=1.0,
        window_end=6.0,
    )


def hit(target="/" + TOKEN, headers=(("Host", "203.0.113.9:9000"),), token=TOKEN,
        eid="1", idx=1):
    return Hit(
        entry_id=eid, nonce="n", token=token, method="GET", target=target,
        headers=tuple(headers), source=("198.51.100.7", 40000), wall=1700000000.5,
        offset=2.5, arrival_index=idx,
    )


def att(note=NOTE):
    return V.Attestation(note, "203.0.113.9", 9000, 9100)


def verdict(c, kind, send_rec=None, hits=(), reason=None, note=None, attestation=None, i=0):
    return V.EgressVerdict(candidate=c, verdict=kind, reason=reason, note=note,
                           credited_hits=tuple(hits), send=send_rec,
                           attestation=attestation, input_index=i)


def report_of(verdicts, hits=(), complete=True, incomplete_reason=None, attestation=None,
              anomalies=(), stop_reason=None, stop_detail=""):
    counts = {}
    for v in verdicts:
        counts[v.verdict] = counts.get(v.verdict, 0) + 1
    return V.EgressVerdictReport(
        verdicts=list(verdicts), complete=complete, incomplete_reason=incomplete_reason,
        counts=counts, hits=tuple(hits), anomalies=tuple(anomalies),
        attestation=attestation, settle=5.0, drain=5.0,
        source_tools=(("ssrf-guard-audit", "1.2"),), stop_reason=stop_reason,
        stop_detail=stop_detail,
    )


def snap(**kw):
    base = dict(
        verified_hits=(), arrival_counts={}, verified_dropped=0, noise_count=7,
        noise_samples=(), refused_count=3, refused_offsets=(), deadline_close_count=2,
        deadline_close_offsets=(), unattributed_count=1, unattributed_offsets=(),
        offsets_truncated=False, oversize_closed=0, malformed_closed=0, peak_connections=4,
        active_connections=0, health="ok",
    )
    base.update(kw)
    return ListenerSnapshot(**base)


def proven_report(**sendkw):
    s = send(**sendkw)
    h = hit()
    return report_of([verdict(cand(), V.VERDICT_PROVEN, s, [h])], hits=[h])


def render(rep, surface, **kw):
    kw.setdefault("advertised", "http://203.0.113.9:9000/base")
    kw.setdefault("bind_addr", "127.0.0.1:9100")
    kw.setdefault("target_commit", "deadbeef")
    kw.setdefault("snapshot", snap())
    return R.render(rep, surface=surface, **kw)


def jdoc(rep, **kw):
    return json.loads(render(rep, "json", **kw))


# --- happy: evidence pack unmasked, elsewhere masked -------------------------


@pytest.mark.parametrize("surface", SURFACES)
def test_proven_pack_has_full_token_and_request_path(surface):
    out = render(proven_report(), surface)
    assert TOKEN in out
    assert "/" + TOKEN in out


def test_json_token_unmasked_in_evidence_field_only():
    d = jdoc(proven_report())
    pack = d["evidence"][0]
    assert pack["evidence"]["token"] == TOKEN
    assert pack["evidence"]["arrivals"][0]["request_path"] == "/" + TOKEN
    row = d["verdicts"][0]
    assert TOKEN not in row["url"]
    assert "***" in row["url"]
    flat = d["hits"][0]
    assert TOKEN not in json.dumps(flat)
    # the only places the full token appears: evidence pack (token, path,
    # reproduction argument), nothing in verdict rows or the flat hit list
    assert TOKEN not in json.dumps(d["verdicts"])
    assert TOKEN not in json.dumps(d["hits"])


@pytest.mark.parametrize("surface", ("terminal", "html"))
def test_token_masked_in_generic_url_field(surface):
    # no PROVEN verdict: the token only reaches the report via a generic URL
    s = send(outcome="result")
    rep = report_of([verdict(cand(), V.VERDICT_UNEXERCISED, s, reason="x")])
    out = render(rep, surface)
    assert TOKEN not in out


def test_flat_hit_list_masks_token_and_target():
    d = jdoc(proven_report())
    h = d["hits"][0]
    assert h["token"] == "***"
    assert TOKEN not in h["target"]
    assert h["credited_to"] == ["c1"]


# --- attestation -----------------------------------------------------------


@pytest.mark.parametrize("surface", SURFACES)
def test_attestation_labeled_with_endpoint_beside_it(surface):
    s = send(outcome="result", cls="public")
    v = verdict(cand(), V.VERDICT_KILL, s, reason=V.REASON_NO_ARRIVAL, attestation=att())
    rep = report_of([v], attestation=att())
    out = render(rep, surface)
    assert "operator-asserted, unverified" in out
    assert "203.0.113.9:9000" in out
    assert "9100" in out
    assert NOTE in out or htmllib.escape(NOTE) in out


def test_verdict_that_used_attestation_names_it_json():
    s = send()
    v = verdict(cand(), V.VERDICT_KILL, s, reason=V.REASON_NO_ARRIVAL, attestation=att())
    d = jdoc(report_of([v], attestation=att()))
    a = d["verdicts"][0]["attestation"]
    assert a["label"] == "operator-asserted, unverified"
    assert a["advertised"] == "203.0.113.9:9000"
    assert a["bound_port"] == 9100
    assert d["reporting"]["attestation"]["label"] == "operator-asserted, unverified"


@pytest.mark.parametrize("surface", ("terminal", "html"))
def test_verdict_row_names_attestation(surface):
    s = send()
    v = verdict(cand(), V.VERDICT_KILL, s, reason=V.REASON_NO_ARRIVAL, attestation=att())
    out = render(report_of([v], attestation=att()), surface)
    # the row itself, not only the reporting block, carries the label
    row = [ln for ln in out.splitlines() if "no_arrival_observed" in ln][0]
    assert "operator-asserted, unverified" in row


def test_no_attestation_reported_as_none():
    d = jdoc(report_of([verdict(cand(), V.VERDICT_UNMAPABLE, reason="no tool")]))
    assert d["reporting"]["attestation"] is None


# --- hostile strings ---------------------------------------------------------

HOSTILE = "\x1b[31mRED\x1b[0m\x07\x85<script>alert(1)</script>\r\nINJECT: x"


def hostile_report():
    h = hit(target="/p" + HOSTILE, headers=(("User-Agent", HOSTILE), ("X-" + "A" * 3, HOSTILE)))
    s = send(url="http://203.0.113.9:9000/q" + HOSTILE, tool="t" + HOSTILE,
             arg="a" + HOSTILE)
    c = cand(cid="id" + HOSTILE, file="f" + HOSTILE + ".py", symbol="sym" + HOSTILE,
             site_label="site" + HOSTILE)
    v = verdict(c, V.VERDICT_PROVEN, s, [h], note="n" + HOSTILE,
                attestation=V.Attestation(HOSTILE, "h" + HOSTILE, 9000, 9100))
    u = verdict(cand("u1"), V.VERDICT_UNMAPABLE, reason="r" + HOSTILE, i=1)
    return report_of([v, u], hits=[h], attestation=V.Attestation(HOSTILE, "h", 9000, 9100),
                     stop_reason="s" + HOSTILE, stop_detail="d" + HOSTILE,
                     complete=False, incomplete_reason="i" + HOSTILE)


def test_hostile_terminal_stripped():
    out = render(hostile_report(), "terminal", advertised="http://h/" + HOSTILE,
                 target_commit="c" + HOSTILE, adapter_limits=("l" + HOSTILE,))
    assert "\x1b" not in out
    for ch in "\x07\x85\r":
        assert ch not in out
    # no injected line may start with the attacker's text
    assert not any(ln.startswith("INJECT") for ln in out.splitlines())


def test_hostile_html_entity_encoded():
    out = render(hostile_report(), "html", advertised="http://h/" + HOSTILE,
                 target_commit="c" + HOSTILE, adapter_limits=("l" + HOSTILE,))
    assert "<script>" not in out
    assert "&lt;script&gt;" in out

    assert "alert(1)</script>" not in out


def test_hostile_json_faithful():
    out = render(hostile_report(), "json", target_commit="c" + HOSTILE,
                 adapter_limits=("l" + HOSTILE,))
    d = json.loads(out)
    pack = d["evidence"][0]
    assert pack["evidence"]["arrivals"][0]["request_path"] == "/p" + HOSTILE
    assert pack["evidence"]["arrivals"][0]["headers"][0][1] == HOSTILE
    assert d["reporting"]["attestation"]["note"] == HOSTILE
    assert d["reporting"]["target_commit"] == "c" + HOSTILE
    assert d["verdicts"][1]["reason"] == "r" + HOSTILE


def test_userinfo_dropped_in_urls():
    s = send(url="http://user:pw@203.0.113.9:9000/x")
    rep = report_of([verdict(cand(), V.VERDICT_UNEXERCISED, s, reason="x")])
    for surface in SURFACES:
        out = render(rep, surface, advertised="http://u:p4ss@203.0.113.9:9000/b")
        assert "p4ss" not in out and "user:pw" not in out


@pytest.mark.parametrize("surface", SURFACES)
def test_secret_shaped_candidate_id_and_file_masked(surface):
    sec = "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8"
    c = cand(cid=sec, file="src/" + sec + "/x.py", symbol=sec)
    rep = report_of([verdict(c, V.VERDICT_UNMAPABLE, reason="no tool " + sec)])
    out = render(rep, surface)
    assert sec not in out
    assert "***" in out


# --- static argument masking -------------------------------------------------


def static_report():
    args = {"url": "http://203.0.113.9:9000/" + TOKEN, "auth": SECRET,
            "nested": {"h": ["x", SECRET_BARE]}, "n": 3,
            "dest": "https://api.example.com/v1/" + SECRET_BARE + "?k=" + SECRET_BARE}
    s = send(arguments=args)
    h = hit()
    return report_of([verdict(cand(), V.VERDICT_PROVEN, s, [h])], hits=[h])


@pytest.mark.parametrize("surface", SURFACES)
def test_static_secret_argument_masked_tracer_arg_full(surface):
    out = render(static_report(), surface)
    assert SECRET_BARE not in out
    assert TOKEN in out


def test_static_masking_in_reproduction_object_json():
    d = jdoc(static_report())
    repro = d["evidence"][0]["reproduction"]
    assert repro["tool"] == "fetch"
    a = repro["arguments"]
    assert a["url"] == "http://203.0.113.9:9000/" + TOKEN
    assert a["auth"] != SECRET and SECRET_BARE not in a["auth"]
    assert a["n"] == 3
    assert SECRET_BARE not in json.dumps(a)


@pytest.mark.parametrize("surface", SURFACES)
@pytest.mark.parametrize("static", [
    "k=" + SECRET_BARE + "://x",
    "Bearer:" + SECRET_BARE + "://",
    "x," + SECRET_BARE + "://y/z",
])
def test_static_value_that_only_looks_like_a_url_is_still_masked(surface, static):
    args = {"url": "http://203.0.113.9:9000/" + TOKEN, "note": static}
    h = hit()
    rep = report_of([verdict(cand(), V.VERDICT_PROVEN, send(arguments=args), [h])], hits=[h])
    assert SECRET_BARE not in render(rep, surface)


# --- INCOMPLETE and clean ----------------------------------------------------


@pytest.mark.parametrize("surface", SURFACES)
def test_incomplete_banner_everywhere(surface):
    s = send(outcome="not_called", token=None)
    rep = report_of([verdict(cand(), V.VERDICT_UNEXERCISED, s, reason="run_incomplete")],
                    complete=False, incomplete_reason="listener_failed",
                    stop_reason="listener_failed", stop_detail="lost socket")
    out = render(rep, surface)
    assert "INCOMPLETE" in out
    assert "listener_failed" in out
    assert "no exit path proven" not in out
    assert "A path not reported is not cleared." in out


def test_incomplete_json_flags():
    rep = report_of([], complete=False, incomplete_reason="x")
    d = jdoc(rep)
    assert d["complete"] is False
    assert d["status"] == "incomplete"
    assert "INCOMPLETE" in d["summary"]


@pytest.mark.parametrize("surface", SURFACES)
def test_clean_zero_proven_labeled_and_not_cleared(surface):
    s = send(cls="public")
    v = verdict(cand(), V.VERDICT_KILL, s, reason=V.REASON_NO_ARRIVAL, attestation=att())
    out = render(report_of([v], attestation=att()), surface)
    assert "completed, no exit path proven" in out
    assert "A path not reported is not cleared." in out
    assert "INCOMPLETE" not in out


@pytest.mark.parametrize("surface", SURFACES)
def test_limits_note_http_only_and_replay_caveat(surface):
    out = render(proven_report(), surface)
    low = out.lower()
    assert "http only" in low
    assert "https" in low and "untested" in low
    assert "replay" in low
    assert "no arrival was observed in this harness" in low


# --- reporting block ---------------------------------------------------------


def test_reporting_block_fields_json():
    d = jdoc(proven_report(), adapter_limits=("analysis_incomplete",))
    r = d["reporting"]
    assert r["dyetrace_version"]
    assert r["target_commit"] == "deadbeef"
    assert r["source_tools"] == [{"tool": "ssrf-guard-audit", "version": "1.2"}]
    assert r["advertised"] == "http://203.0.113.9:9000/base"
    assert r["bind"] == "127.0.0.1:9100"
    assert r["settle"] == 5.0 and r["drain"] == 5.0
    assert r["adapter_limits"] == ["analysis_incomplete"]
    assert d["not_cleared"] == "A path not reported is not cleared."


def test_noise_and_refused_counts():
    d = jdoc(proven_report())
    n = d["noise"]
    assert n["noise_count"] == 7 and n["refused_count"] == 3
    assert n["deadline_close_count"] == 2 and n["unattributed_count"] == 1


def test_no_snapshot_noise_null():
    d = jdoc(proven_report(), snapshot=None)
    assert d["noise"] is None


# --- coverage ----------------------------------------------------------------


def mixed_report():
    c1, c2, c3, c4 = cand("c1"), cand("c2"), cand("c3"), cand("c4")
    s1 = send(0, ids=("c1",))
    s2 = send(1, ids=("c2",), cls="public")
    s3 = send(2, ids=("c3",), outcome="not_called", token=None)
    h = hit()
    return report_of([
        verdict(c1, V.VERDICT_PROVEN, s1, [h], i=0),
        verdict(c2, V.VERDICT_KILL, s2, reason=V.REASON_NO_ARRIVAL, attestation=att(), i=1),
        verdict(c3, V.VERDICT_UNEXERCISED, s3, reason="not_called", i=2),
        verdict(c4, V.VERDICT_UNMAPABLE, reason="no tool", i=3),
    ], hits=[h])


def test_coverage_block_matches_table():
    d = jdoc(mixed_report())
    cov = d["coverage"]
    assert cov["counts"] == {V.VERDICT_PROVEN: 1, V.VERDICT_NEW_FLOW: 0,
                             V.VERDICT_KILL: 1, V.VERDICT_UNEXERCISED: 1,
                             V.VERDICT_UNMAPABLE: 1}
    assert cov["total"] == 4
    assert cov["exercised"] == 2
    assert cov["fraction_exercised"] == 0.5
    rows = [v["verdict"] for v in d["verdicts"]]
    for name, n in cov["counts"].items():
        assert rows.count(name) == n


def test_coverage_function_exposed_for_exit_codes():
    cov = R.coverage(mixed_report())
    assert cov["counts"][V.VERDICT_PROVEN] == 1
    assert cov["total"] == 4


def test_coverage_empty_is_zero_not_error():
    cov = R.coverage(report_of([]))
    assert cov["total"] == 0 and cov["fraction_exercised"] == 0.0


def test_unknown_surface_rejected():
    with pytest.raises(ValueError):
        R.render(proven_report(), surface="pdf")


def test_json_keys_stable():
    d = jdoc(proven_report())
    assert set(d) == {"report", "schema", "status", "complete", "incomplete_reason",
                      "stop_reason", "stop_detail", "banner", "summary", "coverage",
                      "verdicts", "evidence", "hits", "anomalies", "noise", "reporting",
                      "not_cleared"}


def test_anomalies_listed_and_masked():
    h = hit(eid="9")
    rep = report_of([], anomalies=[h], complete=False, incomplete_reason="anomalous_verified_token")
    d = jdoc(rep)
    assert d["anomalies"][0]["token"] == "***"
    assert TOKEN not in json.dumps(d["anomalies"])


def test_new_flow_note_rendered():
    s = send(arg="url")
    v = verdict(cand(), V.VERDICT_NEW_FLOW, s, note="fetched argument: other (predicted url)")
    for surface in SURFACES:
        assert "fetched argument: other" in render(report_of([v]), surface)


def test_tool_error_run_is_not_exercised():
    """exercised means verdict PROVEN, new_flow or KILL (the README and CLI exit
    rule); a call that ended in tool_error was made but exercised nothing."""
    c = cand("c1")
    s = send(0, ids=("c1",), outcome="tool_error", token=None)
    rep = report_of([verdict(c, V.VERDICT_UNEXERCISED, s, reason="tool_error", i=0)])
    cov = R.coverage(rep)
    assert cov["exercised"] == 0 and cov["fraction_exercised"] == 0.0
    assert cov["counts"][V.VERDICT_UNEXERCISED] == 1
    assert jdoc(rep)["coverage"]["fraction_exercised"] == 0.0


def test_timeout_run_is_not_exercised():
    c = cand("c1")
    s = send(0, ids=("c1",), outcome="timeout", token=None)
    rep = report_of([verdict(c, V.VERDICT_UNEXERCISED, s, reason="timeout", i=0)])
    assert R.coverage(rep)["exercised"] == 0


def test_new_flow_counts_as_exercised():
    c = cand("c1")
    rep = report_of([verdict(c, V.VERDICT_NEW_FLOW, send(0), [hit()], note="n", i=0)])
    assert R.coverage(rep)["exercised"] == 1


def test_ipv6_advertised_address_is_bracketed_in_report():
    c = cand("c1")
    s = send(0, ids=("c1",))
    a = V.Attestation(NOTE, "2001:db8::1", 9000, 9100)
    rep = report_of([verdict(c, V.VERDICT_KILL, s, reason=V.REASON_NO_ARRIVAL,
                             attestation=a, i=0)], attestation=a)
    text = json.dumps(jdoc(rep))
    assert "[2001:db8::1]:9000" in text
    assert "2001:db8::1:9000" not in text
