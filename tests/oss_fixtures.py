"""Shared jevsec-candidate fixture builders for the OSS-mode test suites.

One definition of the candidates.json dict shape (dict form, for the loader
and CLI layers) and of the typed Candidate records (for the mapper and verdict
layers), so a schema-shape change is a single edit.
"""

from dyetrace.candidates import Candidate, CandidateEntry, CandidateSink


def candidates_doc(cands):
    """A minimal but schema-valid jevsec candidates.json document."""
    return {
        "version": 1,
        "root": "/repo",
        "limits": {"maxDepth": 6, "maxCandidates": 200, "enumerateLimit": 100},
        "stats": {"enumerated": len(cands), "sanitized": 0,
                  "kept": len(cands), "truncated": False},
        "candidates": cands,
    }


def candidate_dict(cid="cand-aaa111", detail="get /report", kind="route",
                   efile="a.py", eline=1, callee="os.system",
                   sclass="code-exec", sfile="b.py", sline=2, rank=1):
    """One candidates.json entry as the raw dict."""
    return {
        "id": cid,
        "entry": {
            "node": {"id": "fn:h", "kind": "function", "name": "h",
                     "file": efile, "line": eline},
            "kind": kind,
            "detail": detail,
            "site": {"file": efile, "line": eline},
        },
        "hops": [],
        "crossings": [],
        "branchPoints": 0,
        "sink": {
            "node": None,
            "callee": callee,
            "sinkClass": sclass,
            "site": {"file": sfile, "line": sline},
        },
        "score": 1.0,
        "rank": rank,
    }


def candidate(cid="cand-1", detail="get /x", kind="route",
              sink_class="code-exec"):
    """One candidates.json entry as the typed record the loader produces."""
    return Candidate(
        id=cid,
        entry=CandidateEntry(kind=kind, detail=detail, site_file="a.py",
                             site_line=1, node_name="h"),
        sink=CandidateSink(callee="os.system", sink_class=sink_class,
                           site_file="b.py", site_line=2),
        rank=1,
    )


def _bind_obj(candidate_id, request_index, path_id=None, predicted=None):
    """A raw OperatorBind for verdict/mapper tests."""
    from dyetrace.binds import OperatorBind
    return OperatorBind(candidate_id, request_index, path_id, predicted)
