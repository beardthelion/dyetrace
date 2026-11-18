#!/usr/bin/env python3
"""Convert a HAR capture into a dyetrace session JSON.

Local loopback captures only by default: every request host must be a
loopback literal (localhost / 127.0.0.0/8 / ::1) unless --allow-remote is
passed. The tool does not run a proxy; it converts an already-recorded HAR.

Usage:
    python tools/session_from_har.py capture.har [-o session.json]
    python tools/session_from_har.py capture.har --allow-remote
"""

import argparse
import ipaddress
import json
import sys
from urllib.parse import urlsplit, urlencode


def _fail(msg):
    print(f"session_from_har: {msg}", file=sys.stderr)
    return 2


def _is_loopback_host(host: str) -> bool:
    host = host.lower().strip("[]")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _body_for(entry_req):
    post = entry_req.get("postData")
    if not post:
        return None
    mime = post.get("mimeType") or "application/octet-stream"
    text = post.get("text")
    if text is not None:
        return {"content_type": mime, "encoding": "text", "data": text}
    params = post.get("params") or []
    if params:
        data = urlencode(
            [(p.get("name", ""), p.get("value", "")) for p in params]
        )
        return {
            "content_type": "application/x-www-form-urlencoded",
            "encoding": "text",
            "data": data,
        }
    return None


def convert(har, *, allow_remote=False):
    entries = har.get("log", {}).get("entries", [])
    if not entries:
        raise ValueError("HAR has no log.entries")
    requests = []
    cookies = {}
    for i, e in enumerate(entries):
        req = e.get("request", {})
        method, url = req.get("method"), req.get("url")
        if not method or not url:
            raise ValueError(f"log.entries[{i}]: request missing method or url")
        host = urlsplit(url).hostname or ""
        if not allow_remote and not _is_loopback_host(host):
            raise ValueError(
                f"log.entries[{i}]: non-loopback host {host!r} refused "
                "(--allow-remote overrides)"
            )
        requests.append({
            "method": method,
            "url": url,
            "headers": [
                [h["name"], h["value"]]
                for h in req.get("headers", [])
                if h.get("name") and h.get("value") is not None
            ],
            "body": _body_for(req),
        })
        for c in req.get("cookies", []):
            if c.get("name"):
                cookies[c["name"]] = c.get("value", "")
    base_url = f"{urlsplit(requests[0]['url']).scheme}://{urlsplit(requests[0]['url']).netloc}"
    return {
        "version": "1",
        "cookies": cookies,
        "auth_headers": {},
        "base_url": base_url,
        "recorded_requests": requests,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("har", help="path to the HAR capture")
    ap.add_argument("-o", "--out", help="output session JSON path (default stdout)")
    ap.add_argument("--allow-remote", action="store_true",
                    help="permit non-loopback request hosts")
    args = ap.parse_args(argv)
    try:
        har = json.load(open(args.har, encoding="utf-8"))
        session = convert(har, allow_remote=args.allow_remote)
    except (OSError, json.JSONDecodeError, ValueError, KeyError) as exc:
        return _fail(str(exc))
    text = json.dumps(session, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
