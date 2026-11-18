"""Marker core: build, encode, and verify self-identifying tracers.

Design origin: jevsec's MAC-bound canary marker (no code copied).

Self-contained and stdlib-only on purpose, so it can be audited in
isolation. A tracer is

    DYE-<run_id>-<entry_id>-<nonce>-<mac>

where run_id, entry_id, and nonce are lowercase dash-free hex, and mac is a
lowercase hex SHA-256 HMAC computed over the "DYE-<run_id>-<entry_id>-<nonce>"
prefix with a per-run key that dyetrace generates and never puts on the wire.
Every run mints a key and every verdict authenticates by recomputation; there
is no no-HMAC mode.
"""

import secrets
import hmac
import hashlib


# Fields are lowercase hex so no crafted value can carry the "-" delimiter and
# forge the parse. The MAC is 64 lowercase hex chars (SHA-256).
_HEXCHARS = frozenset("0123456789abcdef")
_TOKENCHARS = _HEXCHARS | frozenset("DYE-")
_MAC_LEN = 64

# Encoding variants, raw plus three inert markup-breaking wrappers. Each wraps
# the full canonical token verbatim so the token is recoverable from a hit.
VARIANTS = ("raw", "html", "js", "attr")


def _is_hex(value):
    """True when value is a non-empty string of lowercase hex digits."""
    return (
        isinstance(value, str)
        and len(value) > 0
        and all(c in _HEXCHARS for c in value)
    )


def _is_mac(value):
    """True when value is exactly 64 lowercase hex digits."""
    return len(value) == _MAC_LEN and all(c in _HEXCHARS for c in value)


def mint_key():
    """Mint a fresh per-run key. Held by dyetrace, never placed on the wire."""
    return secrets.token_bytes(32)


def new_nonce():
    """A random dash-free lowercase hex nonce, so plantings never collide."""
    return secrets.token_hex(8)


def _canonical_prefix(run_id, entry_id, nonce):
    """Canonical serialization the MAC covers.

    Fixed field order (run_id, entry_id, nonce), a single scheme, and future
    fields would only ever be appended. The fields are dash-free hex, so this
    join is unambiguous and cannot be forged by a crafted field value.
    """
    return "DYE-" + run_id + "-" + entry_id + "-" + nonce


def _mac(key, run_id, entry_id, nonce):
    msg = _canonical_prefix(run_id, entry_id, nonce).encode("ascii")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def build_token(key, run_id, entry_id, nonce):
    """Build the canonical tracer token, binding the HMAC suffix.

    Raises ValueError if any field is not lowercase dash-free hex.
    """
    for name, value in (("run_id", run_id), ("entry_id", entry_id), ("nonce", nonce)):
        if not _is_hex(value):
            raise ValueError("%s must be non-empty lowercase hex, got %r" % (name, value))
    mac = _mac(key, run_id, entry_id, nonce)
    return _canonical_prefix(run_id, entry_id, nonce) + "-" + mac


def _wrap(variant, token):
    """Wrap a token in an inert, markup-breaking payload for one variant.

    Each wrapper closes a sink context and then carries the token inside an
    inert marker. The character right after the token is never a token
    character, so extract_token stops cleanly at the token boundary.
    """
    if variant == "raw":
        return token
    if variant == "html":
        # Break out of an attribute/tag and open an inert <dye> element.
        return '"><dye t=' + token + ">"
    if variant == "js":
        # Break out of a JS string and assign into an inert variable.
        return "';dye=" + token + ";'"
    if variant == "attr":
        # Break out of an attribute value and add an inert attribute.
        return '" dye=' + token + ' x="'
    raise ValueError("unknown variant %r" % variant)


def build_variants(key, run_id, entry_id, nonce, raw_only=False):
    """Build the planted tracers for one site.

    Returns a list of {"variant", "payload"} records. Each record is tagged
    with its encoding variant id (raw, html, js, attr). raw_only suppresses the
    three markup-breaking variants but never the HMAC: the raw payload still
    carries the full MAC-bound token.
    """
    token = build_token(key, run_id, entry_id, nonce)
    names = ("raw",) if raw_only else VARIANTS
    return [{"variant": v, "payload": _wrap(v, token)} for v in names]


def parse(candidate):
    """Structural pre-check then split a candidate into fields.

    Returns a dict with run_id, entry_id, nonce, mac when candidate is a
    well-formed canonical token, otherwise None. Never raises on bad input.
    """
    if not isinstance(candidate, str):
        return None
    parts = candidate.split("-")
    if len(parts) != 5:
        return None
    tag, run_id, entry_id, nonce, mac = parts
    if tag != "DYE":
        return None
    if not (_is_hex(run_id) and _is_hex(entry_id) and _is_hex(nonce)):
        return None
    if not _is_mac(mac):
        return None
    return {"run_id": run_id, "entry_id": entry_id, "nonce": nonce, "mac": mac}


def extract_token(payload):
    """Recover the embedded canonical token from a variant payload.

    Scans from the first "DYE-" over the maximal run of token characters, then
    confirms the run is a well-formed token. Returns the token string, or None
    when no parseable token is embedded.
    """
    if not isinstance(payload, str):
        return None
    start = payload.find("DYE-")
    if start == -1:
        return None
    end = start
    n = len(payload)
    while end < n and payload[end] in _TOKENCHARS:
        end += 1
    candidate = payload[start:end]
    return candidate if parse(candidate) is not None else None


def verify(candidate, key):
    """Authenticate a candidate token by recomputing its HMAC.

    Structural pre-check (shape plus MAC charset) first, then compare the
    recorded MAC against the recomputed one with hmac.compare_digest. Returns
    True only for a token that both parses and authenticates under key.
    """
    parsed = parse(candidate)
    if parsed is None:
        return False
    expected = _mac(key, parsed["run_id"], parsed["entry_id"], parsed["nonce"])
    return hmac.compare_digest(parsed["mac"], expected)
