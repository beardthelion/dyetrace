# Dye: black-box dataflow tracer for bug bounty

## Problem

Source-code taint tools (jevsec) cannot see the flow of data through a target
you do not have source for. Most HackerOne programs are black box. The
stored, second-order, and cross-context classes (stored XSS, data leaking into
admin views, PDF/email templates, logs, other users' sessions) are exactly the
classes a code-blind scan misses, and they are where most payouts live.

Treat the application as a closed system of pipes. Inject a unique tracer
(dye) into every input. Crawl the system and watch where each tracer
resurfaces. A tracer that surfaces in a context it should never reach is a
leak, and that leak is the finding.

## Core design

The verdict is binary and deterministic, same discipline as jevsec's
MAC-bound canary: a given tracer either resurfaced in a given context or it
did not. No heuristics, no scoring.

### Tracer format

Each injected value is unique and self-identifying:

    DYE-<run_id>-<entry_id>-<nonce>

- `run_id`: one sweep.
- `entry_id`: which entry point this tracer was planted in (field, header,
  path segment, filename, JSON key). The entry_id maps back to a recorded
  request so a hit names its own source.
- `nonce`: random, so two plantings of the same field never collide.

Optional HMAC suffix keyed per run so a tracer found in the wild is provably
ours and not attacker-controlled noise. Reuse jevsec's marker code.

Tracers are also emitted in context-sensitive encodings so a hit tells you the
sink's escaping behavior:
- raw `DYE-...`
- an HTML-breaking variant (`"><dye id=...>`) to catch unencoded HTML sinks
- a JS-string-breaking variant
- an attribute-breaking variant
A raw hit is a tracked leak. A markup-breaking hit is likely injection
(stored XSS or template injection), flagged at higher severity.

### Pipeline

1. **Capture.** Load a recorded authenticated session (cookies, tokens,
   headers) from a file. Capture is a separate one-time step; it can be a
   desktop browser recording or a scripted/API login. Everything after this
   runs headless.

2. **Plant.** Replay each recorded request with a fresh tracer substituted
   into every writable parameter: form fields, JSON values, query params,
   path segments, custom headers, filenames, multipart bodies. Record the
   entry_id -> request mapping.

3. **Propagate.** Trigger the app to move the data: re-fetch the planted
   resource, list views, exports, search, any endpoint that renders stored
   content. Where a second identity exists (admin, other user), fetch the
   same surfaces as that identity.

4. **Observe.** Grep every response body, header, rendered page, and
   downloadable artifact (HTML, JSON, PDF via text extraction, CSV, emails
   captured through a test mailbox) for any tracer.

5. **Verdict.** For each hit: tracer's entry_id (where it came from), the
   sink URL and identity (where it surfaced), the encoding variant (whether
   it was escaped), and whether sink identity differs from source identity
   (cross-context = access-control-flavored leak). Emit one row per hit.

### Output

A flow table, one row per resurfacing:

    entry_id | source request | sink url | sink identity | encoding | cross-context? | severity

Plus a findings bucket: markup-breaking hits and cross-context hits promoted
to candidate findings with a reproducible request pair attached.

## Scope and safety

- Only plants into inputs observed in the recorded session. Never invents
  endpoints or parameters. Empty input list means stop, same rule as
  scope-boundary.
- Dummy, clearly-marked tracer data only. No destructive payloads; the
  markup-breaking variants are inert markers, not live exploit code.
- Rate limited and scoped to one target host allowlist per run.
- Runs fully headless on a VPS after the session file exists.

## Build notes

- Python, `httpx` for the replay engine; optional Playwright headless only
  for JS-only apps that will not render via plain HTTP.
- Session file format: a portable JSON of cookies + auth headers + base URL,
  exportable from a browser recording or written by a login script.
- Reuse jevsec's marker/HMAC module directly.
- PDF/doc sinks: poppler text extraction.
- Email sinks: point a test mailbox (AgentMail-style) as the app's contact
  address and grep delivered messages.

## Out of scope for v1

- Automatic crawling/spidering beyond replaying recorded requests. v1
  propagates only through surfaces reachable from the recorded session plus a
  second identity's view of the same surfaces. Full autonomous crawl is a
  later addition.
- Race conditions and IDOR enumeration. Those are sibling tools (differential
  replay, race harness) that can share the replay engine later.

## Sibling mode: source-available targets

Black-box mode is for targets without source. When the target is open source
(or you otherwise have the code), use dye as the runtime verifier on top of
jevsec candidates instead of planting into every observed input. That mode
is specified in [SPEC-OSS.md](SPEC-OSS.md).
