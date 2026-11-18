# Dye OSS: runtime verifier for jevsec candidates

Black-box dye (SPEC.md) treats the app as closed pipes and plants into every
observed input. This document is the source-available mode: dye still does the
same plant/propagate/observe/verdict loop, but the plant list and the sink
watchlist come from jevsec instead of from a recorded session alone.

## Problem

On an open-source target you already have code. jevsec reads that code and
lists candidate source-to-sink paths. Those candidates are static: "this
untrusted byte could reach this sink." Static analysis alone is not an
accept-path proof. False positives (dead branches, sanitized mid-path,
sink never hit in a real request) burn triage time, and static tracking
drops flows that leave the analyzer's model (templates, caches, serializers,
background jobs, out-of-process workers).

Dye is the runtime half. Plant a tracer at the predicted source, drive the
request that should carry it, and watch whether it surfaces at the predicted
sink (and anywhere else). A hit is a binary, reproducible flow. That is the
same accept-path standard the harness holds submissions to.

## Relationship to jevsec

| Role | Tool | Question it answers |
|---|---|---|
| Static candidate finder | jevsec | Which source-to-sink paths look reachable in the code? |
| Runtime verifier | dye (this mode) | Did a tracer planted at that source actually surface at that sink (or another unexpected sink)? |

Use them together on OSS. Do not run dye-OSS as a blind plant-everywhere sweep
when jevsec has already ranked the entry points; that reverts to black-box
mode and wastes the static pass. Do not treat a jevsec candidate as proven
without a dye hit (or an equivalent end-to-end PoC).

Dye can also surface flows jevsec missed. After planting at a jevsec source,
observe every response and artifact the black-box pipeline already greps. A
tracer that lands somewhere jevsec did not predict is still a hit; file it as
a new path and feed it back as a jevsec seed if the sink is in-repo.

## What stays the same as black-box

- Tracer format: `DYE-<run_id>-<entry_id>-<nonce>`, optional HMAC via jevsec's
  marker module, context-sensitive encodings (raw / HTML-break / JS-break /
  attribute-break).
- Binary verdict: resurfaced in a given context, or did not. No scoring.
- Safety: dummy tracers only, host allowlist, rate limit, no invented
  endpoints beyond the candidate set plus the recorded session's observed
  surfaces.
- Output shape: flow table row per resurfacing, plus a findings bucket for
  markup-breaking and cross-context hits with a reproducible request pair.

## Pipeline (OSS mode)

1. **Candidates.** Run jevsec on the repo root for the entry point under
   audit (`TAINT: yes` from scope-boundary). Take each in-EP candidate as a
   `(source, predicted_sink)` pair. If jevsec is unavailable or returns 0
   in-EP, stop this mode and fall back to black-box plant-on-session, or to
   a manual taint pass; do not invent sources.

2. **Harness.** Bring the target up locally (or against a scoped staging
   host on the allowlist). Capture or script one authenticated session the
   same way black-box does, so plant and propagate have real cookies/tokens.
   Local / loopback preferred; no public-network spray.

3. **Plant.** For each candidate, issue the request that hits the source
   with a fresh tracer in the untrusted field jevsec named. `entry_id`
   records both the jevsec candidate id and the concrete parameter. Skip
   candidates whose source is not reachable from the session without
   inventing a new route.

4. **Propagate.** Drive the path that should carry data to the predicted
   sink (re-fetch, worker flush, export, second identity) using the same
   rules as black-box propagate. Prefer the minimal trigger that makes the
   predicted sink execute.

5. **Observe.** Grep the predicted sink's response or artifact first. Also
   grep every other response/header/PDF/email the black-box observer already
   covers, so missed static flows still show up.

6. **Verdict.**
   - Hit at predicted sink: PROVEN flow for that jevsec candidate. Attach
     the request pair and the tracer id. This is submission-grade evidence
     for the accept path, not a finding by itself; severity and impact still
     come from what the sink does with the value.
   - Hit at unexpected sink: new flow. Promote to findings bucket and add a
     jevsec seed for the new sink if it is in-repo.
   - No hit after the propagate steps that should have exercised the sink:
     candidate is a static false positive for this harness. Mark KILL for
     dye-OSS; do not debug the app to force a hit.

## Accept-path bar

A dye-OSS PROVEN row means: one crafted or replayed request planted a tracer
at a named source, and that same tracer was observed at a named sink under
a real process. Task-only or log-only sightings that never leave a security
boundary are not PROVEN. Same discipline as black-box and as the harness
`ACCEPT_PATH:e2e` gate.

## Build notes (OSS additions)

- Input: jevsec runs-dir (or a normalized candidate JSON) plus the black-box
  session file.
- Map each candidate's source parameter onto a concrete HTTP/RPC field in
  the session's request templates; if the map cannot be made without
  guessing, skip that candidate and record `unmapable`.
- Prefer driving the local test/app binary over a remote host when the
  repo ships one.
- Reuse the black-box replay engine, observer, and marker/HMAC module. OSS
  mode is a candidate-driven plant list and a predicted-sink-first observe
  order, not a second codebase.

## Out of scope for OSS v1

- Replacing jevsec. Dye does not do static taint.
- Auto-building or patching the target. The operator brings a runnable
  harness.
- Turning a dye hit into a filed report. Report drafting stays in the
  harness / operator loop.
- Autonomous crawl beyond candidate-driven plant + black-box propagate
  surfaces (same limit as black-box v1).
