# dyetrace

Black-box dataflow tracer for authorized bug-bounty testing.

Dye injects a unique, self-identifying tracer into every observed input of a
recorded authenticated session, re-drives the recorded read surfaces, and
watches where each tracer resurfaces. A tracer that surfaces in a context it
should never reach is a leak, and that leak is the finding.

See `SPEC.md` for the design. v1 is HTTP-only.

## Status

Early development. HTTP-only core.

## OSS mode (dye-OSS)

`--candidates` consumes a jevsec `candidates.json` and turns each static
candidate into a runtime verdict: the tracer is planted only at the requests
the candidate's source maps to, and a hit at the predicted surface proves the
flow.

```bash
dyetrace --session session.json --host app.example.com \
  --candidates runs/<run-id>/candidates.json
```

Each candidate gets a verdict: `PROVEN` (tracer surfaced at the predicted
surface), `new_flow` (surfaced elsewhere), `KILL` (executed, never surfaced),
`unexercised` (plants never reached the handler), or `unmapable` (no
guess-free map exists). Gate submission on `verdict == "PROVEN"`.

### Operator binds

Candidates whose entry kind has no HTTP field (`exported`, `cli-handler`,
`consumer`, `module-init`) stay `unmapable` unless bound explicitly:

```bash
dyetrace --session session.json --host app.example.com \
  --candidates candidates.json --binds binds.json
```

```json
{
  "cand-abc123": {
    "request_index": 4,
    "path_id": "query:q",
    "predicted": "propagate:7"
  }
}
```

`request_index` names the recorded request to plant; `path_id` restricts the
plant to one leaf, using the same ids the plant layer emits:

| site | path_id shape | example |
| --- | --- | --- |
| query / form leaf | `query:<key>` / `form:<key>` (dup keys get `[i]`) | `query:q`, `query:id[1]` |
| path segment | `path:<route with {segN}>` | `path:/api/items/{seg1}/action` |
| header | `header:<name>` | `header:x-target` |
| JSON body leaf | `json:$<.key | [i] path>` | `json:$.user.name` |
| multipart | `multipart:<name>.value` / `.filename` | `multipart:file.value` |

 `predicted` names where a resurfacing tracer proves the
flow: `plant` (default: the candidate's own executed plant response body),
`propagate:<index>` (the unplanted replay of recorded request `<index>`, for
stored-then-reflected sinks), or `identity:<n>` (any observation under
identity `<n>`). `--predicted-surface` sets the default for all candidates
and per-candidate binds override it. Binds fail closed on unknown candidate
ids, out-of-range indexes, or malformed JSON.

### Loopback harnesses

`--allow-loopback` permits loopback target addresses (127.0.0.0/8, ::1) for
local harness runs; it is off by default and every other forbidden range
(private, link-local, metadata IPs) stays blocked. Plain HTTP still needs
`--allow-cleartext`. Session `auth_headers` is the place for the bearer or
cookie tokens the recorded session ran under.

### Mount prefixes and runs dirs

`--route-prefix PREFIX` (repeatable) joins an operator-asserted mount prefix
onto route details during matching: a `get /x` candidate maps a recorded
`/api/x` under `--route-prefix /api`. Prefixes only join; nothing is
discovered or stripped, and unmatched routes stay `unmapable`.

`--candidates` also accepts a jevsec run dir, or a runs root holding exactly
one run dir (the pick is printed on stderr). A runs root with several run
dirs fails with a numbered list; pass one explicitly.

### Building the session

`tools/session_from_har.py` converts a HAR capture into session JSON. It
accepts loopback captures only (localhost / 127.x / ::1) unless
`--allow-remote` is set:

```bash
python tools/session_from_har.py capture.har -o session.json
```

### The full loop

```bash
# jevsec prints its candidates path; feed it straight to dye-OSS
bun src/cli.ts /path/to/target            # in the jevsec repo
python tools/session_from_har.py capture.har -o session.json
dyetrace --session session.json --host app.example.com   --candidates <runs>/candidates.json --binds binds.json   --route-prefix /api --output json --out verdicts.json
# gate submit only on verdict == "PROVEN"
```

## Egress prover mode

`dyetrace egress` checks whether an MCP server's URL-taking tool makes the
server fetch from inside the environment it runs in. For each static candidate
(a URL-fetching handler found by `ssrf-guard-audit`, or a lead from
`egress-plane`), it calls the matching tool with a URL argument that carries a
fresh tracer and points at a listener you control. A request that reaches the
listener with a verified tracer, attributed to that candidate's own call, is the
proof. For authorized testing only, against servers you have the right to test.

It is a separate subcommand. The black-box and OSS modes are unchanged.

### Install

The MCP client SDK is an optional extra; the core install still needs only
`httpx`.

```bash
pip install 'dyetrace[mcp]'
```

Without it, a run stops before spawning anything and prints this install line.

### Flags

| flag | meaning |
| --- | --- |
| `--candidates FILE` | saved candidates file (required) |
| `--candidates-format` | `normalized` (default), `ssrf-guard-audit` or `egress-plane` |
| `--binds FILE` | operator binds: candidate id to tool, argument, optional static `arguments` |
| `--target FILE` | operator target config JSON: stdio command or HTTP URL (required) |
| `--listen HOST:PORT` | listener bind, an IP literal (default `127.0.0.1:0`; a real run needs a nonzero port) |
| `--advertise URL` | http base URL the target is told to fetch; carries its own nonzero port |
| `--allow-exposed-bind` | permit a non-loopback or wildcard listener bind |
| `--allow-local-advertise` | permit a loopback or private advertised address |
| `--redirect-hop URL` | 302 every well-formed request to this base URL on the `--listen` port; a tracer that resurfaces there proves the redirect hop was fetched without re-validation |
| `--attest-listener-reachable NOTE` | operator note that the target can reach the listener; recorded verbatim, unverified; required for any KILL |
| `--settle SECONDS` | wait for the token after each call (default 5) |
| `--drain SECONDS` | final wait for late fetches (default 5) |
| `--call-timeout SECONDS` | per-call timeout (default 30) |
| `--rate N` | calls per second (default 1.0) |
| `--max-calls N` | call-count cap, checked before any send (default 500) |
| `--target-commit TEXT` | target commit or version, recorded verbatim in the report |
| `--allow-cleartext` | permit a plain `http` MCP target (HTTP target only) |
| `--allow-loopback` | permit a loopback MCP target (HTTP target only) |
| `--output` | `terminal` (default), `html` or `json` |
| `--out FILE` | write the report to a file instead of stdout |

### Worked example: a stdio server

The target config names the command to spawn. It is operator input only: a
list, never a shell string, and nothing from the candidates file or the
server's output ever reaches it. The child gets only the SDK's default
environment (`HOME`, `PATH`, and a few more), your `env` map, and any names
listed in `env_passthrough`. `cwd` is optional.

`target.json`:

```json
{
  "transport": "stdio",
  "command": ["python", "server.py"],
  "env": {"LOG_LEVEL": "warning"},
  "env_passthrough": ["API_BASE"]
}
```

For an HTTP server use `{"transport": "http", "url": "https://mcp.example.com/mcp"}`.
Those requests go through the same host allowlist, pinned-address, byte-cap and
recheck rules as the other modes, so `--allow-loopback` and `--allow-cleartext`
apply to them. Only streamable HTTP is supported.

`candidates.json` comes from a saved scan:

```bash
ssrf-guard-audit scan --json ./server > scan.json
egress-plane scan --format json ./server > scan.json    # or this one
```

Pass it with `--candidates-format ssrf-guard-audit` or `egress-plane`. The
adapters read the saved file; they never run either tool. You can also write the
normalized form by hand (`"version": 1`, a `candidates` array; each entry needs
`id`, `source_tool`, `source_version`, `file`, `start_line`, `end_line`;
optional keys are `symbol` (null allowed; without it the candidate maps only via
`tool_name` or a bind), `site_label`, `param_names`, `params_truncated`, `sinks`
(a list of `file` and `line` objects), `guard_classes`, `destination_kind`,
`lead`, `tool_name` and `arg_name`; unknown keys are ignored).

A candidate is mapped to a tool and argument only when exactly one live tool
name equals the candidate's symbol and exactly one string argument matches a
parameter name. Neither scanner records MCP tool names, so most candidates
need a bind. `binds.json`:

```json
{
  "cand-abc123": {
    "tool": "proxy_fetch",
    "argument": "callback_url",
    "arguments": {"url": "https://example.com"}
  }
}
```

`argument` receives the tracer URL; `arguments` are static values for the
tool's other required arguments (a tool whose required arguments are not all
covered is `unmapable`). A bind naming a tool or argument that is not in the
server's live `tools/list` stops the run before anything is sent.

For tools whose URL sits inside a nested or union-typed argument (for
example `{"action": {"type": "introspect", "endpoint": ...}}`), omit
`argument` and place exactly one `{url}` placeholder in `arguments` instead;
the tracer URL is substituted into that leaf and the placeholder's dotted
path is recorded as the argument. A bind may not mix `argument` and `{url}`.

The listener port contract: `--advertise` carries its own explicit port, and
`--listen` must bind that exact port. A missing port, port 0 or a mismatch is a
stop. Behind NAT or a container the two addresses differ, which is why they are
separate flags.

```bash
dyetrace egress \
  --candidates scan.json --candidates-format ssrf-guard-audit \
  --binds binds.json --target target.json \
  --listen 0.0.0.0:8099 --allow-exposed-bind \
  --advertise http://canary.corp.example:8099 \
  --attest-listener-reachable "egress-plane probe from target host reached 10.0.4.7:8099, 2026-10-27" \
  --target-commit 3f2a9c1 --output json --out egress.json
```

For a local harness run (loopback only, so KILL is not available):

```bash
dyetrace egress --candidates candidates.json --binds binds.json \
  --target target.json \
  --listen 127.0.0.1:8099 --advertise http://127.0.0.1:8099 \
  --allow-local-advertise
```

Without `--advertise`, the advertised URL is derived from the address the
listener bound, under the same rules.

### Redirect-hop mode

`--redirect-hop URL` turns the listener into a two-hop harness. Any request
whose `Host` does not already name the redirect authority gets a `302` to
`URL` plus the request-target (the tracer path rides along); a request that
does gets the usual empty 200, so one listener serves both hops with no loop.
The redirect URL is validated like `--advertise` and must carry the `--listen`
port. An arrival whose `Host` matches the redirect authority is marked
`via_redirect` in the report: it could only have arrived by following the
302. Pair it with a control run showing the same address refused when asked
directly and the evidence is a missing redirect re-validation (the G6 shape:
hop 0 passes the guard, hop 1 does not get checked).

### Verdicts and exit codes

The same five names as OSS mode, with these definitions:

- `PROVEN`: a request reached the listener whose path carries a tracer that
  verifies for this run and maps, through the driver's own send record, to this
  candidate's call. Status codes, tool result text (even one that echoes the
  token), unverified requests, and tokens in a header or query never count.
- `new_flow`: a verified arrival from a call to the same tool but a different
  argument than the candidate predicted. The note names the argument that was
  fetched.
- `KILL`: the call returned without error, nothing arrived, and every
  condition for trusting that silence held: a settle window of at least 2 s, an
  operator reachability attestation, a healthy listener, no refused or
  deadline-closed connections or unattributed arrivals in the window, no
  silently closed (oversize, malformed or truncated) request heads and no
  unverified arrival carrying this run's prefix anywhere in the run (not only in
  the window), and a public-class advertised URL. A single such stray request
  (including scanner traffic on a public listener) therefore turns every
  would-be KILL into `unexercised` with `unattributed_arrival`.
- `unexercised`: the call was not made, or failed (tool error, transport error,
  timeout, invalid params), or the conditions for KILL did not hold. The reasons
  are joined with `+`: `settle_window_too_short`,
  `listener_reachability_unconfirmed`, `listener_saturated`,
  `unattributed_arrival`, `local_class_only_no_arrival`,
  `address_class_unknown`, `tool_error`, `transport_error`, `timeout`,
  `server_rejected_input`, `not_called`, `listener_failed`, `run_incomplete`.
- `unmapable`: no guess-free map to a tool and argument exists. Supply a bind.

A guard that refuses loopback and private targets but still fetches public
hosts is the common SSRF fix. A silent probe against a loopback or private
canary therefore cannot clear a path, and gets `local_class_only_no_arrival`.
Only a public-class advertised URL can produce KILL.

Exit codes: `0` when the run completed and every candidate was exercised
(PROVEN, new_flow or KILL); `3` when it completed with any `unmapable` or
`unexercised` candidate, or when nothing mapped; `2` for every stop and for an
incomplete run (the INCOMPLETE report is still written). A stop prints
`dyetrace: stopped: <reason>` on stderr. The JSON report carries a `coverage`
block with counts per verdict and the fraction exercised; do not read exit 0 as
clearance.

### Safety rules

- The listener binds `127.0.0.1` by default. Any other bind, wildcard included,
  needs `--allow-exposed-bind`. Bind hosts must be IP literals.
- A loopback, private, ULA or CGNAT advertised address needs
  `--allow-local-advertise`. Cloud metadata and special addresses are refused
  with or without opt-ins (`169.254.0.0/16`, `fe80::/10`, `fd00:ec2::254`,
  `100.100.100.200`, `168.63.129.16`, and other special-purpose ranges).
  Embedded-IPv4 forms are canonicalized first, and non-canonical numeric hosts
  (decimal, hex, octal, short forms) are refused.
- The advertised URL is validated before any socket opens or any tool is called.
  It must be `http`: the listener has no TLS, and an `https` URL is refused with
  its own error. No userinfo, fragment, query or whitespace, so no credentials
  go in the URL.
- The listener answers every request with an empty 200 and closes the
  connection. It bounds head size, head time, body bytes, concurrent
  connections and retained records, and counts what it drops.
- The stdio command comes from the target config only. Dyetrace never dials the
  model-chosen URL; it only hands it to the tool.
- Calls are rate-limited (`--rate`), capped (`--max-calls`) and time-limited
  (`--call-timeout`). Tracers are inert identifiers; nothing is extracted.

### What a result does and does not mean

`PROVEN` means the tracer URL reached the listener after that call. It does not
show that the tool handler made the request itself: something else in the
server's stack, or on the same host, could have fetched it. The report gives
the call, the token, and each arrival's source address, time and order so you
can judge that.

`KILL` means no arrival was observed in this harness. It does not mean the path
is safe. The reachability attestation is your assertion, recorded verbatim and
labeled operator-asserted and unverified, with the advertised host:port and the
bound port beside it so a stale note is visible. A tool that raises on a refused
target ends as `unexercised` (`tool_error`), not KILL.

A path that is not reported is not cleared. The candidates come from static
scans, and this mode only tests what they name.

Named limits:

- Dyetrace's own outbound checks (HTTP target) resolve the host and then the
  transport re-resolves when it dials, so a DNS rebind in that window is not
  closed. The stdio leg dials nothing.
- A fetch that happens after the drain window is missed. Raise `--settle` and
  `--drain` for slow or queued tools.
- A network observer who sees the tracer URL can replay it during the run. Each
  arrival records source address, time and order; tokens are not bound to a
  source.
- A tracer that appears in the target's logs is not detected here; use a log
  scanner on the target side.
- Candidate-derived text and the target's stderr can contain bidi or escape
  characters. They are neutralized in terminal output by the existing report
  helper; treat the HTML and JSON surfaces as untrusted input to whatever reads
  them next.
- Only `http` is exercised. Tools that require `https` are untested.
