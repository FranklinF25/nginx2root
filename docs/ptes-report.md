# PTES technical report — NGINX2Root family

Report date: 2026-11-20 (evidence window: disclosure 2026-11-18 → public
landscape 2026-11-20). Prepared from this repository's labs
([docs/finding-sheet.md](finding-sheet.md) and
[docs/prior-art.md](prior-art.md) are the canonical sources; every claim
below traces to them, to the task log L1–L21, or to the lab harnesses in
`lab/` + `poc/`). Methodology narrative:
[docs/research-writeup.md](research-writeup.md).

## 1. Executive summary

- **What.** Five unauthenticated, pre-auth memory-corruption
  vulnerabilities in NGINX — CVE-2026-123007 (HTTP/2 flow-control
  integer overflow), CVE-2026-123633 (HTTP/2 connection-drain UAF),
  CVE-2026-123634 (DNS resolver waiting-list UAF), CVE-2026-121810
  (HTTP/3/QUIC connection-drain UAF), CVE-2026-113425 (mail proxy
  `auth_http` UAF) — disclosed 2026-11-18 by Xint (@imssm99, @cdor1,
  @tjbecker, @yves), with CVE-2026-123007/-123633 also independently
  reported by Rapid7, Wiz, Ikotas Labs and Metnir. Each is rated
  CVSS v4.0 **9.2 CRITICAL** / v3.1 8.1.
- **Impact.** All five are **worker-level** memory corruption reachable
  without authentication. Converting corruption into remote code
  execution is non-trivial: it requires ASLR to be disabled or bypassed —
  the 123007 chain carries its own address-disclosure primitive
  (demonstrated by Xint/Wiz/Rapid7, so ASLR/PIE are not standalone
  mitigations), and the one public RCE implementation additionally
  constrains libc and CPU (glibc EVEX/YMM memcpy path, `avx512f`/
  `avx512vl`, x86-64).
- **Fix.** NGINX OSS **1.31.9** (mainline) / **1.30.7** (stable), both
  released 2026-11-18. A **restart is required — reload leaves old
  workers with old sessions**.
- **Threat status.** No public evidence of in-the-wild exploitation;
  none of the five is in CISA KEV as of 2026-11-19 (CISA advisory
  [2026-136](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-nginx-could-allow-for-remote-code-execution_2026-136),
  2026-11-19; Cloudflare status, 2026-11-19).
- **Exposure.** Shodan (2026-11-10/18): 56.7M nginx hosts; of the 21%
  exposing a version, 98.9% are in the affected range for 123007.
  Censys: ~9M services on an affected version with HTTP/2 enabled
  (103M more hide their version).
- **This repo's verification posture** (all lab work, Docker-only,
  1.31.8-vulnerable vs 1.31.9-fixed differentials):
  - **123007** — full differential: safe oracle + deterministic crash
    PoC + `http2 off` mitigation control + libc matrix (musl/Alpine
    SIGILL vs glibc SIGSEGV).
  - **123634** — first public **stock-build** (non-ASAN) worker crash,
    with the timing race characterized (50–300 ms DNS-failure holds,
    20–40% win rate per attempt).
  - **121810** — honest negative (~120 attempts × 11 configs) plus the
    first published gate analysis of why the obvious interleavings
    cannot fire; externally validated by Cloudflare (also not
    reproduced).
  - **123633** — honest partial: differential oracle 3/3 across four
    builds + verbatim server-side kill chain + three source-verified
    mechanism corrections; terminal UAF not landed.
  - **113425** — no local lab (dropped 2026-11-20); presented from
    public prior art (Cloudflare ASAN repro + full mechanism).

## 2. Scope and approach

Family-wide, NGINX-only. The Linux SCTP kernel LPE that chains
worker-context compromise into host root is **out of scope** (no CVE,
unpatched as of 2026-11-19; tracked in the finding sheet only). All
testing was performed against self-built lab pairs inside Docker
(loopback-only ports, digest-pinned images) — no third-party system was
ever tested. Each CVE was approached differential-first: a safe
oracle/detector against vulnerable 1.31.8 vs fixed 1.31.9 before any
crash attempt, with honest-negative semantics baked into the harnesses
(exit 0 means "lab functional", never "bug fired", where the bug is not
reproduced). Full methodology: [docs/research-writeup.md](research-writeup.md).

## 3. Findings

### 3.1 CVE-2026-123007 — HTTP/2 flow-control window double-return

**Required configuration.** HTTP/2 enabled. First affected 1.9.5
(2015-09-22).

**Mechanism.** H2 flow-control window credit is returned twice
(`WINDOW_UPDATE` + canceled-stream cleanup) → connection window exceeds
2³¹−1 → unsigned underflow in the capacity check → signed/unsigned
confusion → ~2⁶⁴-sized memcpy (OOB write + address disclosure). The
window inflation to 2^63 needs ~4.29e9 `WINDOW_UPDATE` frames (~52 GiB
wire), and nginx 1.31.8's `http2 flood detected` heuristic
(`total_bytes/8 > payload_bytes + 1 MiB`) must first be defeated — our
labs do it legally with ~10 GiB of real server-sent downloads (raising
the allowance to ~80 GiB) before flooding.

**Our lab evidence** (`lab/` + `poc/diagnose.py`, `poc/crash.py`;
commands: `cd lab && ./verify.sh`, crash matrix via `RUN_CRASH=1`):

- Safe oracle (differential, no crash): `[vuln:8080] VULNERABLE`,
  `[fixed:8080] PATCHED`, `[mitigated:8080] NOT-H2`; the musl/Alpine
  pair (F2) classifies identically — verify.sh asserts 5/5 verdicts and
  `PASS` (observed ~25 s post-build).
- Crash PoC over TLS (opt-in): `[vuln:443] WORKER-DIED` with the
  server-side line `worker process 7 exited on signal 11 (core dumped)`;
  `[fixed:443] SURVIVED` (terminated inside the ritual, before any
  flood); `[mitigated:443] NOT-H2` (TLS alert `no application protocol`
  — ALPN never offers h2). Observed cost: ~52 GiB wire, ~3 min per vuln
  run at ~0.5 GB/s primed.
- Libc matrix (F2, first public for this bug): musl (alpine:3.22) —
  3/3 `WORKER-DIED`, deterministic **signal 4 (SIGILL)**; every glibc
  tested (2.23 xenial → bookworm) — **signal 11 (SIGSEGV)**. DoS holds
  on every libc; the surgical 160-byte write primitive (RCE tier) is
  glibc-only. The oracle classifies on musl with the debian staging
  constants untouched (kernel owns socket buffers, not libc).

**Public landscape position.** Rapid7 ships the full marker-verified RCE
against 1.31.8 (implementation constraints: ~119 GiB traffic, ≥300
Mbit/s, glibc EVEX/YMM path — characterized by Cloudflare as "suitable
only for demonstrating the attack against a freshly started local
container"); Censys ships the compact accounting oracle (ours is a
convergent reinvention) plus the release/arm64/worker/heap matrices;
Cloudflare verified the fault on ASAN-built 1.31.8 (clean on 1.31.9).
Our distinct pieces: stock-build differential + TLS crash matrix, the
first public libc matrix, and the only shipped executable `http2 off`
verification (per-artifact verdicts in
[docs/prior-art.md](prior-art.md)).

### 3.2 CVE-2026-123634 — resolver waiting-list use-after-free

**Required configuration.** `resolver` + variable `proxy_pass` +
`mirror` (SSI may reach the same path). First affected **0.6.18**
(Cloudflare correction, 2026-11-20; supersedes the advisory-era 1.13.4).

**Mechanism.** The resolver waiting-list loop holds `next` while a
handler frees the sibling context: a main request plus its `mirror`
subrequest attach to the same DNS node; when the first handler's 502
send fails on an RST'd client socket, `ngx_http_terminate_request` tears
down the whole request tree — including the sibling's resolver ctx — and
walk iteration 2 writes through the freed pointer
(`ngx_resolver.c:2142`).

**Our lab evidence** (`lab/123634/`, `poc/123634/trigger.py`; command:
`cd lab/123634 && ./verify.sh`, ~2–3 min):

- **Stock-build worker crash — first public beyond Censys's
  ASAN/custom-debug repros.** Verbatim chain per hit:
  `could not cancel sf-300-0.u123634.test resolving` (ALERT) →
  `http request count is zero while closing request` (ALERT) →
  `worker process 21 exited on signal 11 (core dumped)`.
- Race characterization: DNS-failure holds of **50–300 ms** with the
  client RST landing inside the window; observed win rate **20–40% per
  attempt** (verify.sh uses 10 attempts; has not missed in practice).
- Negative controls survive: answer-then-RST, half-close (FIN), RST
  before body, no RST.
- Fixed 1.31.9 under the identical trigger: **zero** `could not cancel`
  alerts, **zero** deaths; `fixed-asan`: zero reports.
- ASAN floor, verbatim: `AddressSanitizer: heap-use-after-free`,
  `WRITE of size 8`, `#0 … in ngx_resolver_process_a
  src/core/ngx_resolver.c:2142`, freed under `ngx_http_terminate_request`
  ← `ngx_http_upstream_cleanup` ← `ngx_resolve_name_done`.

**Public landscape position.** Censys: ASAN UAF + custom-debug crash
only; Cloudflare (2026-11-20): ASAN-build repro plus the walk-list
mechanism and the 0.6.18 first-affected correction. Our stock-build
crash + quantified race recipe remain technically distinct, but the
novelty window is closed — both facts recorded (task log L20).

### 3.3 CVE-2026-121810 — HTTP/3/QUIC connection-drain use-after-free

**Required configuration.** HTTP/3 (`listen … quic` + `http3 on`) +
`proxy_pass` upstream. First affected 1.25.0.

**Mechanism.** The QUIC parent connection is re-queued as reusable
during stream creation (rbtree insert happens after the connection-slot
allocation); a later connection drain can then select the parent and
free the in-flight request pool under `ngx_event_connect_peer`'s stack.
The 1.31.9 fix moves the rbtree insert before the slot allocation.

**Our lab evidence** (`lab/121810/`, `poc/121810/trigger.py`; command:
`cd lab/121810 && ./verify.sh`, ~3–4 min):

- **NOT REPRODUCED — honest negative**: no ASAN report, no stock worker
  death, no client-observable differential across **~120 attempts × 11
  configurations** (worker_connections 32–128; idle/FIN/abort stream
  mixes; h1-refiller saturation pinning `free_connection_n` at
  `connection_n/16`; `/proxied`, `/refused`, `/slow` upstream paths).
  The harness asserts the *lab*: H3 sanity on all four builds
  (`TRIGGER-OK`), drain events firing (`PASS: drain events firing
  (precondition for the race present)`), fixed controls clean
  (`PASS: fixed-asan clean under identical trigger`,
  `PASS: stock fixed control death-free`), and prints the expected
  outcome line verbatim: `INFO: no ASAN report / worker death — race
  not landed (matches public state)`.
- Drains fire — the race precondition is present — but drain victims
  were ~100% h1 keepalives.
- **First published gate analysis** (source-verified on 1.31.8): for the
  line-1168 re-mark to run inside the create window, the drain must
  synchronously close a same-parent stream passing both
  `ngx_quic_close_stream()` gates — `recv_state != RECV` (client FIN or
  RST already seen) **and** `send_state ∈ {DATA_RECVD, RESET_RECVD}`
  (everything the server sent ACKed, or the server's own RST ACKed).
  Drain-closable streams are reusable-marked only while *waiting for
  request bytes*, so both gates cannot be passed synchronously; the
  real interleaving must be second-order (next angles: instrumented
  debug builds, uni-stream/two-parent pressure).

**Public landscape position.** Censys: "Not reproduced". Cloudflare
(2026-11-20): also not reproduced — their section rests on the fix
commit and published analysis. **External validation of our honest
negative; our gate analysis remains the only published why-not.**

### 3.4 CVE-2026-123633 — HTTP/2 connection-drain use-after-free

**Required configuration.** HTTP/2 + `proxy_pass` upstream. First
affected 1.19.7.

**Mechanism.** An active h2 connection is left in the reusable-connection
queue (the incomplete-frame flag is checked *after* enqueue); a later
connection drain selects it mid-request and can free the live request.
The 1.31.9 fix un-marks the connection the moment a stream opens.

**Our lab evidence** (`lab/123633/`, `poc/123633/trigger.py`; command:
`cd lab/123633 && ./verify.sh`, ~4–5 min):

- **Differential oracle, 3/3, four builds**: vuln 1.31.8 and vuln-asan
  show `VULNERABLE-STATE (drain GOAWAY'd the active h2 conn)` — the
  drain selects the ACTIVE h2 connection mid-request and GOAWAYs it
  before the response data; fixed 1.31.9 and fixed-asan show
  `PATCHED-STATE (no GOAWAY before response data)` under identical
  triggers (verify.sh asserts `3/3 attempts VULNERABLE-STATE` on the
  vulnerable pair and 0 on the fixed pair; recorded run: 3/3 stock
  pair, 2/2 ASAN pair).
- **Verbatim server-side kill chain** (debug build, one attempt):
  `http2 close stream 1, queued 0, processing 1` → `http2 handle
  connection handler` → `reusable connection: 1` (the bug mark) →
  `http2 request line: "GET /refused HTTP/2.0"` (stream opens still
  marked) → `reusing connection` (the drain selects it) → `http2 send
  GOAWAY frame: last sid 3, error 0` (read handler runs mid-request) →
  `http upstream connect: -2` (`ngx_event_connect_peer` continues on
  the same stack).
- **Three source-verified mechanism corrections**: the incomplete frame
  that marks the connection reusable is a **SETTINGS** frame (not
  HEADERS); reusable marks insert at queue **head** while the drain
  takes **oldest-first** (`ngx_queue_last`); the working pressure
  instrument is **busy unread h1 requests** (idle fillers are
  self-defeating — the drain sacrifices the oldest marks).
- **Terminal UAF not landed** (honest): ~200 crash-race attempts → no
  ASAN report, no stock crash; the unlanced step is dead-socket
  detection inside the drain-invoked handler (below Censys parity on
  the crash, above on mechanism). Fixed controls: zero markers under
  identical triggers.

**Public landscape position.** Censys: stock worker crash on 1.31.8
(our parity target, not reached); Cloudflare (2026-11-20): public ASAN
crash. Our distinct contribution: the 3/3 four-build differential
oracle + the three mechanism corrections.

### 3.5 CVE-2026-113425 — mail proxy `auth_http` use-after-free

**Required configuration.** `mail` block with `proxy on` +
`auth_http`. First affected **0.5.33** (Cloudflare, 2026-11-20;
supersedes the advisory-era 0.5.15). **Presented from public prior
art — the local lab was dropped on 2026-11-20** (task log L20) after
Cloudflare's deep dive published an independent ASAN repro plus the
full mechanism; a scoped local lab had nothing left to add.

**Mechanism (Cloudflare, 2026-11-20 — first full public account).** Two
connections share one mail session; during `auth_http` the reply the
protocol handler prepared stays queued and the client write handler
remains `ngx_mail_send()`. If that handler runs and the write fails
because the client reset the connection, the client connection closes
and destroys the session while the auth connection still points at it.
Two conditions: the client write event must already be registered
(e.g. the client stopped reading), and the login command + reset must
be handled in the same event-loop pass. **Valid credentials are NOT
needed.** Fix: discard the queued reply when the auth request begins,
plus three further commits blocking client writes during auth phases.

**Public landscape position.** Cloudflare: ASAN repro (faults on
1.31.8, clean on 1.31.9) + full mechanism; Xint: disclosure writeup;
F5 K000163931: vendor advisory; Censys: command execution confirmed
from retained artifacts (not independently replayed).

## 4. Risk and remediation

All five CVEs: CVSS v4.0 **9.2 CRITICAL** / v3.1 8.1; exploitation runs
with **worker** privileges; all five are independent paths — no chaining
needed.

### 4.1 Fixed versions

| Product | Fixed |
|---|---|
| NGINX OSS mainline 1.9.5–1.31.8 | 1.31.9 |
| NGINX OSS stable ≤ 1.30.6 (incl. 1.28.x) | 1.30.7 |
| NGINX Plus 37.1.0–37.2.0.1 | 37.3.0.1 (123633 already in 37.2.0.1) |
| NGINX Plus 37.0.0–37.0.7.1 | 37.0.8.1 (123633 already in 37.0.7.1) |
| NGINX Plus R34–R36 | **no fix listed** |
| F5 NGINX Ingress Controller | 5.8.0 |
| F5 NGINX Gateway Fabric | 2.9.0 |
| BIG-IP / BIG-IQ / F5OS | not vulnerable |
| community ingress-nginx | archived 2026-03, no further fixes |

### 4.2 Mitigation matrix (where upgrading is not yet possible)

| CVE | Mitigation | Verified how |
|---|---|---|
| 123007 + 123633 | `http2 off` | our `mitigated` service + `NOT-H2` verdict — the only *executable* `http2 off` verification among public artifacts (Cloudflare recommends it; no shipped harness) |
| 121810 | remove QUIC listeners + `http3 off` | configuration-only (no public repro exists to test against) |
| 123634 | fixed upstream groups (avoid variable `proxy_pass` targets + SSI/mirror) | **`mirror_request_body on` is NOT sufficient** — SSI reaches the same resolver path (Cloudflare) |
| 113425 | bind `mail` listeners to trusted networks only | configuration-only (no local lab, L20) |
| all five | **restart, not reload** | reload leaves old workers with old sessions |

Vendor workarounds exist only for 123634 and 113425; `http2 off` is a
CIRCL/Xint (and now Cloudflare) recommendation, not an F5 one.

### 4.3 Distribution status snapshot (2026-11-20; details in the finding sheet)

- Ubuntu USN-9182-1 (2026-11-20) fixes only the co-shipped non-family
  CVEs (125283, 123640, 118899) — **no NGINX2Root family fix in Ubuntu
  packages as of 2026-11-20**; ≤ 20.04 is unpatchable via nginx.org
  (newest build 1.27.5).
- Debian stable/testing: vulnerable, no fixed package yet.
- Official Docker images: 1.31.9/1.30.7 tags live; running containers
  keep old builds until pull + redeploy (restart required).
- Backports may fix without changing `nginx -v` — compare the full
  package revision against the distro advisory.

## 5. Detection guidance

Configuration triage first (`nginx -v`, `nginx -V`, `nginx -T` greps —
full commands in the finding sheet), testing origin reachability, not
the CDN (`openssl s_client -alpn h2`). Then, per CVE:

- **123634 (strongest pre-exploitation signal):** the alert
  `could not cancel <name> resolving` is **unpatched-only** — 1.31.9
  demotes it to debug; correlate with `worker process N exited on
  signal 11`. Caveat: one CNAME-following variant produced no alert
  (Cloudflare), so absence does not imply safety.
- **123633 / 121810:** `worker process … exited on signal 11` in
  error.log / `coredumpctl`, plus saturation pressure markers —
  `worker_connections are not enough` (observed in this lab's 121810
  matrix as `worker_connections are not enough while handling frames`).
- **113425:** mail-worker crashes (signal exits, core dumps) correlated
  with client resets during authentication phases (login + reset in one
  event-loop pass; no valid credentials involved).
- **Strongest RCE signal:** workers executing programs —
  `auditctl -a always,exit -F arch=b64 -S execve,execveat -F
  euid=<nginx_uid> -k nginx_worker_exec`.
- Supporting heuristics (none is proof alone): long-lived connections
  with `bytes_received ≫ bytes_sent` and few logged requests
  (`ss -tinp`); abnormal worker exits/core dumps; note that H2 control
  frames (`WINDOW_UPDATE`, `RST_STREAM`) never appear in access logs.
- **Fake-exploit warning:** Cloudflare (2026-11-20) reports fake
  nginx2root "exploit" repos circulating on GitHub; the origin exploits
  (Xint, Wiz) were never released — audit before running anything.

## 6. References

Primary (URLs carried by this repo's source list; accessed 2026-11-19/20):

- Xint writeup, "nginx2root" (disclosure, 2026-11-18) —
  <https://xint.io/blog/nginx2root-remote-code-execution>
- nginx security advisories — <https://nginx.org/en/security_advisories.html>;
  CHANGES — <https://nginx.org/en/CHANGES> (1.31.9/1.30.7, 2026-11-18)
- Cloudflare, "nginx2root" deep dive (2026-11-20) —
  <https://blog.cloudflare.com/nginx2root/>
- CISA advisory 2026-136 (2026-11-19) —
  <https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-nginx-could-allow-for-remote-code-execution_2026-136>
- Ubuntu USN-9182-1 (2026-11-20) —
  <https://ubuntu.com/security/notices/USN-9182-1>
- Rapid7 PoC repo (S. Fewer) —
  <https://github.com/sfewer-r7/CVE-2026-123007> (public, 2026-11-19)
- Censys research repo —
  <https://github.com/Censys-Research/nginx2root> (commit `332d951`,
  2026-11-19)
- The Hacker News (2026-11-18) —
  <https://thehackernews.com/2026/11/10-year-old-nginx-http2-flaw-lets.html>

Secondary (carried by identifier in the finding sheet's Sources list;
no URL recorded there — cited as such): F5 K000164058 and K000163931;
CIRCL TR-105; Rapid7 blog post (S. Fewer); Censys blog; Wiz blog
(N. Ohfeld, T. Schwartz); Qualys TRU; SecurityWeek; Laravel Forge KB;
Tenable/watchTowr FAQs.

Internal evidence: [docs/finding-sheet.md](finding-sheet.md) (canonical
claims), [docs/prior-art.md](prior-art.md) (path:line artifact
verdicts), `lab/*/README.md` + `lab/*/verify.sh` (runnable harnesses),
task log L1–L21 in `odd/tasks/nginx2root.md`.
