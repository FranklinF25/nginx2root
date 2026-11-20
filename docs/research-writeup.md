# Research writeup — the NGINX2Root family, worked end to end

Narrative companion to [docs/ptes-report.md](ptes-report.md) (findings,
per-CVE detail) and [docs/finding-sheet.md](finding-sheet.md) /
[docs/prior-art.md](prior-art.md) (canonical facts). Written 2026-11-20;
all lab work is frozen as of that date.

## 1. Objective and scope

**Objective.** Take the five-CVE NGINX2Root disclosure of 2026-11-18 and
do for the whole family what we did for our earlier nginx CVEs
(cve-2026-42533, cve-2026-42945): differential labs, safe detectors, an
exploit-constraints audit, and honest documentation of what was and was
not reproduced — plus an explicit original-vs-prior-art verdict for
everything we ship.

**Scope (decided 2026-11-19, held throughout).**

- Family-wide, **NGINX-only**: CVE-2026-123007, -123633, -123634,
  -121810, -113425.
- The **Linux SCTP kernel LPE** (worker→root chain, no CVE, unpatched)
  is explicitly **out of scope** — tracked in the finding sheet only.
- **Docker-only execution** (S4): every build, probe and exploit run
  happens inside containers; nothing builds or executes on the host.
  All published ports are loopback-only; probes run inside a probe
  container against in-network service names.
- RCE itself is out of scope for our labs: we stop at worker death
  (crash tier) and safe differentials.

## 2. Methodology

- **Differential labs.** Every CVE is approached as a vulnerable
  1.31.8 vs fixed 1.31.9 pair (source builds, tarball sha256 + base
  image digest pinned, TOFU values dated 2026-11-19), plus the controls
  each question needs: a `mitigated` service (`http2 off`) for 123007,
  ASAN instrumented siblings for the F3 races. Single worker per nginx
  so a worker death is unambiguous.
- **Safe-oracle-first discipline.** Before any crash attempt there must
  be a safe, client-observable differential (an oracle) that exercises
  the bug's precondition without memory unsafety — the 123007
  flow-control oracle, the 123633 stale-mark oracle. Verdicts are
  phase-tracked: a connection death outside the expected phase is
  `UNCLEAR`, never "patched"; `PATCHED` verdicts are confirmed with a
  double-stream re-run.
- **Honest-negative policy.** Where a bug does not reproduce, the
  harness's exit 0 means *the lab works*, not *the bug fired* — and the
  failure is documented with the same rigor as a success (attempt
  counts, configuration matrices, and a source-level analysis of *why*
  it cannot fire). Both upstream PoC repos had mislabel bugs of exactly
  the class this discipline prevents; that is evidence it is worth
  shipping.
- **Prior-art audit with path:line verdicts.** Every public artifact
  (Rapid7, Censys, later Cloudflare) was diffed against our work claim
  by claim, with `path:line` citations — see
  [docs/prior-art.md](prior-art.md). Nothing original is claimed that a
  public artifact already contains.
- **Bounded everything.** `timeout` on every compose/trigger command,
  `settimeout` on every socket, SIGALRM watchdogs per attempt,
  healthcheck-gated bring-up, worker-safety greps after every matrix.

## 3. Findings

### 3.1 F1 — CVE-2026-123007: from oracle to deterministic crash

The root lab (`lab/`) built the vuln/fixed/mitigated trio plus (in F2)
the musl pair. The safe oracle (`poc/diagnose.py`) reproduces Xint §5.1:
queue DATA against a zero-sized stream window, return credit with a
stream-0 `WINDOW_UPDATE`, cancel the streams — the vulnerable build adds
the credit twice and the connection window passes 2³¹−1; an oversized
probe update then diverges without crashing anyone
(`VULNERABLE` vs `PATCHED`), and the `mitigated` service refuses h2
entirely (`NOT-H2`). 4/4 stable verdicts on validation, 5/5 asserted in
the shipped `verify.sh`.

The crash PoC (`poc/crash.py`) completes the kill over TLS: prime,
ritual, flood, trigger. Three measurement findings shaped it:

1. **The flood's real enemy is not timeouts but the `http2 flood
   detected` heuristic** (`total_bytes/8 > payload_bytes + 1 MiB`),
   which kills a control-frame-only connection within a few hundred MB.
   It is defeated *legally*: `payload_bytes` grows with every byte the
   server sends, so ~10 GiB of real downloads raise the allowance to
   ~80 GiB — enough for the ~52 GiB, ~4.29e9-frame `WINDOW_UPDATE`
   flood (~3 min at ~0.5 GB/s primed).
2. **nginx deducts the connection window at frame-build time** and the
   vulnerable capacity check is `send_window + increment > MAX` —
   staging grants must be state-aware, not hardcoded.
3. **Lingering close creates a 30 s illusion of rate-related deaths**,
   and on primed connections the patched build's FIN can surface one
   drain later — both must be accounted for or controls mislabel.

Outcome: `[vuln:443] WORKER-DIED` (server line: `worker process …
exited on signal 11 (core dumped)`), `[fixed:443] SURVIVED`,
`[mitigated:443] NOT-H2` — the only executable `http2 off` verification
among public artifacts.

### 3.2 F2 — exploit-constraints audit (libc/architecture)

Step 0 was the prior-art audit (above). The empirical step answered the
two crash-viability questions no public artifact had:

- **musl/Alpine (alpine:3.22): the crash survives — as deterministic
  signal 4 (SIGILL), not glibc's signal 11.** 3/3 `WORKER-DIED` runs;
  the ~2^63 OOB copy still faults under musl's forward memcpy. The DoS
  holds on every libc tested; the surgical 160-byte write primitive
  (RCE tier) is **glibc-only**. The oracle classifies on musl with the
  debian staging constants untouched — flow-control accounting is nginx
  logic; socket buffers are kernel-owned.
- **glibc 2.23 (xenial stretch pair): crashes with signal 11** — the
  kill predates the 2.24 backward-copy memmove rework entirely.

Flood-side: musl sustains 52.21 Mfr/s / 679 MB/s (glibc ~709 MB/s);
priming identical. This is the **first public libc matrix for this
bug**. Caveat kept honest: the musl SIGILL root cause (which
instruction faults) is not dissected — cores do not persist in the lab
containers. arm64 accounting and the AVX-512 RCE constraint were
inherited as verified fact from Censys/Rapid7 rather than re-run.

### 3.3 F3 — the four siblings

**CVE-2026-123634 — stock crash, race characterized (strongest F3
result).** The lab reproduces the resolver waiting-list UAF on *stock*
1.31.8: a request-derived `proxy_pass` + `mirror` put the main request
and its subrequest on one DNS node; a held-back SERVFAIL answer plus a
precisely-timed client RST makes the first handler's 502 send fail,
`ngx_http_terminate_request` frees the sibling's resolver ctx inside
the walk, and iteration 2 writes through it. Verbatim chain: ALERT
`could not cancel … resolving` → `worker process 21 exited on signal 11
(core dumped)`; ASAN floor pinpoints `ngx_resolver.c:2142`. The race is
characterized, not just hit: DNS-failure holds of 50–300 ms, 20–40% win
rate per attempt, negative controls (answer-then-RST, half-close, RST
before body, no RST) all survive, fixed 1.31.9 zero alerts and zero
deaths under every cell. This was the first public **non-ASAN** crash
for this CVE (Censys had ASAN + custom-debug; Cloudflare's 2026-11-20
repro is ASAN-built) — recorded with the honest footnote that the
novelty window closed the day Cloudflare published.

**CVE-2026-121810 — honest negative + the first published gate
analysis.** ~120 attempts across 11 configurations (worker_connections
32–128, idle/FIN/abort stream mixes, h1-refiller saturation pinning
free slots at `connection_n/16`): no ASAN report, no stock crash, no
differential. The precondition fires — drain events (`reusing
connections`) are produced on demand — but drain victims were ~100% h1
keepalives. The source-verified gate analysis explains why the obvious
interleaving cannot work in 1.31.8: for the parent's re-mark to run
inside the stream-create window, the drain must *synchronously* close a
same-parent stream passing both `ngx_quic_close_stream()` gates
(`recv_state != RECV` and `send_state ∈ {DATA_RECVD, RESET_RECVD}`) —
and every stream the drain can close is reusable-marked only while
still *waiting for request bytes*, failing gate 1, while RST'ing it
sets `RESET_SENT`, failing gate 2 until a round trip later. The real
interleaving must be second-order; the lab ships the infrastructure,
the matrix, and the next angles (instrumented debug builds,
uni-stream/two-parent pressure). Cloudflare's 2026-11-20 "also not
reproduced, fix-commit analysis only" is external validation; our why-not
remains the only published one.

**CVE-2026-123633 — honest partial: window proven, terminal UAF not
landed.** What is reproduced differentially, on all four builds (3/3
per the harness): on vulnerable 1.31.8 an **active** h2 connection
carrying an in-flight proxied request sits in the reusable-connection
queue and the drain selects it mid-request — `VULNERABLE-STATE (drain
GOAWAY'd the active h2 conn)`; on 1.31.9 this can never happen. The
server-side kill chain is captured verbatim on a debug build
(`reusable connection: 1` → `reusing connection` → `http2 send GOAWAY
frame: last sid 3` → `http upstream connect: -2`). Three corrections to
the naive mechanism model came out source-verified: the incomplete
frame that marks the connection is a **SETTINGS** frame (not HEADERS);
marks insert at queue **head** while the drain takes **oldest-first**;
and the pressure instrument that actually works is **busy unread h1
requests** (idle fillers are self-defeating — the drain eats its own
oldest marks). What is *not* reproduced: the terminal free-under-caller
(~200 race attempts, no ASAN report, no stock crash — below Censys's
stock-crash parity). The unlanced step is dead-socket detection inside
the drain-invoked read handler, a sub-millisecond window (SO_LINGER-0
RSTs discard the unACKed completion bytes; later closes land one stack
frame too late). Fixed controls: zero markers under identical triggers.

**CVE-2026-113425 — lab dropped, presented from prior art.** On
2026-11-20 (L20), after a 24 h landscape re-check, we dropped the
planned local lab: Cloudflare's deep dive had just published an
independent ASAN repro (faults 1.31.8, clean 1.31.9) plus the complete
mail-proxy mechanism (queued reply + `ngx_mail_send()` write handler +
client reset during `auth_http`; two conditions: write event already
registered + same event-loop pass; valid credentials not needed). With
Xint's disclosure and F5 K000163931 on top, a scoped local lab had
nothing left to add. Spending the closure effort instead of re-deriving
public results was the right call.

## 4. Position vs the public landscape (2026-11-20)

**Uniquely ours** (nothing public contradicts these; path:line verdicts
in [docs/prior-art.md](prior-art.md)):

- **123007**: the stock-build TLS differential + crash matrix with a
  `http2 off` mitigation control (the only *executable* `http2 off`
  verification among public artifacts); the quantified flood heuristic
  (`total_bytes/8 > payload_bytes + 1 MiB`) and the server-direction
  priming measurement; the **libc matrix** (musl SIGILL vs glibc
  SIGSEGV, glibc-only write primitive) — first public.
- **123634**: the **first public stock-build (non-ASAN) crash** plus
  the quantified race recipe (50–300 ms holds, 20–40%/attempt, the
  `could not cancel` alert as path marker).
- **121810**: the **gate analysis** — the only published explanation of
  why the obvious interleavings cannot fire, now externally validated
  by Cloudflare's independent non-reproduction.
- **123633**: the 3/3 four-build **differential oracle** + the three
  source-verified mechanism corrections.
- Cross-cutting: phase-tracked verdict discipline (UNCLEAR-never-PATCHED
  + confirm re-runs) — a refinement of the post-hoc discipline both
  upstreams adopted after their own mislabel bugs, and the only one
  that generalizes past a single script.

**Covered by public prior art** (we adopt, don't re-claim):

- **Cloudflare (2026-11-20)**: ASAN verification of 4/5 (123007,
  123633, 123634, 113425 fault on 1.31.8, clean on 1.31.9), the full
  113425 mechanism, the 123634 walk-list mechanism + first-affected
  corrections (0.6.18 / 0.5.33), and the mitigation matrix.
- **Rapid7**: the full marker-verified RCE, the flood-budget *concept*
  (client-sent carrier), the exact 2^64 window wrap, the AVX-512/glibc
  constraint set. Cloudflare's characterization — "suitable only for
  demonstrating the attack against a freshly started local container" —
  is the operative caveat on the public PoC.
- **Censys**: the compact accounting oracle (ours is a convergent
  reinvention, down to the same 4 MiB refund constant), the
  release/arm64/worker/heap matrices, the 123633 stock crash, 123634
  ASAN-only repro, 113425 cmd-exec from retained artifacts.
- **Xint / Wiz**: discovery and disclosure; exploits never released —
  and fake "exploits" circulate on GitHub (audit before running
  anything).

## 5. Operational lessons

1. **Legal priming beats fighting the flood heuristic.** The heuristic
   formula (`total_bytes/8 > payload_bytes + 1 MiB`) means bandwidth
   figures alone mislead: the public "~119 GiB" is *necessary but not
   the whole story* — the payload allowance must be grown first, and it
   grows in **both directions** (Rapid7's client-sent HEAD/HPACK
   carrier; our server-sent downloads). Neither direction is documented
   upstream.
2. **nginx rate-limits by frame count, not just bytes.** Outbound
   frames are capped (10,000) and PING payloads are 8 bytes — you
   cannot blast data out of nginx with control frames. The working
   staging shape is many streams of unread DATA held by kernel
   backpressure (120 × 256 KiB), with grants computed relative to the
   live window (frame-build-time deduction).
3. **ASAN builds on high-ASLR WSL2: plain `./configure`, sanitizer
   flags at make time.** Configure's ASAN-instrumented test programs
   hang ~295 s on this kernel, and `setarch -R` is seccomp-blocked in
   Docker (`personality(ADDR_NO_RANDOMIZE)` = EPERM). Running configure
   plain and injecting `-fsanitize=address` into `CFLAGS`/`LINK` at
   make time gives fully instrumented builds; an ASLR-lottery re-exec
   entrypoint (bounded retries) handles the occasional bad sanitizer
   layout. Also: bound *every* network call in Dockerfiles — an
   unbounded `curl` in a build stage hung two lab attempts.
4. **Bounded-everything worker discipline is what makes delegated,
   long-running race hunts survivable**: `timeout 600` on compose,
   `timeout 120` per trigger, per-attempt SIGALRM watchdogs,
   `settimeout` on every socket, controls run before the vuln attempt,
   worker-safety greps after every matrix, single-worker services so a
   death is unambiguous.
5. **Measurement traps that mislabel controls**: lingering close (30 s
   of silence that looks like rate-related death), patched-build FIN
   surfacing one drain later on primed connections, and idle-filler
   pressure defeating itself (the drain eats the oldest marks first).
   Phase-tracked verdicts exist precisely because these traps are
   generic.

## 6. What remains open

- 121810 terminal reproduction — open everywhere (Censys, Cloudflare,
  this repo all failed); our gate analysis narrows the search to
  second-order interleavings.
- 123633 terminal UAF — the in-drain dead-socket detection window
  (sub-millisecond); Censys's stock crash remains the parity target.
- Unbuffered-proxy accounting behavior (Censys: inconclusive, < 4 MiB
  queues); the exact nginx source sites of the dual-direction payload
  allowance; the musl SIGILL faulting instruction.
- Non-x86-64 crash/RCE remains unverified anywhere public (Censys
  covered arm64 accounting only; Rapid7's profiles are x86-64 glibc).

## 7. References

Same canonical list as the PTES report (URLs + dates):

- Xint writeup (2026-11-18) —
  <https://xint.io/blog/nginx2root-remote-code-execution>
- nginx security advisories — <https://nginx.org/en/security_advisories.html>;
  CHANGES — <https://nginx.org/en/CHANGES>
- Cloudflare deep dive (2026-11-20) — <https://blog.cloudflare.com/nginx2root/>
- CISA advisory 2026-136 (2026-11-19) —
  <https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-nginx-could-allow-for-remote-code-execution_2026-136>
- Ubuntu USN-9182-1 (2026-11-20) —
  <https://ubuntu.com/security/notices/USN-9182-1>
- Rapid7 repo — <https://github.com/sfewer-r7/CVE-2026-123007>
- Censys repo — <https://github.com/Censys-Research/nginx2root>
  (commit `332d951`, 2026-11-19)
- The Hacker News (2026-11-18) —
  <https://thehackernews.com/2026/11/10-year-old-nginx-http2-flaw-lets.html>
- By identifier (finding-sheet Sources; no URL recorded there): F5
  K000164058 / K000163931, CIRCL TR-105, Rapid7 blog (S. Fewer), Censys
  blog, Wiz blog (N. Ohfeld, T. Schwartz), Qualys TRU, SecurityWeek,
  Laravel Forge KB, Tenable/watchTowr FAQs.

Internal: [docs/finding-sheet.md](finding-sheet.md) ·
[docs/prior-art.md](prior-art.md) · [docs/ptes-report.md](ptes-report.md) ·
lab harnesses `lab/verify.sh`, `lab/{121810,123633,123634}/verify.sh` ·
task log L1–L21 (`odd/tasks/nginx2root.md`).
