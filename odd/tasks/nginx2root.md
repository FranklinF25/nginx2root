# Feature: nginx2root — NGINX2Root family research repo

Family-wide NGINX-only security research on the five NGINX2Root CVEs
(disclosed 2026-11-18), following the standard X2Shell/cve-* playbook.
The Linux SCTP kernel LPE is explicitly out of scope (tracked only).

## Specs

- **S1** — "haz un deepresearch sobre nginx2root": state-of-the-art research
  on the NGINX2Root disclosure, materialized as the living finding sheet
  (`docs/finding-sheet.md`).
- **S2** — "viste que ya vimos 2 cve de ngix cierto? que me sugieres hacer
  porque la idea era hacer lo de siempre aqui" + scope decision
  (2026-11-19): "Familia nginx-only (recomendado)" — differential labs +
  safe detectors for the five CVEs, exploit-constraints audit
  (musl/glibc/arch), full docs trio (finding sheet + PTES report +
  research writeup) with verification matrix. SCTP kernel bug: out of scope.
- **S3** — "crea el repo publico con gh con el mismo nombre que este
  directorio sin readme ni descripcion": public GitHub repo
  `FranklinF25/nginx2root`, no README, no description, created before the
  scaffold.
- **S4** — "ah por cierto usa docker para no ensuciar mi maquina": every
  lab, PoC and exploit runs inside Docker containers (like the companion
  repos); no nginx build, dependency install or exploit traffic touches
  the host.

## Tasks

| ID | Spec | Route | Commit |
|---|---|---|---|
| T1 Create public repo `FranklinF25/nginx2root` (no README/desc) | S3 | inline | n/a (gh) |
| T2 Scaffold + living finding sheet (F0) | S1, S2 | inline | recorded below |
| T3 F1: differential lab 1.31.8 vs 1.31.9 + safe detector + crash PoC + `http2 off` mitigation verification for CVE-2026-123007 | S2 | inline | — |
| T4 F2: exploit-constraints audit — Alpine/musl, glibc < 2.24, arm64, trigger-vs-exploit traffic gap | S2 | inline | — |
| T5 F3: labs + detectors for CVE-2026-123633, -121810, -123634, -113425 | S2 | inline | — |
| T6 Closure: PTES report + research writeup + README verification matrix + cross-links (42533/42945, profile) | S2 | inline | — |

## Log

- **L1** (2026-11-19) — User: "haz un deepresearch sobre nginx2root".
  Deep research completed against primary sources (Xint writeup, nginx
  advisories/CHANGES, F5 K000164058, CIRCL TR-105, Qualys, Rapid7, Censys,
  Wiz, THN, Laravel Forge). Key facts captured for the finding sheet.
- **L2** (2026-11-19) — User: "revisa esto tambien: https://thehackernews.com/2026/11/10-year-old-nginx-http2-flaw-lets.html".
  THN article cross-checked: accurate; adds Plus fix mapping (R34–R36 no
  fix; 123633 fixed earlier in 37.2.0.1/37.0.7.1), distro status, Rapid7
  constraints (128 GB, ≥300 Mbit/s, avx512f/vl glibc path).
- **L3** (2026-11-19) — User repo review: confirmed prior nginx work
  (cve-2026-42533/42945, script-engine heap bugs, 1.30.0→1.30.1) and the
  standard playbook. Correction: http2shell is Brotli/Node CVE-2026-111497,
  NOT nginx HTTP/2 — no direct prior art; only lab discipline transfers.
- **L4** (2026-11-19) — Scope decision via question: "Familia nginx-only
  (recomendado)". SCTP kernel LPE out of scope.
- **L5** (2026-11-19) — User: "espera antes crea el repo publico con gh con
  el mismo nombre que este directorio sin readme ni descripcion". Repo
  created empty, then scaffold proceeds.
- **L6** (2026-11-19) — T2 scaffold commit `66c30e9` (structure + living
  finding sheet + LICENSE); history rebased onto empty root `f7aab07` so
  the whole slice is assessable as a committed range.
- **L7** (2026-11-19) — User: "ah por cierto usa docker para no ensuciar mi
  maquina". New constraint S4: Docker-only execution for all lab work.
- **L6** (2026-11-19) — T2 scaffold commit `837165a` (structure + living finding sheet + LICENSE).
- **L8** (2026-11-19) — T3 oracle validated by delegated worker: 120
  streams x 256 KiB staging (kernel backpressure, no PING flood — nginx
  caps outbound frames at 10000), 4 MiB first-return, RST+drain second
  return, oversized WU probe. 4/4 stable verdicts, zero worker deaths.
  Findings: nginx frame cap, 8-byte PING payloads, sendfile-off staging
  mechanics; lab conf lacks sendfile on (production default) — noted for
  F2. Commit `29466be`.
- **L9** (2026-11-19) — Native review on 2348fe2..8cf9c5c approved
  (lineage review-f04a6e0d43ce4206, lenses risk+reliability, zero
  corrections). 10 advisory findings recorded as task #7; range pushed.
- **L10** (2026-11-19) — User approved continuing with #7 and the crash
  PoC ("si dale segui con la #7 y el crash PoC").
- **L11** (2026-11-19) — #7 closed by delegated worker: all 10 findings
  fixed, regression 3/3 PASS, worker safety clean. Deviation accepted:
  FIRST_RETURN kept at 4 MiB — the bounded first-return drain consumes
  up to 1.5 MiB on the vuln path, so 2 MiB would zero the margin
  (empirically reproduced). TOFU pinning values dated 2026-11-19.
  Commit `4a739b4`.
- **L12** (2026-11-19) — T3 crash PoC closed by delegated worker:
  WORKER-DIED (signal 11, core dumped, PID transitions) on vuln:443,
  SURVIVED on fixed:443, NOT-H2 on mitigated:443; oracle regression
  3/3 PASS; RUN_CRASH=1 verify.sh PASS. Original mechanism findings:
  (1) the flood's real enemy is the 'http2 flood detected' heuristic
  (total/8 > payload + 1 MiB), not timeouts — defeated legally with
  ~10 GiB payload priming; (2) lingering close creates a 30s illusion
  of rate-related deaths; (3) nginx deducts the connection window at
  frame-build time (grants must be state-aware); (4) patched-build FIN
  surfaces one drain later on primed connections. ~52 GiB wire, ~3 min
  per vuln run at ~0.5 GB/s primed. Commit `fb4d4ab`.
- **L13** (2026-11-19) — Delivery of the fix + crash units was blocked by
  reviewer infrastructure: the review-reliability lens (glm-5.3) exceeded
  the relay bound three times and ECONNRESET once across two scopes
  (104KB full range, 58KB wave-1 split), while review-risk captured
  successfully every time (510-715s). Provider declared the slot
  unachievable; two lineages parked with risk captured
  (review-abaeca8739f5d32a, review-812250475160c8fe), no closure.
  User decision (ask_user_choice): disable RDD clone-local and deliver
  under ordinary policy — risk lens had approved both waves and
  reliability was covered empirically (verify.sh 3/3 + crash matrix).
  `gentle-ai review mode disable --scope clone` applied; re-enable is a
  user decision when reviewer capacity recovers.
- **L14** (2026-11-19) — F2 step 0 (worker A): docs/prior-art.md with
  path:line verdicts. Corrections: flood-heuristic priming = prior art
  BY CONCEPT (Rapid7 primes the payload budget with max-size HEAD
  requests before the WU replay, bootstrap.py:447-471); ours = opposite
  direction (downloads) + quantified formula; dual-direction allowance
  growth = joint undocumented. Oracle = convergent reinvention of the
  Censys compact PoC. arm64/AVX-512/release matrix inherited. Commit
  `077100a`.
- **L15** (2026-11-19) — F2 empirical (worker B): musl/Alpine pair +
  glibc 2.23 stretch. ANSWERS: oracle classifies on musl with debian
  constants intact; crash SURVIVES musl (3/3 WORKER-DIED, signal 4
  SIGILL vs glibc signal 11 — DoS holds on every libc, surgical write
  primitive glibc-only); glibc 2.23 crashes (signal 11 — kill predates
  the 2.24 memmove rework). verify.sh default 5/5 PASS ~25 s,
  RUN_CRASH=1 full PASS 5m37s. Finding sheet + README integrated.
  Commits `5b07f8a` + this one. F2 CLOSED.
- **L16** (2026-11-19) — F3 first result (worker, attempt 3 after two
  stalls root-caused and fixed): CVE-2026-123634 STOCK CRASH on 1.31.8 —
  first public beyond Censys's ASAN/custom-debug. Race: DNS-failure holds
  50-300 ms; ALERT "could not cancel" -> signal 11; win rate 20-40%.
  ASAN report ngx_resolver.c:2142 verbatim; fixed survives all. Stalls:
  (1) unbounded curl (patched in both Dockerfiles), (2) ASAN configure
  test-exec hang ~295 s on high-ASLR WSL2 kernel, setarch -R seccomp
  blocked -> plain configure + make-time sanitizer injection. Commit
  `4b2467c`. Next: 121810.
- **L17** (2026-11-19) — F3 wave 1 closed (worker): CVE-2026-121810 NOT
  REPRODUCED (~120 attempts, 11 configs, no ASAN/crash/differential —
  matching public state) but with the first published gate analysis of
  WHY: ngx_quic_close_stream's gates block the obvious interleaving in
  1.31.8; real path must be second-order. H1-refiller saturation
  technique documented. Lab shipped and green (root regression intact).
  Commit `fcb4aec`. Wave 2 next: 123633 (reuses h2lib) then 113425.
- **L18** (2026-11-19) — F3 wave 2 first result (worker, survived 118
  turns + a rate-limit death of its predecessor): CVE-2026-123633
  PARTIAL — differential oracle 3/3 four builds + verbatim kill chain,
  no terminal UAF (below Censys crash parity, above on mechanism: 3
  source-verified corrections incl. SETTINGS-frame mark shape and
  head-insert/oldest-drain queue law). Commit `7034029`. Remaining: 113425.
- **L19** (2026-11-19, night) — User paused the session ("terminamos por
  ahora me quiero dormir"): 113425 worker cancelled mid-flight (its
  partial scaffold in lab/113425/ + poc/113425/ stays uncommitted, review
  before continuing). F3 remaining: 113425 lab. Then closure docs (PTES
  + writeup + verification matrix + cross-links). All delivered work is
  pushed through 43a64ae. Resume: read this doc to ## Log, check
  lab/113425 state first.
