# Prior art — public NGINX2Root artifacts vs this repo (F2 step 0)

Written 2026-11-19. Scope: every public NGINX2Root/CVE-2026-123007 artifact,
compared against our F1 work, with an honest original-vs-redundant verdict per
artifact. Citations use `path:line` against the exact trees we read:

**Landscape refresh 2026-11-20 (T7):** Cloudflare's deep dive added as a
compared artifact; per-CVE overlap verdicts for our final F3 outcomes
recorded below; the 113425 local lab is dropped (L20) — that CVE is
presented from public prior art only. The original 2026-11-19 F1 verdicts
stand unchanged.

- **Rapid7** — `sfewer-r7/CVE-2026-123007`, cited as `r7/…` (clone at
  `/tmp/r7-nginx2root-poc`; the revision Censys pinned for its reproduction
  was `ebff45f` per `censys/docs/REPRODUCTION.md`).
- **Censys** — `Censys-Research/nginx2root`, cited as `censys/…` (single
  squashed public commit `332d951`, 2026-11-19).
- **ours** — this repository, cited as `poc/…`, `lab/…`.
- **Xint** — disclosure writeup only (xint.io blog); no public PoC code.
- **Wiz** — blog + local Docker demo; **PoC not public**. Nothing below
  relies on it. (WormW/nginx2root-rce-lab claims an AVX-512-free adaptation;
  unaudited, no code read.)
- **Cloudflare** — engineering blog `blog.cloudflare.com/nginx2root`
  (2026-11-20), cited as `cf/…`; no public code repo — the artifact is
  the blog's build + test account (public nginx 1.31.8 @ `140aa94` and
  1.31.9, both built with AddressSanitizer).

## Summary

Every tier of the CVE-2026-123007 kill chain we touched in F1 has prior art in
at least one public artifact: the accounting oracle is Censys's compact PoC
(ours is a convergent reinvention, down to the same 4 MiB refund constant),
the deterministic worker crash is Rapid7's `simple-trigger-poc.py` (ours
differs in trigger mechanism, window bookkeeping, and TLS handling but lands
in the same ≥ 2^63 signed-window tier), and — the finding we had credited to
ourselves — defeating nginx's `http2 flood detected` heuristic by raising the
payload allowance *before* flooding is explicit, commented, and exactly sized
in Rapid7's exploit (their client-sent "flood-budget carrier"; our variant
primes in the opposite direction with server-sent downloads). What remains
genuinely ours: the quantified statement of the heuristic itself
(`total_bytes/8 > payload_bytes + 1 MiB` — appears in no upstream repo), the
opposite-direction priming measurement, a TLS-capable differential (Censys's
compact client is h2c-only and their own TLS attempts failed or false-positived),
the verified `http2 off` mitigation control (neither upstream mentions `http2
off` anywhere), and the phase-tracked verdict discipline with confirm re-runs.
Both upstreams had mislabel bugs of exactly the class our phase tracking
prevents, which is evidence the discipline is worth shipping.

**2026-11-20 landscape:** Cloudflare published the first public ASAN
verification of the family — 123007, 123633, 123634 and 113425 each fault
on 1.31.8 and run clean on 1.31.9; 121810 not reproduced (their section
rests on the fix commit and published analysis). This changes no F1
verdict above (their 123007 repro is ASAN-build-based; ours is a
stock-build differential) and externally validates our 121810 honest
negative. Per-CVE overlap verdicts against our final F3 outcomes: see the
landscape section below.

## Capability × artifact

| Capability | Xint writeup | Censys repo | Rapid7 repo | Wiz | this repo |
|---|---|---|---|---|---|
| Discovery & disclosure | ✔ (origin) | — | independent | independent | — |
| Safe accounting oracle (differential) | described §5.1 | ✔ `censys/h2c_flow_control_test.py:348-411` | ✔ bootstrap oracle `r7/exploit/nginx_rce/bootstrap.py:154-206` | not public | ✔ `poc/diagnose.py` (reinvention) |
| Oracle verdict discipline | — | stage exit-code + `probe_sent` guard `censys/h2c_flow_control_test.py:154-171` | restart-on-missing-oracle rule `r7/NGINX_HTTP2_STANDALONE_REPRODUCTION.md` | not public | ✔ 4-phase tracking + `--confirm` `poc/diagnose.py:24-40,386-404,450-467` |
| Accounting oracle over TLS | — | ✘ failed/false-positive, "TLS unvalidated" `censys/docs/COMPACT-POC.md` (TLS status), `censys/evidence/release-validation/compact-avx512-vm/RESULTS.md` | ✔ exploit chain is TLS-native `r7/NGINX_HTTP2_STANDALONE_REPRODUCTION.md:88-104` | demo only | ✔ crash matrix over TLS; oracle h2c `poc/crash.py:1-75`, `lab/README.md` |
| Deterministic crash PoC | described | — (no flood PoC shipped) | ✔ `r7/simple-trigger-poc.py` (~60 GiB, signal 11) | not public | ✔ `poc/crash.py` (~52 GiB, signal 11) |
| Full RCE (marker-verified) | described | reproduced Rapid7's, not own `censys/docs/REPRODUCTION.md` | ✔ origin `r7/exploit/` | claimed, not public | — (out of scope) |
| Flood-heuristic defeat (priming) | — | — (compact PoC never floods; 0 grep hits) | ✔ explicit, sized `r7/simple-trigger-poc.py:338-346`, `r7/exploit/nginx_rce/bootstrap.py:447-471` | not public | ✔ independent, opposite direction `poc/crash.py:145-158` |
| Heuristic formula quantified | — | — | — (budget sized, formula never stated) | not public | ✔ `lab/README.md:45-52` |
| Window target: crash tier (≥ 2^63) | described | — | ✔ exactly 2^32 MAX increments `r7/simple-trigger-poc.py:364-376` | — | ✔ computed from oracle-validated start `poc/crash.py:143-144,180-184` |
| Window target: exact 2^64 wrap | described | — | ✔ `near_wrap`, distance 14392 `r7/exploit/nginx_rce/bootstrap.py:254-266` | — | — (crash-oriented only) |
| State-aware staging grants | — | fixed 8 MB staging `censys/h2c_flow_control_test.py:367-381` | profile-driven `r7/exploit/nginx_rce/bootstrap.py:165-176` | — | ✔ measured-window-relative `poc/diagnose.py:239-249` |
| Idle/keepalive during flood | — | n/a | ✔ 96 rotating one-byte-Range owners `r7/exploit/nginx_rce/bootstrap.py:268-323` | — | ✔ single zero-window keepalive stream `poc/crash.py:478-483` |
| Verified `http2 off` mitigation harness | recommended | ✘ (0 mentions) | ✘ (0 mentions) | — | ✔ NOT-H2 control `poc/diagnose.py`, `lab/verify.sh` |
| Release/compat matrix | — | ✔ 1.30.0–1.31.9 ×86-64/arm64 ×workers ×heaps ×response types | ✔ per-profile (1.31.6, 1.31.8 + historical) | — | narrow: 1.31.8/1.31.9 + mitigation control |
| Evidence format | writeup | pcaps + JSON + retained markers | client logs + external marker check | video/gif | phase-tracked stdout + exit codes + log greps |

## Per-artifact notes

### Xint (writeup only)

Origin of everything: five-CVE disclosure, kill-chain designations we follow
(Xint §5.1 accounting sequence, §5.1.2 crash chain — cited from `lab/README.md`
"Oracle design" and `poc/crash.py` docstring), the `http2 off` mitigation
recommendation, exposure numbers. No public code; nothing to diff against
beyond the sequences our F1 already reimplemented from the writeup.

### Censys (`Censys-Research/nginx2root`)

**What they did.** A single-file compact h2c accounting PoC plus the widest
verification matrix in public, plus independent reproduction of Rapid7's full
RCE and behavior-level reproductions of three sibling CVEs.

- Oracle sequence (`censys/h2c_flow_control_test.py`): fill the connection
  window to exactly 0 with 73×896 + 127 bytes of small responses (stages
  print at :348, requests at :350-356), raise to MAX via `WINDOW_UPDATE(0,
  MAX)` (:360-361), request an 8 MB file on stream 157 and grant 8 MB of
  stream credit in 122×65535 chunks **without reading** (:366-381), refund
  event `WINDOW_UPDATE(0, 4 MiB)` then `RST_STREAM(157, CANCEL)` (:383-391),
  probe `WINDOW_UPDATE(0, 1)` (:400-404), sync PING `POC-SYNC` (:407-411).
  `SO_RCVBUF` pinned to 262144 at :306. Result classification only from a
  complete post-probe exchange: `summarize_result` (:154-171) requires probe
  sent + no close + no GOAWAY + PING ACK; anything else is INCONCLUSIVE or
  negative — never "patched" by absence of evidence.
- **Verified compatibility matrix** (the compact table the family needed):
  - Releases, x86-64 native: accounting error confirmed on **every release
    1.30.0–1.31.8**, 1.31.9 rejects (README "Compatibility matrix";
    `--versions` support at `censys/h2c_flow_control_test.py:497-508`).
  - arm64 native: verified on 1.30.0, 1.30.6, 1.31.0, 1.31.5, 1.31.6,
    1.31.7, 1.31.8 (+1.31.9 rejecting) —
    `censys/evidence/release-validation/arm64-results-summary.json`.
  - Workers/heaps: 72-case matrix (8 releases × 1/2/4 workers ×
    fresh/40/200-request heaps): 63 positive ("accepted + PING ACK"), 9
    patched controls ("closed before probe") —
    `censys/evidence/release-validation/worker-heap-matrix.md`.
  - Response types (`censys/evidence/release-validation/response-matrix.csv`):
    static full/range, upstream buffered full/range/chunked/close-delimited —
    all positive on every vulnerable release; the `upstream-short` row is
    negative on *all* versions including 1.31.8, with a queued-bytes lower
    bound of ~3.1–3.2 MB < 4 MiB — matching the README's note that
    unbuffered proxying is *inconclusive* because it "leaves insufficient
    queued data".
  - Full RCE: Rapid7's chain independently reproduced on matched native
    x86-64 AVX-512 (1.31.6 and 1.31.8, fresh + exercised;
    119.02 GiB / 166 s / marker UID 101:101 / post-dispatch double-free
    signal 6) — `censys/docs/REPRODUCTION.md`,
    `censys/evidence/cve-2026-123007/RCE-CONFIRMED.md`. 1.31.7 RCE
    unverified (no calibrated profile); 1.31.9 negative control fails fast
    at the in-band fingerprint (`censys/evidence/release-validation/VALIDATION.md`).
  - Sibling CVEs: 123633 stock worker crash on 1.31.8 (no RCE adapter);
    123634 ASAN UAF + custom-debug crash only; 121810 **not reproduced**;
    113425 command execution confirmed **from retained artifacts**
    (1.31.8 ×3 runs, 1.31.7 ×1, patched negative; "not independently
    replayed") — `censys/cve-2026-*/README.md`.
- **TLS honesty.** The shipped compact client is h2c-only; TLS is explicitly
  "not validated" (`censys/docs/COMPACT-POC.md`, `censys/SECURITY.md`). Their
  AVX-512 VM notes record why: on direct TLS both versions closed at the
  4 MiB update (different effective windows, 41,008 bytes apart), and on
  host-network TLS **both versions false-positived** (patched 1.31.9 also
  accepted the one-byte update and answered PING because fewer than 4 MiB
  remained queued) —
  `censys/evidence/release-validation/compact-avx512-vm/RESULTS.md`. Their
  bounded diagnostics (2 MiB / 3 MiB updates, rcvbuf tweaks, settling
  intervals) all failed to produce an honest TLS differential. One orphaned,
  unreferenced CSV (`censys/evidence/release-validation/tls-oracle-matrix.csv`)
  shows a TLS oracle differential across 8 releases with
  Rapid7-bootstrap-style constants (rejection at `increment 2147483647 …
  window 1792`), but no doc in the repo references it and the client that
  produced it is not public; we treat their public claim (TLS unvalidated)
  as canonical.
- **Exit-code defect.** Their own RESULTS.md records that the original
  client returned `None` (shell exit 0) when the target closed mid-sequence,
  "incorrectly ma[king] a patched rejection look successful" — fixed with a
  `probe_sent` guard. Same bug class Rapid7 documents for their trigger
  ("An earlier version could spin after a clean TLS close"). Our phase
  tracking (`poc/diagnose.py:24-40`) is the systematic answer to exactly
  this failure mode.

### Rapid7 (`sfewer-r7/CVE-2026-123007`)

**What they did.** The public reference exploit: full marker-verified RCE
against stock nginx 1.31.8 (Debian 13, glibc 2.41), plus a standalone
accounting-oracle + crash trigger.

- **Oracle / double-credit trigger** (differs from both Censys's and ours):
  consume the initial 65,535-byte window with measured bodies
  (`r7/simple-trigger-poc.py:218-233`), clamp TCP to 1024 bytes for physical
  backpressure (:237-238), set `SETTINGS_INITIAL_WINDOW_SIZE=0` (:243), park
  two 896-byte responses with per-stream credit only (:246-247), then the
  root-cause event (:257-261): `WINDOW_UPDATE(0, 1792)` (exact pending-byte
  return) + `WINDOW_UPDATE(0, MAX)` + per-stream `MAX-1` increments +
  `SETTINGS(2)` — the stream windows now exceed MAX **by the client's own
  doing**, so *nginx itself* resets both streams with FLOW_CONTROL_ERROR and
  the cleanup path refunds the still-queued DATA credit a second time; a
  following `WINDOW_UPDATE(0, MAX)` passes the underflowed check. Verified
  server-side resets and the ten released public bytes are asserted
  (:309-326). The exploit's generalized version is
  `r7/exploit/nginx_rce/bootstrap.py:165-176` (`reserved = 2 × primary_size`,
  same event shape), returning the exact post-bootstrap window
  `2*MAX_WINDOW + reserved - release_size` (:250) — the RCE does its later
  arithmetic *from that exact value*, not from a guess. A 7 MiB HEAD-filler
  carrier + 262,144 TLS KeyUpdates give the deterministic parser/output
  boundary (:162-196); oracle liveness is proven with PINGs (`POC-SYNC`,
  `H2HBKEY0`).
- **Q1 — flood heuristic.** Explicit, designed, and commented — not implicit:
  `r7/simple-trigger-poc.py:338-346`: "Nginx's flood check permits control
  traffic only in proportion to parsed payload. These 512 maximum-size but
  header-empty HEAD requests provide enough legitimate input accounting for
  the unavoidable 52 GiB sequence of tiny WINDOW_UPDATE frames." (512 ×
  ~16.78 MB HPACK filler ≈ 8 GiB client-sent payload ⇒ ~64 GiB allowance for
  the 2^32 × 13 B ≈ 55.8 GB crash flood.) The full exploit sizes it exactly:
  `r7/exploit/nginx_rce/bootstrap.py:447-471` — "The fixed carrier raises
  Nginx's flood budget. Rotating live Range owners prevents Nginx's
  idle-stream timer from terminating the WU flood" — 960 HEADERS frames ×
  16,777,215 B payload across 320 HEAD requests = 15.00 GiB
  (`carrier_frames`/`carrier_frame_payload_bytes` in
  `r7/exploit/profiles/golden-nginx-1.31.8-debian13-amd64.json`), then the
  (2^33+1)-frame WINDOW_UPDATE replay ≈ 104 GiB; totals match the reported
  119.02 GiB. The carrier and the flood ride the **single** corrupted
  connection (the window is per-connection); the 16 auxiliary connections
  open only *after* the numeric stage, for heap shaping
  (`r7/exploit/nginx_rce/bootstrap.py:329-345`). There is no pacing trick —
  the C streamer (`r7/exploit/streamer.c`) blasts at line rate; **the budget
  is the defense**. Nowhere do they state the heuristic's formula (no
  `1048576`, no 8:1 arithmetic anywhere in the repo — grep-verified).
- **Q2 — window target.** Two tiers, both exact:
  - Crash tier (`r7/simple-trigger-poc.py:364-376`): "MAX is just under 2^31.
    Exactly 2^32 accepted increments therefore move the 64-bit connection
    window through its signed midpoint." 2^32 × MAX from start ≈ 2×MAX+1782
    lands just above 2^63 ⇒ (off_t)-negative ⇒ inverted buffer ⇒ huge
    apparent length into TLS memcpy staging ⇒ noncanonical endpoint ⇒
    deliberate SIGSEGV; fired by a 1-byte grant on a parked one-byte Range
    owner (:388). 128 rotating owners keep the sequence alive (:374-386).
  - RCE tier (`r7/exploit/nginx_rce/bootstrap.py:254-266`): `near_wrap()`
    sends 2^33+extra MAX increments so the 64-bit window **wraps past 2^64**
    to `(-distance) & MASK64` with `distance = negative_distance = 14392`,
    then a final legal "tailored" increment lands exactly; the wrapping copy
    is released by `WINDOW_UPDATE(0, release_increment=14393)`
    (`r7/exploit/nginx_rce/reclaim.py:226`, invariant
    `negative_distance + 1 == release_increment` enforced at
    `r7/exploit/nginx_rce/profiles.py:380-382`) — this is the bounded
    14,393-byte disclosure copy.
- **Q3 — glibc/CPU dependency.** The wrapping copy must be performed by a
  memcpy whose huge-length behavior is *bounded and calibrated*: the profile
  pins `calibration.backend = "x86-64-glibc-evex-v1"`
  (`r7/exploit/nginx_rce/constants.py:10`, profile :6),
  `heap.memcpy_variant = "glibc EVEX/YMM unaligned implementation"` (:243),
  `required_cpu_flags = ["avx512f", "avx512vl"]` (:246-248), target
  `libc = "Debian glibc 2.41-12+deb13u4"` (:16); non-x86-64 targets are
  rejected outright (`r7/exploit/nginx_rce/profiles.py:78-83`). The schema
  says it plainly: "a profile can describe another architecture, but it
  cannot supply missing architecture-specific exploit code"
  (`r7/exploit/profiles/SCHEMA.md:12-15`). Constraint set as documented:
  ~119.02 GiB plaintext, each ~1.08 GiB owner interval inside the 60 s send
  timeout and the whole connection inside the 1 h lifetime (⇒ the ≥300
  Mbit/s floor our finding sheet carries), fresh/lightly-exercised heap
  ("Earlier tests after substantial prior traffic … failed in two
  attempts"), four workers, direct TLS backpressure, no h2-terminating
  intermediaries, 16 auxiliaries reaching the same worker
  (`r7/NGINX_HTTP2_STANDALONE_REPRODUCTION.md` "Run the RCE PoC" +
  validation section). Censys's reproduction adds: CPU flags are "necessary
  but not sufficient: runtime glibc must select the calibrated EVEX/YMM
  copy routine" (`censys/docs/REPRODUCTION.md`).

### Wiz

Blog-level disclosure and a local Docker demo (fresh container, same host).
**PoC not public** — nothing further can be compared, and we do not
speculate.

### Cloudflare (`blog.cloudflare.com/nginx2root`, 2026-11-20)

**What they did.** Built the public nginx trees — 1.31.8 (commit `140aa94`)
and 1.31.9 — with AddressSanitizer and tested four of the five CVEs (flow
control 123007, HTTP/2 UAF 123633, resolver 123634, mail proxy 113425):
each faults under ASAN on 1.31.8 and runs clean on 1.31.9. They did **not**
reproduce 121810; their HTTP/3 section is analysis of the fix commit plus
published writeups. No code released — the blog is the artifact.

- **113425, first full public mechanism:** two connections share one mail
  session; during `auth_http` the reply the protocol handler prepared
  stays queued and the client write handler remains `ngx_mail_send()`. If
  that handler runs and the write fails because the client reset the
  connection, the client connection closes and destroys the session while
  the auth connection still points at it. Two conditions: the client
  write event must already be registered (e.g. the client stopped
  reading), and the login command + reset must be handled in the same
  event-loop pass. Valid credentials are **not** needed. Fix: discard the
  queued reply when the auth request begins + three further commits
  blocking client writes during auth phases.
- **123634 mechanism detail:** the resolver waiting-list walk frees the
  next ctx when a request + mirror/SSI subrequest share one resolver node
  and the first handler ends the request; the `could not cancel <name>
  resolving` alert is unpatched-only (one CNAME-following variant
  produced no alert); the fix swaps the handler and downgrades the alert
  to debug.
- **First affected:** 123634 since 0.6.18; 113425 since 0.5.33.
- **Mitigation matrix:** `http2 off` blocks 123007+123633; removing QUIC
  listeners + `http3 off` blocks 121810; fixed upstream groups for 123634
  (`mirror_request_body on` is NOT sufficient — SSI reaches it too); bind
  mail listeners to trusted networks for 113425; restart required (reload
  leaves old workers with old sessions).
- **Status as of 2026-11-19 (per the blog):** none of the five in CISA
  KEV; no in-the-wild reports; Xint and Wiz exploits not released; the
  Rapid7 PoC is public but "suitable only for demonstrating the attack
  against a freshly started local container"; fake 'exploits' circulating
  on GitHub.

## Verdicts on the five key questions

1. **Flood heuristic** — *prior art for the concept, ours for the
   measurement and the opposite direction.* Rapid7 defeats the heuristic by
   explicit client-sent payload staging sized as a "flood-budget carrier"
   (citations above); Censys's compact PoC never floods (zero grep hits for
   flood/priming/lingering in their tree). Our priming is an independent
   discovery of the same requirement with a different mechanism: ~10 GiB of
   *server-sent* `/big.bin` downloads raising the allowance to ~80 GiB
   (`poc/crash.py:145-158`, `lab/README.md:45-52`). Read together, the two
   artifacts show nginx's payload allowance grows with payload **in both
   directions** (their HEAD/HPACK carrier is arithmetically necessary for
   their run to survive; our download priming is measured) — neither
   upstream documents the other direction. The quantified heuristic
   (`total_bytes/8 > payload_bytes + 1 MiB`, unprimed death within a few
   hundred MB, ~10 GiB ⇒ ~80 GiB) exists only in our docs.
2. **Window target** — *crash tier: convergent (both ≥ 2^63); exact-wrap
   tier: Rapid7 only.* Their crash trigger uses the exact doubling identity
   (2^32 increments from their known start); ours computes
   `ceil((2^63 − (MAX + FIRST_RETURN))/0x7FFFFFFF) + 16` from the
   oracle-validated staging constant (`poc/crash.py:180-184`) — same tier,
   different bookkeeping. The RCE's `2^64 − d` exact wrap (`near_wrap`)
   has no counterpart here and none is needed for a crash.
3. **glibc/CPU dependency** — theirs, fully: RCE requires the calibrated
   glibc EVEX/YMM memcpy (avx512f/avx512vl, glibc 2.41 profile,
   x86-64-only guard); the crash tier takes the deliberately fatal
   noncanonical path instead. We inherit the constraint set as verified
   fact; our musl/glibc<2.24 crash questions were answered by F2 (crash
   survives musl as SIGILL, glibc 2.23 as SIGSEGV — finding sheet).
4. **Censys compatibility matrix** — extracted above (per-artifact notes);
   the compact table to reference is releases 1.30.0–1.31.8 x86-64 (all
   verified) + arm64 (7 releases) + 72-case worker/heap matrix + response
   types (unbuffered inconclusive) + RCE only on AVX-512 native x86-64
   (1.31.6/1.31.8) + per-CVE statuses (123633 stock crash; 123634
   ASAN-only; 121810 not reproduced; 113425 cmd-exec from retained
   artifacts).
5. **Oracle comparison** — ours is a **convergent reinvention** of Censys's
   compact PoC: same oracle concept (window→MAX, stage DATA unread,
   mid-size stream-0 refund, cancel streams, small probe), converging even
   on the 4 MiB refund constant (their fixed 4 MiB at
   `censys/h2c_flow_control_test.py:388`; our measured-invariant
   `FIRST_RETURN = 4 << 20` at `poc/diagnose.py:117`). Real differences:
   staging shape (their 1×8 MB stream vs our 120×256 KiB streams,
   `poc/diagnose.py:91-92`), probe size (1 byte vs 1 MiB
   `poc/diagnose.py:130`), coverage (their 17-release matrix vs our
   1.31.8/1.31.9 pair + `http2 off` control), evidence format (pcaps/JSON
   vs phase-tracked stdout), and robustness: their fixed 4 MiB threshold is
   transport-sensitive — their own TLS runs failed or false-positived for
   exactly that reason — while our measured first-return invariant plus
   bounded drains is what makes our TLS differential (crash matrix) work.

## Landscape refresh 2026-11-20 — per-CVE overlap verdicts

Cloudflare's deep dive against our final F3 outcomes, recorded honestly in
both directions (their blog: 2026-11-20, `blog.cloudflare.com/nginx2root`):

- **123007** — concept overlap on the crash tier only: their repro is
  ASAN-build-based (fault on 1.31.8 @ `140aa94`, clean on 1.31.9); ours is
  a stock-build differential + crash matrix. Every F1 originality verdict
  in "What is original" below stands unchanged.
- **123633** — Cloudflare now has a public ASAN crash (Censys already had
  a stock worker crash). Ours remains distinct: the 3/3 four-build
  differential oracle and the three source-verified mechanism corrections
  (SETTINGS-frame mark shape, head-insert vs oldest-drain queue law,
  h1-pressure instrument).
- **123634** — concept overlap with a real edge retained: their repro is
  ASAN-build-based; ours remains the **first public non-ASAN (stock-build)
  crash**, including the timing-race recipe (50–300 ms DNS-failure holds,
  20–40% win rate per attempt, the "could not cancel … resolving" alert as
  path marker). The novelty window is closed — both recorded, only what is
  ours claimed.
- **121810** — Cloudflare also failed to reproduce; their section rests on
  the fix commit and published analysis. External validation of our honest
  negative and gate analysis, which remains the only published why-not.
- **113425** — lab dropped (L20). Public prior art (Cloudflare full
  mechanism + ASAN repro, Xint disclosure, F5 K000163931) covers repro and
  mechanism; a scoped local lab had nothing left to add.

## What is original in this repo

Honest verdicts:

- **(a) Oracle** — *reinvention, not invention.* Convergent with Censys's
  compact PoC in concept and constants (see verdict 5). Original edges:
  the FIRST_RETURN gap measurement (both edges quantified,
  `poc/diagnose.py:96-116`), transport-robust staging, phase-tracked
  verdicts with `--confirm` re-runs, and the NOT-H2 mitigation control.
- **(b) Crash chain** — *prior art at every stage; differences are
  engineering.* vs Rapid7's simple trigger: double-credit trigger differs
  (client RST_STREAM of 120 staged streams vs their SETTINGS-induced
  server-side resets of 2 parked responses — theirs needs the exact
  response size, ours needs the measured queue depth); window target
  computed from the oracle-validated constant vs their exact doubling
  identity; trigger differs (1 MiB grant + liveness PING on a fresh stream
  vs 1-byte grant on a parked one-byte Range owner); keepalive differs
  (single zero-window stream vs 128 rotating owners); TLS handling differs
  (plain ALPN sockets vs their CPython-3.10/OpenSSL-3-specific MemoryBIO +
  262,144 KeyUpdates bridge); single connection throughout, like them; no
  auxiliary connections (they open 16, post-numeric, for RCE heap shaping).
- **(c) Flood-heuristic priming** — *concept is prior art (Rapid7's
  carrier); the measured formula, the server-direction variant, and the
  "bandwidth necessary but not the whole story" reframe are ours.*
  **Lingering close** (the 30 s death illusion behind `GOAWAY(NO_ERROR)`):
  no upstream repo mentions lingering close (grep-verified in both trees;
  Rapid7 only notes "An earlier version could spin after a clean TLS
  close"), so our characterization appears original. **State-aware staging
  grants** (nginx deducts the connection window at frame-build time; grants
  must be relative to the live window, not hardcoded) — Rapid7 achieves the
  same effect differently (exact-value bookkeeping from the bootstrap
  return, `r7/exploit/nginx_rce/bootstrap.py:250`), so the *requirement* is
  shared knowledge; our measured-estimate formulation
  (`poc/crash.py:201-212`, `poc/diagnose.py:239-249`) is an independent,
  equivalent answer. Call it reinvented, not novel.
- **(d) Verified-mitigation harness + phase-tracked verdicts** — *ours.*
  Neither upstream repo mentions `http2 off` even once (grep-verified);
  their controls are version controls (patched 1.31.9), not mitigation
  controls. Our `mitigated` service + NOT-H2 verdict asserted by
  `lab/verify.sh` in both matrices is the only shipped `http2 off`
  verification among public artifacts. Phase-tracked verdicts: both
  upstreams discipline observation *after* documented mislabel bugs
  (Censys's exit-0-on-rejection defect; Rapid7's spin-after-clean-close);
  ours builds the discipline into the verdict taxonomy itself
  (per-phase attribution, UNCLEAR-never-PATCHED, confirm re-runs) — a
  refinement in the same spirit, and the only one that generalizes past a
  single script.

## Inherited from prior art (adopted as verified, not re-run)

- **Censys release matrix** — accounting error confirmed on all releases
  1.30.0–1.31.8 (x86-64), incl. 1/2/4 workers, fresh/40/200-request heaps,
  and the main response types; 1.31.9 rejects. Our 1.31.8/1.31.9 oracle pair
  remains the in-lab regression, but a 17-release sweep would be redundant.
- **arm64 accounting** — verified by Censys on 7 releases (arm64 closes the
  accounting half of our old open question; crash/RCE on arm64 remains
  unverified anywhere public).
- **AVX-512 RCE constraint** — Rapid7's profile machinery + Censys's
  independent marker-verified reproduction on matched hardware: full RCE
  requires the calibrated glibc EVEX/YMM memcpy (x86-64, avx512f/avx512vl,
  matched glibc build). Treated as settled for the RCE tier.
- **Rapid7 traffic figures & budget design** — ~60 GiB crash / ~119.02 GiB
  RCE and the flood-budget-carrier requirement; our priming measurements
  explain *why* those volumes look the way they do.
- **Patched-build rejection site** — the 1.31.9 capacity check counting
  queued bytes (rejection at the mid-size update) is tri-verified (Censys
  h2c + our oracle + their TLS diagnostics), incl. the 41,008-byte
  effective-window delta Censys measured between builds on TLS.
- **113425 repro + mechanism** — Cloudflare (2026-11-20) ASAN repro and
  full mechanism, on top of Xint's disclosure and F5 K000163931; inherited
  wholesale per L20 (no local lab).
- **First-affected corrections + mitigation matrix** (Cloudflare,
  2026-11-20): 123634 since 0.6.18, 113425 since 0.5.33; `http2 off`
  (123007+123633), QUIC listeners off + `http3 off` (121810), fixed
  upstream groups (123634), trusted-network mail listeners (113425),
  restart-not-reload.

**Remains open** (not answered by any public artifact):

- musl/Alpine crash viability — closed **in this repo** by F2 (crash
  survives as deterministic SIGILL; finding sheet); still nothing public
  elsewhere.
- glibc < 2.24 — closed **in this repo** by F2 (2.23 SIGSEGV); non-x86-64
  crash/RCE remains unverified anywhere public (Rapid7's profiles are
  glibc-2.41 x86-64; Censys arm64 covered accounting only).
- Unbuffered-proxy accounting behavior (Censys inconclusive: < 4 MiB queues).
- Exact nginx-internal accounting sites for the dual-direction payload
  allowance (both directions are demonstrated empirically — theirs
  client-sent, ours server-sent — but neither repo cites the source lines).
- 121810 terminal reproduction — open everywhere: Censys, Cloudflare
  (2026-11-20, fix-commit analysis only) and this repo all failed; our
  gate analysis remains the only published explanation of why the obvious
  interleavings are blocked. The other siblings now have public repro
  (Censys stock/ASAN; Cloudflare ASAN; ours: 123634 stock crash, 123633
  differential oracle).
