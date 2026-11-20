# Finding Sheet — NGINX2Root family

| Field | Value |
|---|---|
| Event | NGINX2Root ("Nginx to Root") — five pre-auth NGINX RCEs + worker→root kernel chain |
| Disclosed | 2026-11-18 |
| Reported by | Xint (@imssm99, @cdor1, @tjbecker, @yves); CVE-2026-123007/-123633 also independently by Rapid7, Wiz, Ikotas Labs, Metnir |
| Severity | All five: CVSS v4.0 **9.2 CRITICAL** / v3.1 8.1 |
| Fixed (OSS) | 1.31.9 (mainline), 1.30.7 (stable) — both 2026-11-18 |
| Kernel LPE | SCTP send-path UAF/double-free, introduced Linux v4.15 (2018) — **no CVE, unpatched** as of 2026-11-19; out of scope for this repo |

## The five paths

| CVE | Bug | Required config | First affected | `http2 off` blocks? |
|---|---|---|---|---|
| CVE-2026-123007 | H2 flow-control window credit returned twice (`WINDOW_UPDATE` + canceled-stream cleanup) → window > 2³¹−1 → unsigned underflow → signed/unsigned confusion → ~2⁶⁴ memcpy length (OOB write + address disclosure) | HTTP/2 enabled | 1.9.5 (2015-09-22) | Yes |
| CVE-2026-123633 | Active h2 connection left in the reusable queue (incomplete-frame flag checked after enqueue); drain during upstream connect frees the live request | HTTP/2 + `proxy_pass` upstream | 1.19.7 | Yes |
| CVE-2026-123634 | Resolver waiting-list loop holds `next` while a handler frees the sibling context (main request + `mirror` subrequest on the same DNS node) | `resolver` + variable `proxy_pass` + `mirror` (SSI may reach) | 0.6.18 (Cloudflare, 2026-11-20) | No |
| CVE-2026-121810 | Parent QUIC connection re-queued during stream creation (rbtree insert after slot alloc); drain frees the in-flight request | HTTP/3 + `proxy_pass` upstream | 1.25.0 | No |
| CVE-2026-113425 | Client session freed during `auth_http` lookup (write-handler error path); auth connection later uses stale `data` pointer — full public mechanism below | `mail` block: `proxy on` + `auth_http` | 0.5.33 (Cloudflare, 2026-11-20) | No |

All five are independent attack paths; no chaining needed. Exploitation
runs with **worker** privileges. ASLR/PIE are **not** mitigations: the
bugs themselves provide address disclosure (Xint/Wiz/Rapid7 demonstrated).

First-affected corrections (Cloudflare, 2026-11-20,
<https://blog.cloudflare.com/nginx2root/>): 123634 dates back to **0.6.18**
and 113425 to **0.5.33**, correcting the advisory-era figures this sheet
previously carried (1.13.4 / 0.5.15).

### CVE-2026-113425 — presented from public prior art (lab dropped, L20)

The local 113425 lab was dropped on 2026-11-20 (L20): Cloudflare's deep
dive (2026-11-20, <https://blog.cloudflare.com/nginx2root/>) published
an independent ASAN repro (faults on 1.31.8, runs clean on 1.31.9) plus
the full mechanism, on top of Xint's disclosure and F5 K000163931 —
nothing left for a scoped local lab to add. Full mechanism (Cloudflare):
two connections share one mail session; during `auth_http` the reply the
protocol handler prepared stays queued and the client write handler
remains `ngx_mail_send()`. If that handler runs and the write fails
because the client reset the connection, the client connection closes
and destroys the session while the auth connection still points at it.
Two conditions: the client write event must already be registered (e.g.
the client stopped reading), and the login command + reset must be
handled in the same event-loop pass. **Valid credentials are NOT
needed.** Fix: discard the queued reply when the auth request begins,
plus three further commits blocking client writes during auth phases.

## Fixed-version matrix

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

1.31.9/1.30.7 also fix CVE-2026-125283 (`try_files`+`alias` buffer
overflow, found by Marc Luchian and Liviu-Alexandru Bud — finder
attribution confirmed by USN-9182-1; different finders, **not** part of
the NGINX2Root family — it merely shipped in the same releases),
CVE-2026-118899 (TLS 1.3 body read infinite loop), CVE-2026-120993 (PROXY
protocol v2 NULL deref). Vendor workarounds exist only for 123634 (avoid
variable proxy targets + SSI/mirror) and 113425 (trusted-network
listeners); `http2 off` is a CIRCL/Xint mitigation, not
an F5 one — and now also Cloudflare's (matrix below).

Mitigation matrix (Cloudflare, 2026-11-20,
<https://blog.cloudflare.com/nginx2root/>):

| CVE | Mitigation |
|---|---|
| 123007 + 123633 | `http2 off` |
| 121810 | remove QUIC listeners + `http3 off` |
| 123634 | fixed upstream groups (`mirror_request_body on` is NOT sufficient — SSI reaches the same path) |
| 113425 | bind `mail` listeners to trusted networks only |
| all five | **restart required** — reload leaves old workers with old sessions |

## Distribution status (Ubuntu re-checked 2026-11-20; rest 2026-11-19)

- Ubuntu 26.10 + 26.04–14.04 LTS: USN-9182-1 (2026-11-20,
  https://ubuntu.com/security/notices/USN-9182-1) ships distro fixes for
  the **co-shipped non-family** nginx CVEs only (125283, 123640, 118899) —
  none of the five NGINX2Root CVEs is listed in the notice; family status
  in Ubuntu packages is unchanged (vulnerable, no family-specific fixed
  package observed as of 2026-11-20). ≤ 20.04 remains unpatchable via
  nginx.org (newest build 1.27.5 — vulnerable)
- Debian bookworm/trixie/forky/sid: vulnerable, no fixed package yet
- Laravel Forge: auto-updates do **not** patch nginx; ondrej/nginx PPA
  removed from Launchpad — manual switch to nginx.org repo required
- Official Docker images: 1.31.9/1.30.7 tags live (incl. Alpine); running
  containers keep old builds until pull+redeploy; **reload ≠ binary
  upgrade — restart required**
- Backports may fix without changing `nginx -v` — always compare the full
  package revision against the distro advisory

## Exposure (2026-11-10/18 measurements)

- Shodan: 56.7M nginx hosts; of the 21% exposing a version, **98.9%** in
  the affected range for CVE-2026-123007
- Censys: ~**9M** services on an affected version with HTTP/2 on; 103M
  more hide their version

## Detection

```sh
nginx -v 2>&1                                  # 1.9.5–1.31.8 = vulnerable code
nginx -V 2>&1 | grep -- --with-http_v2_module  # module present?
sudo nginx -T 2>&1 | sed 's/#.*//' | grep -nE \
  'listen[[:space:]].*http2|^[[:space:]]*http2[[:space:]]+on|quic|resolver|mirror|auth_http'
# external HTTP/2 reachability (test the origin, not the CDN):
openssl s_client -connect HOST:443 -servername HOST -alpn h2 </dev/null 2>&1 | grep 'ALPN'
```

Post-exploitation heuristics (none is proof alone): workers executing
programs (`auditd`: `auditctl -a always,exit -F arch=b64 -S execve,execveat
-F euid=<nginx_uid> -k nginx_worker_exec`); long-lived connections with
`bytes_received` ≫ `bytes_sent` and few logged requests (`ss -tinp`);
abnormal worker exits/core dumps (`error.log`, `coredumpctl`). H2 control
frames (`WINDOW_UPDATE`, `RST_STREAM`) never appear in access logs.

## Threat landscape (checked 2026-11-20)

- **In the wild**: no public evidence of exploitation yet; none of the
  five in CISA KEV (Cloudflare status, 2026-11-19). CISA advisory
  **2026-136** (2026-11-19): no exploitation in the wild as of
  2026-11-18/19.
- **Public PoCs**:
  - Rapid7 `sfewer-r7/CVE-2026-123007` — full RCE vs 1.31.8; constraints
    of *this implementation*: ~119 GiB of H2 traffic, ≥300 Mbit/s (else
    the 1 h connection lifetime kills it), glibc EVEX/YMM memcpy path
    selected by `avx512f`/`avx512vl`, fails through H2-proxied hops,
    fragile vs busy workers; Cloudflare (2026-11-20) characterizes it as
    "suitable only for demonstrating the attack against a freshly
    started local container"
  - Censys `Censys-Research/nginx2root` — compact accounting-error PoC on
    cleartext h2c, works 1.30.0–1.31.8 with 1.31.9 as control; plus
    reproductions of the three non-h2 UAFs
  - Wiz PoC — local Docker demo (fresh container, same host)
  - WormW/nginx2root-rce-lab — claims an adaptation without AVX-512
    (unaudited)
  - Cloudflare (2026-11-20, <https://blog.cloudflare.com/nginx2root/>) —
    no PoC code; public ASAN verification: built 1.31.8 (commit
    `140aa94`) and 1.31.9 with AddressSanitizer — 123007, 123633, 123634
    and 113425 each fault on 1.31.8 and run clean on 1.31.9; 121810 not
    reproduced (fix-commit analysis only)
  - **Fake 'exploits'**: Cloudflare (2026-11-20) reports fake nginx2root
    'exploit' repos circulating on GitHub; the origin exploits (Xint,
    Wiz) were never released — audit before running anything
- **Opsec note**: the fix landed in the public nginx repo ~1 week before
  disclosure, commit message crediting "Reported by Xint.io" — a live
  window for repo-diff watchers

## Open research questions (this repo)

Statuses after the F2 step-0 prior-art pass ([docs/prior-art.md](prior-art.md)):

1. **musl/Alpine crash viability** — **ANSWERED (F2, this lab)**: the
   crash **survives musl** — 3/3 WORKER-DIED runs on alpine:3.22, but as
   deterministic **signal 4 (SIGILL)**, not glibc's signal 11; the ~2^63
   OOB copy still faults under musl's forward memcpy. DoS holds on every
   libc tested; the surgical 160-byte write primitive (RCE tier) is
   glibc-only. Oracle classifies on musl with the debian staging
   constants untouched (kernel owns socket buffers, not libc).
2. **glibc < 2.24 crash viability** — **ANSWERED (F2 stretch, this
   lab)**: glibc 2.23 (buildpack-deps:xenial) crashes with signal 11 —
   the kill predates the 2.24 backward-copy memmove rework entirely.
3. Minimum-volume gap between "accounting trigger" (Censys, cheap) and
   "exploitable memcpy" (Rapid7, 119 GiB) — partially answered by our
   flood-budget measurements; the remaining gap is unbuffered-proxy
   behavior (Censys: inconclusive, < 4 MiB queues)
4. ~~Verified `http2 off` mitigation harness~~ — **done, shipped in F1**
   (`poc/diagnose.py` NOT-H2 control + `poc/crash.py`); still the only
   public `http2 off` verification among the artifacts (neither upstream
   repo mentions it; Cloudflare's 2026-11-20 mitigation matrix lists
   `http2 off` as a recommendation — no shipped harness, so ours remains
   the only executable verification)
5. Full public closure of the four UAF paths — **123634 ANSWERED (F3,
   this lab)**: stock 1.31.8 worker SIGSEGV, reproducible (DNS-failure
   holds 50–300 ms; race win rate 20–40%/attempt), ALERT "could not
   cancel ... resolving" as the path marker, verbatim ASAN report at
   ngx_resolver.c:2142; fixed 1.31.9 survives every cell — first public
   stock-build crash for this CVE (Censys had ASAN + custom-debug only).
   **121810: NOT REPRODUCED (F3, this lab, honest negative)** — ~120
   attempts x 11 configurations (worker_connections 32–128, idle/fin/abort
   streams, h1 refiller saturation pinning free_connection_n at
   connection_n/16): no ASAN report, no stock crash, no differential;
   drains fire (precondition present) but victims were ~100% h1
   keepalives. Source-verified gate analysis: a drain-closed same-parent
   idle stream cannot synchronously pass ngx_quic_close_stream's two
   gates in 1.31.8 — the real interleaving must be second-order (next
   angles: instrumented-debug builds, uni-stream/two-parent pressure).
   **123633: PARTIAL (F3, this lab)** — differential oracle reproduced
   3/3 on all four builds (vuln/vuln-asan VULNERABLE-STATE: the drain
   GOAWAYs the still-marked ACTIVE h2 connection mid-request; fixed pair
   PATCHED-STATE under identical triggers) + the verbatim server-side
   kill chain on a debug build; ~200 crash-race attempts produced no
   ASAN report and no stock crash (below Censys parity on the crash,
   above on mechanism): the incomplete frame that marks the connection
   reusable is a SETTINGS frame (not HEADERS), marks insert at queue
   HEAD while the drain takes oldest-first (`ngx_queue_last`), and the
   working pressure instrument is busy unread h1 requests — the unlanced
   step is dead-socket detection inside the drain-invoked handler
   (SO_LINGER-0 RSTs discard the unACKed completion bytes; later closes
   land one stack frame too late).
   **113425: closed from public prior art (2026-11-20, L20)** — local
   lab dropped; Cloudflare ASAN repro + full mechanism, Xint disclosure,
   F5 K000163931, Censys cmd-exec from retained artifacts. 2026-11-20
   cross-check (Cloudflare): 123634 — their repro is ASAN-build-based;
   ours remains the first public **stock-build** crash (50–300 ms
   DNS-failure holds, 20–40% win rate per attempt). 121810 — they also
   did not reproduce (fix-commit analysis only): external validation of
   our honest negative + gate analysis. 123633 — they publish an ASAN
   crash; our distinct contribution stands (3/3 differential oracle +
   the three source-verified mechanism corrections).

### Verified by prior art (inherited — see [prior-art.md](prior-art.md))

- **arm64 accounting tier** — Censys verified the accounting error on
  arm64 for 1.30.0–1.31.8 (7 releases); crash/RCE on arm64 remains
  unverified anywhere
- **AVX-512 RCE constraint** — full RCE requires the calibrated glibc
  EVEX/YMM memcpy (`avx512f`/`avx512vl`, matched glibc build, x86-64);
  Rapid7 profile + Censys independent marker-verified reproduction
- **Release matrix** — accounting error on every release 1.30.0–1.31.8
  (x86-64, 1/2/4 workers, fresh/40/200-request heaps, main response
  types); 1.31.9 rejects. A 17-release oracle sweep would be redundant
- **Family ASAN verification** — Cloudflare (2026-11-20,
  <https://blog.cloudflare.com/nginx2root/>): 123007, 123633, 123634 and
  113425 each fault on ASAN-built 1.31.8 and run clean on 1.31.9; 121810
  not reproduced by them either (fix-commit analysis)

### Measured in this lab (F1, 2026-11-19)

- The window inflation to 2^63 needs ~4.29e9 WINDOW_UPDATE frames
  (~52 GiB wire) — and nginx 1.31.8's `http2 flood detected`
  heuristic (`total_bytes/8 > payload_bytes + 1 MiB`) kills a
  control-frame-only connection within a few hundred MB. Legal defeat:
  prime `payload_bytes` with ~10 GiB of real downloads (raising the
  allowance to ~80 GiB) before flooding. This reframes the public
  "~119 GiB" figures: bandwidth is necessary but not the whole story.
  (Credit where due: Rapid7's exploit already defeats the same heuristic
  by design — its client-sent "flood-budget carrier"; the priming
  *concept* is prior art. The quantified heuristic, the server-direction
  priming, and the reframe are ours. Details in
  [prior-art.md](prior-art.md).)
- nginx deducts the connection window at frame-build time, and the
  vulnerable capacity check is `send_window + increment > MAX` —
  staging grants must be state-aware, not hardcoded. (Rapid7 reaches
  the same requirement via exact-value bookkeeping.)
- Effective flood rate on primed loopback Docker: ~0.5 GB/s sustained
  (vuln run ≈ 3 min; controls die safely inside the ritual).

### Measured in this lab (F2, 2026-11-19)

- musl (alpine:3.22) and glibc 2.23 (xenial) pairs: oracle verdicts and
  staging envelopes match the debian pair (patched flush 0.77–0.87 MiB,
  vulnerable bounded-drain ~1.5 MiB — libc-independent, kernel-owned).
- Flood under musl: 52.21 Mfr/s / 679 MB/s effective (glibc: ~709 MB/s);
  priming identical (10 GiB / 160 streams / ~33 s); vuln-musl kill wall
  ~1m51s. Fault signature: **SIGILL on musl, SIGSEGV on every glibc
  (2.23 → bookworm)** — first public libc-matrix for this bug.
- Caveat: the musl SIGILL root cause (which instruction faults) is not
  dissected — cores do not persist in the lab containers.

## Prior art

Formal comparison of every public artifact against our F1 work, with
per-artifact original-vs-redundant verdicts and file:line citations:
[docs/prior-art.md](prior-art.md). The two upstream repos we diffed
against:

- Rapid7 — `github.com/sfewer-r7/CVE-2026-123007` (full RCE exploit,
  standalone crash trigger; the flood-budget carrier and the exact 2^64
  window wrap are theirs)
- Censys — `github.com/Censys-Research/nginx2root` (compact accounting
  PoC, release/arm64/worker/heap/response matrices, Rapid7 RCE
  reproduction; our oracle is a convergent reinvention of theirs)

Wiz's PoC is not public; Xint disclosed but shipped no code.
Cloudflare's 2026-11-20 deep dive (blog only, no code) adds a public
ASAN verification of 4/5 — per-CVE overlap verdicts in
[prior-art.md](prior-art.md).

## Sources

Xint writeup (xint.io/blog/nginx2root-remote-code-execution) · nginx
CHANGES + security advisories · F5 K000164058 · CIRCL TR-105 · Rapid7
blog (S. Fewer) · Censys blog + repo · Wiz blog (N. Ohfeld, T. Schwartz) ·
Qualys TRU · SecurityWeek · The Hacker News (2026-11-18) · Laravel Forge
KB · Tenable/watchTowr FAQs · Cloudflare blog "nginx2root" (2026-11-20,
https://blog.cloudflare.com/nginx2root/) · Ubuntu USN-9182-1 (2026-11-20,
https://ubuntu.com/security/notices/USN-9182-1) · CISA advisory 2026-136
(2026-11-19) · F5 K000163931.
