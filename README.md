# nginx2root

Security research on the **NGINX2Root** family: five unauthenticated,
pre-auth remote code execution vulnerabilities in NGINX (CVSS 4.0 **9.2
CRITICAL** each), disclosed on **2026-11-18** by the Xint research team —
plus the separate, currently unpatched Linux kernel SCTP LPE that chains
worker-context RCE into host root (tracked, out of research scope here).

| CVE | Bug | Required config |
|---|---|---|
| CVE-2026-123007 | HTTP/2 flow-control integer overflow → OOB read/write | HTTP/2 enabled |
| CVE-2026-123633 | HTTP/2 connection-draining use-after-free | HTTP/2 + proxied upstream |
| CVE-2026-123634 | DNS resolver use-after-free | `resolver` + variable `proxy_pass` + subrequest (`mirror`, SSI) |
| CVE-2026-121810 | HTTP/3/QUIC connection-draining use-after-free | HTTP/3 + proxied upstream |
| CVE-2026-113425 | Mail proxy `auth_http` use-after-free | `proxy on` + `auth_http` |

Fixed in NGINX Open Source **1.30.7** (stable) / **1.31.9** (mainline).
Ubuntu's [USN-9182-1](https://ubuntu.com/security/notices/USN-9182-1)
(2026-11-20, 26.10 + 26.04–14.04 LTS) covers only the co-shipped
non-family nginx CVEs — no NGINX2Root fix in Ubuntu packages yet.

**Scope** (decided 2026-11-19): family-wide, NGINX-only — differential
labs and safe detectors for the five paths, an exploit-constraints audit
(musl/glibc/architectures), and the full docs trio. The kernel SCTP bug
is documented but not researched here. **All lab work runs inside Docker;
nothing builds or executes on the host.**

## Status

- **F0** — scaffold + living [finding sheet](docs/finding-sheet.md) ✔
- **F1** — CVE-2026-123007 ✔: differential lab (1.31.8 vs 1.31.9 vs
  `http2 off`), safe oracle (`poc/diagnose.py`, 3/3 verdicts), and the
  deterministic worker-death crash PoC over TLS (`poc/crash.py`:
  WORKER-DIED on 1.31.8, SURVIVED on 1.31.9, NOT-H2 when disabled);
  regression harness `lab/verify.sh` (`RUN_CRASH=1` adds the crash
  matrix; loopback-only ports, digest-pinned images, healthcheck-gated)
- **F2** — exploit-constraints audit ✔ (step 0: [prior-art comparison](docs/prior-art.md) — oracle = convergent reinvention of Censys's compact PoC; flood-heuristic priming concept = Rapid7 prior art; `http2 off` verification + phase-tracked verdicts = ours. Empirical: **crash survives musl as SIGILL and glibc 2.23 as SIGSEGV** — DoS holds on every libc, RCE-tier primitive is glibc-only; arm64 accounting inherited from Censys)
- **F3** — labs + detectors for the other four CVEs ✔ — 123634: first
  public **stock-build** crash (50–300 ms DNS-failure race, 20–40% win
  rate); 123633: differential oracle 3/3 on four builds + three
  source-verified mechanism corrections (honest partial — no terminal
  UAF); 121810: NOT reproduced (~120 attempts × 11 configs) + the first
  published gate analysis; 113425: lab dropped 2026-11-20 (Cloudflare
  published an independent ASAN repro + the full mechanism) — presented
  from public prior art
- **Closure** ✔ — [PTES report](docs/ptes-report.md) +
  [research writeup](docs/research-writeup.md) +
  [verification matrix](#verification-matrix) + cross-links

## Verification matrix

One row per verifiable claim. All commands are Docker-only (S4),
loopback-bound, digest-pinned; first runs add image builds (minutes).
Full verdict semantics per lab: `lab/README.md`,
`lab/{121810,123633,123634}/README.md`.

| Claim | Command | Expected verdict (exact strings) | Runtime | Status |
|---|---|---|---|---|
| 123007 safe oracle, glibc + musl pairs (5 verdicts) | `cd lab && ./verify.sh` | `verdict vuln:8080: VULNERABLE — ok`, `fixed:8080: PATCHED`, `mitigated:8080: NOT-H2`, `vuln-musl:8080: VULNERABLE`, `fixed-musl:8080: PATCHED`; `no worker deaths — ok`; final `PASS` | ~25 s post-build | ✔ green (observed 5/5, F2) |
| 123007 crash PoC, glibc pair | `cd lab && RUN_CRASH=1 ./verify.sh` | `crash verdict vuln:443: WORKER-DIED — ok` + server `worker process N exited on signal 11 (core dumped)`; `fixed:443 SURVIVED`; `mitigated:443 NOT-H2` | ~6 min (observed 5m37s, F2) | ✔ |
| F2 libc matrix — musl/Alpine (SIGILL vs SIGSEGV) | same `RUN_CRASH=1` run | `vuln-musl:443 WORKER-DIED` + server `worker process N exited on signal 4`; `fixed-musl:443 SURVIVED` (oracle pair already in the default run) | same run | ✔ first public libc matrix |
| F2 libc matrix — glibc 2.23 (xenial, manual) | `cd lab && docker compose -f docker-compose.yml -f docker-compose.xenial.yml up -d --build --wait vuln-xenial fixed-xenial`, then `diagnose.py` / `crash.py` vs the `-xenial` targets | oracle `VULNERABLE` / `PATCHED`; crash `vuln-xenial:443 WORKER-DIED`, `fixed-xenial:443 SURVIVED` (signal 11) | build-heavy (ephemeral pair) | ✔ observed 2026-11-19; not part of `verify.sh` |
| 123634 stock-build crash + ASAN floor | `cd lab/123634 && ./verify.sh` | `PASS: stock worker died Nx, ALERT marker Nx`; alert `could not cancel … resolving`; `worker process N exited on signal 11`; `PASS: ASAN heap-use-after-free xN` (`ngx_resolver.c:2142`); fixed pair zero alerts/deaths; final `==== verify: PASS ====` | ~2–3 min | ✔ probabilistic race (20–40%/attempt; 10-attempt trigger hasn't missed) |
| 123633 differential oracle (four builds) | `cd lab/123633 && ./verify.sh` | `vuln: 3/3 attempts VULNERABLE-STATE` and `vuln-asan: 3/3`; fixed pair 0 (`PATCHED-STATE`); race matrix `INFO: no ASAN report / worker death — honest state`; final `==== verify: PASS ====` | ~4–5 min | ✔ oracle; terminal UAF honestly not landed |
| 121810 honest negative (lab-functional semantics) | `cd lab/121810 && ./verify.sh` | sanity `TRIGGER-OK` on all four variants; `PASS: drain events firing`; `INFO: no ASAN report / worker death — race not landed (matches public state)`; `PASS: fixed-asan clean under identical trigger`; `PASS: stock fixed control death-free`; final `==== verify: PASS ====` | ~3–4 min | ✔ CVE not reproduced (~120 attempts × 11 configs) — by design of the harness |
| 113425 | — no local lab (dropped 2026-11-20) | presented from public prior art (Cloudflare ASAN repro + full mechanism) | — | n/a |

## Landscape (2026-11-20)

- [CISA advisory **2026-136**](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-nginx-could-allow-for-remote-code-execution_2026-136)
  (2026-11-19): published; no exploitation in the wild as of
  2026-11-18/19 — and none of the five CVEs in CISA KEV
  (Cloudflare status, 2026-11-19).
- [Cloudflare deep dive](https://blog.cloudflare.com/nginx2root/)
  (2026-11-20): ASAN builds of 1.31.8 vs 1.31.9 — 123007, 123633, 123634
  and 113425 each fault on the vulnerable build and run clean on the
  fixed one; 121810 not reproduced there either (external validation of
  our honest negative).
- Rapid7's public PoC: "suitable only for demonstrating the attack
  against a freshly started local container" (Cloudflare, 2026-11-20).
- **Warning — fake 'exploits' circulate on GitHub.** The origin exploits
  (Xint, Wiz) were never released; audit anything before running it.
- CVE-2026-125283 (`try_files`+`alias`, different finders) shipped in the
  same 1.31.9/1.30.7 releases — a same-release coincidence, **not** part
  of the NGINX2Root family.

## Companion research

Part of the nginx arc:
[CVE-2026-42533](https://github.com/FranklinF25/cve-2026-42533) ·
[CVE-2026-42945](https://github.com/FranklinF25/cve-2026-42945)
(script-engine heap bugs, 1.30.0 → 1.30.1). Upstream NGINX2Root
artifacts we diffed against:
[Rapid7](https://github.com/sfewer-r7/CVE-2026-123007) ·
[Censys](https://github.com/Censys-Research/nginx2root).
Author: [FranklinF25](https://github.com/FranklinF25).

## License

MIT.
