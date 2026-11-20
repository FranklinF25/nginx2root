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
- **Closure** — PTES report, research writeup, verification matrix

## Landscape (2026-11-20)

- CISA advisory **2026-136** (2026-11-19): published; no exploitation in
  the wild as of 2026-11-18/19 — and none of the five CVEs in CISA KEV
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
(script-engine heap bugs, 1.30.0 → 1.30.1).

## License

MIT.
