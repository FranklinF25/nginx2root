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
- **F2** — exploit-constraints audit: Alpine/musl, glibc < 2.24, arm64,
  trigger-vs-exploit traffic gap
- **F3** — labs + detectors for the other four CVEs
- **Closure** — PTES report, research writeup, verification matrix

## Companion research

Part of the nginx arc:
[CVE-2026-42533](https://github.com/FranklinF25/cve-2026-42533) ·
[CVE-2026-42945](https://github.com/FranklinF25/cve-2026-42945)
(script-engine heap bugs, 1.30.0 → 1.30.1).

## License

MIT.
