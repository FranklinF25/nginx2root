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
