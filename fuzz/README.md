# RESP reply parser fuzzing

Coverage-guided (libFuzzer) fuzzing of the three Redis (RESP) reply parsers in
`../src/ngx_http_cache_turbo_redis.c`:

| function | reply shape |
|---|---|
| `ngx_http_cache_turbo_redis_parse`       | bulk string (`GET`) — `$<len>\r\n<bytes>\r\n` |
| `ngx_http_cache_turbo_redis_parse_array` | array (`SMEMBERS`) — `*<count>\r\n` then N bulk strings |
| `ngx_http_cache_turbo_redis_parse_scan`  | `SCAN` 2-tuple — `[ cursor, [ keys… ] ]` |

These parse bytes from a shared, possibly buggy or compromised L2, doing
length-line and bulk-string pointer arithmetic against `op->rbuf .. op->rbuf +
op->rlen`. A single off-by-one in a CRLF scan or a missing length bound is a
worker-crashing out-of-bounds read or a signed-overflow UB — exactly the bug
class coverage-guided fuzzing finds and the runtime suite misses.

## No copy drift

The fuzz target does **not** contain a copy of the parser. `extract_parser.sh`
slices the three function bodies (and the `MAX_MEMBERS` guard) verbatim out of
the shipped source into `generated_parser.inc` at build time, and asserts the
`MAX_REPLY`/`MAX_MEMBERS` size constants still match the shim. If a signature,
body, or constant changes upstream, the next build picks it up — or fails loudly
rather than fuzz stale code. `ngx_shim.h` supplies the minimal nginx surface the
parsers touch (`op` struct, a malloc-backed pool, and verbatim `ngx_atoi` /
`ngx_strlchr`) with faithful upstream semantics.

The harness feeds a buffer sized **exactly** to `op->rlen` with **no** trailing
NUL, so ASAN turns any read at or past the end into an immediate, reproducible
heap-buffer-overflow. On `NGX_OK` it also asserts every returned `ngx_str_t`
points back into the input buffer.

## Build & run locally

```bash
# needs clang with libFuzzer (clang >= 6)
bash fuzz/build.sh                 # -> fuzz/fuzz_resp_parser (ASan+UBSan+fuzzer)
cd fuzz
./fuzz_resp_parser -max_total_time=60 corpus/
```

A crash drops a `crash-*` reproducer; re-run it with
`./fuzz_resp_parser crash-<id>` to reproduce. Add the reproducer to `corpus/`
(named `regress_*`) so it becomes a permanent regression seed.

## CI

`.github/workflows/fuzzing.yml` runs this monthly (1st of the month) and on
manual dispatch, mirroring the `valgrind` / `codeql` heavy-job cadence. The
build-time ASan+UBSan suite in `build-test.yml` is the per-change gate.

## Findings

- **`regress_scan_cursor_len_overflow`** — the `SCAN` cursor bulk-string length
  was used in `end - p < len + 2` without first bounding it by `MAX_REPLY`
  (unlike `parse()` and the member loops). A cursor length of `INT64_MAX`
  overflowed `len + 2` (UBSan signed-overflow). Fixed by adding the
  `len > MAX_REPLY → NGX_DECLINED` guard; the seed is kept so the bug can never
  return silently.
