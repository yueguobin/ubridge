# Phase 2 Increment F Postmortem — cBPF→eBPF Expression Reuse

**Date:** 2026-08-04  
**Branch:** `feature/xdp-expr` (renamed → `feature/xdp-dataplane`, from `eee72aa`)  
**Status:** ABANDONED — both attempted approaches failed the eBPF verifier; F is deferred.

## Goal

Replace the IPv4 placeholder match (`is_ipv4`) in the XDP dataplane's marker and filter
with a real tcpdump/libpcap expression ("any tcpdump expr works," contract #2 in
`doc/xdp-tap-mode.md`). The expression should be changeable at runtime without
reloading the XDP hook.

## Approach (A) — cBPF Interpreter in eBPF

Chosen initially because "change-BPF = map update" (the interpreter is data in a map;
no program reload). A bounded for-loop in eBPF interprets the cBPF instruction stream
per packet.

**What was built:**
- `ubridge_xdp.bpf.c` — `cbpf_prog` ARRAY map + `cbpf_match()` subprogram: bounded-loop
  interpreter over the full classic BPF opcode set (LD/LDX/ST/STX/ALU/JMP/MISC/RET,
  LD_ABS/IND with ntohl/ntohs).
- `xdp_events.h` — `xdp_cbpf_insn` (layout-identical to libpcap's `bpf_insn`, 8 bytes),
  `xdp_cbpf_prog`, `CBPF_MAX_INSNS=64`, `CBPF_PKT_CAP=192`.
- `xdp_load.[ch]` — `xdp_load_set_cbpf()`.
- `xdp_cbpf.[ch]` — pcap glue (compile tcpdump expr → cBPF insn stream).
- `xdp_expr.c` — driver: forward+marker+filter live, `expr <tcpdump>` verb → recompile + map update.
- `test_xdp_expr.py` — inject UDP/53 vs UDP/9999, prove expr gates marker+filter, runtime expr change.

**Verifier errors hit (4):**

| # | Error | Cause | Fix applied |
|---|-------|-------|-------------|
| 1 | `invalid access to packet, off=1 size=1, R4 min value outside` | `__builtin_memcpy` of variable-offset packet pointer → clang lowered to per-byte loads → verifier range tracking failed with unbounded offset `smax=0xffffffff`. | Bound `off` against `pkt_len` first (shrink smax); use `volatile` typed single load. |
| 2 | same error | Bounds-check `off + size > pkt_len` overflowable via u32 wrap when `off ≈ 0xffffffff`. | Use `off > pkt_len \|\| pkt_len - off < size` (overflow-safe). |
| 3 | `misaligned stack access off (0x0;0xffffffffffffffff)+0 size 4` | `*(u32*)(buf + off)` on stack — multi-byte read at non-aligned offset rejected. | Rewrote W/H loads as byte-by-byte assembly with shifts. |
| 4 | `-E2BIG` / log truncated | Verifier log too large for libbpf's auto-grow buffer (the interpreter's bounded loop + switch generates ~6000+ verifier insns). | Added `bpf_program__set_log_buf()` with 8 MiB buffer in `xdp_load.c`. |

After fix #4, the user chose to abandon (A) and pivot to translation (B) before the
next sudo run. (A) may have worked with the 8 MiB log buffer fix; this was never
tested.

**Why the interpreter was hard:** The verifier must prove safety at LOAD time for ALL
possible programs in the map. Every cBPF offset `k` is an unknown scalar → every load
is a variable-offset access. eBPF variable-offset reads require: bounds-checked,
overflow-safe, aligned, and with bounded `smax`. The interpreter's bounded loop +
50-case switch also blows up the verifier log.

## Approach (B) — cBPF→eBPF Translation + Tail-Call

Pivot: translate cBPF to eBPF bytecode at runtime (like the kernel's own
`bpf_convert_filter()` in `net/core/filter.c`), keep the marker/filter/forward
epilogue in compiled C, and chain via tail-call (`prog_array`).

**Architecture:**
- `ubridge_xdp_dyn.bpf.c` — dispatcher (XDP entry, `pkt_count` + `bpf_tail_call
  prog_array[0]`) + epilogue (`prog_array[1]`, compiled C: marker/filter/forward).
- `xdp_translate.c` — cBPF → eBPF bytecode generator. First version: hand-rolled
  translation with custom fixup. Second version: kernel's `bpf_convert_filter`
  register mapping (A→R0, X→R7, CTX→R6) + XDP-style packet loads for LD_ABS/IND.
- `xdp_dyn_load.c` — dyn skeleton loader + `bpf_prog_load` for generated match
  programs + `prog_array[0]` swap.
- Change-BPF = generate new match program + `bpf_map_update_elem` replace
  `prog_array[0]` (no XDP hook re-attachment).

**Verifier/integrity errors hit (4):**

| # | Error | Cause |
|---|-------|-------|
| 1 | `BPF_JA uses reserved fields` | `ja_fix_cbpf` stored cBPF target in `.imm` (non-zero), which the verifier rejects on JA. |
| 2 | `unreachable insn 27` | After-loop fallback code (no match path) was DEAD — all cBPF paths exited via RET→JA to trampoline. |
| 3 | `misaligned stack access` / `32→64-bit truncation` | Hand-rolled prologue loaded `ctx->data`/`ctx->data_end` as 32-bit (`ldx_w`), truncating 64-bit pointers. |
| 4 | (never reached) — rewritten to match kernel's register mapping but still untested | Second translator version uses kernel's exact opcode patterns; LD_ABS/IND substituted with XDP-style bounds-checked reads. Not tested under verifier. |

**Why translation was hard:** The kernel's `bpf_convert_filter` is designed for socket
filters and emits `BPF_LD_ABS` — an eBPF pseudo-insn the verifier rejects in XDP
context. Hand-writing correct eBPF bytecode for the replacement (XDP packet reads +
epilogue map updates + tail-call) is error-prone at the instruction-encoding level
(register widths, reserved fields, jump offset resolution). There is no
kernel-blessed reference mapping for the XDP path.

## Files (committed here for reference)

| File | Role |
|------|------|
| `doc/xdp-f-postmortem.md` | This document |
| `src/xdp/ubridge_xdp_dyn.bpf.c` | (B) dyn dispatcher + epilogue eBPF object |
| `src/xdp/xdp_cbpf.[ch]` | (A+B) pcap compile glue |
| `src/xdp/xdp_translate.[ch]` | (B) cBPF→eBPF translator (final version: kernel register mapping) |
| `src/xdp/xdp_dyn_load.[ch]` | (B) dyn skeleton loader + match install/swap |
| `src/xdp/xdp_expr.c` | (B) driver: forward+marker+filter + expr verb |
| `tests/xdp/test_xdp_expr.py` | F test (udp port 53 vs UDP/9999, runtime expr change) |
| `Makefile` / `.gitignore` / `run_all.py` | F wiring |

## Lessons

1. **eBPF interpreter (A) is possible but painful.** The verifier imposes 4 stacked
   constraints (range tracking, alignment, overflow bounds, log size). Each is
   fixable but the sequence of fixes is long and each needs root to verify.
2. **eBPF bytecode emission (B) has no kernel-blessed XDP mapping.** `bpf_convert_filter`
   is socket-filter-only. Hand-emitting bytecode is fragile. A proper XDP cBPF→eBPF
   translator needs tooling (like LLVM's BPF backend or a higher-level eBPF asm library).
3. **For F, consider sidestepping the problem:** instead of translating or interpreting
   in eBPF, pre-compile the tcpdump expression to a SEPARATE XDP program at the
   gns3server layer (where Python can drive clang), load it as a standalone match
   program in `prog_array[0]`, and let the fixed dispatcher tail-call it. This moves
   the compilation burden to the server (Python + clang) and keeps ubridge's eBPF
   simple — only the dispatcher + epilogue (already working).
4. **tail-call split (dispatcher + prog_array[0]=match + prog_array[1]=epilogue) works
   fine** — the dyn object (dispatcher + epilogue) loaded cleanly under the verifier.
   Only the generated match program failed.

## Next steps for F

Recommended: **Pre-compiled match via clang at the server layer.** The Python
gns3server compiles a tiny eBPF C program containing the tcpdump filter as
a fixed-offset packet check, generates the object, ships it to ubridge, which
loads it via `bpf_prog_load` and inserts it into `prog_array[0]`. ubridge's
eBPF (dispatcher + epilogue) stays fixed and simple. This inherits clang's
proven BPF codegen and avoids both the interpreter's verifier fight and the
hand-rolled bytecode bugs.
