/* xdp_translate.h — translate a compiled classic-BPF program to eBPF.
 *
 * The translator emits an eBPF XDP program that embeds the cBPF filter (fixed-
 * offset packet reads, verifier-friendly), writes the match result to a scratch
 * per-CPU map, and tail-calls the compiled-C epilogue (marker/filter/forward).
 * Changing the expression = regenerate this program and swap prog_array[0]. */
#ifndef XDP_TRANSLATE_H
#define XDP_TRANSLATE_H

#include <linux/bpf.h>       /* struct bpf_insn (eBPF insn) */
#include "xdp_cbpf.h"        /* struct ub_cbpf_insn (cBPF insn — no pcap collide) */

/* Translate a compiled classic-BPF program (`cbpf`, `len` instructions) into an
 * eBPF XDP program. On success returns 0 and sets *out to a malloc'd insn array
 * (caller frees) and *out_len to its count. The map file descriptors `scratch_fd`
 * and `prog_array_fd` are baked into BPF_LD_MAP_FD insns so the generated program
 * can write scratch[0]=matched and tail-call prog_array[1] (the epilogue).
 * Returns -1 on a logic error (errbuf filled). */
int cbpf_translate(const struct ub_cbpf_insn *cbpf, int cbpf_len,
                   int scratch_fd, int prog_array_fd,
                   struct bpf_insn **out, int *out_len,
                   char *errbuf, int errlen);

#endif /* XDP_TRANSLATE_H */
