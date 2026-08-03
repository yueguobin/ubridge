/* xdp_cbpf.h — compile a tcpdump expression to a classic-BPF instruction stream.
 *
 * Isolates <pcap/pcap.h> (and its `struct bpf_insn`) from everything else: this
 * header defines our OWN classic-BPF insn type `ub_cbpf_insn` (no pcap include),
 * so callers that also pull in <linux/bpf.h>'s eBPF `struct bpf_insn` don't hit a
 * collision. Only xdp_cbpf.c includes pcap; it memcpy's libpcap's bpf_insn stream
 * into ub_cbpf_insn (identical layout). */
#ifndef XDP_CBPF_H
#define XDP_CBPF_H

#include <linux/types.h>

/* A classic-BPF instruction (libpcap bpf_insn / kernel sock_filter: {code,jt,jf,
 * k}, 8 bytes). */
struct ub_cbpf_insn {
    __u16 code;
    __u8  jt;
    __u8  jf;
    __u32 k;
};

#define UB_CBPF_MAX_INSNS 512   /* libpcap's BPF_MAXINSNS */

/* Compile `expr` (a tcpdump/libpcap filter string, DLT_EN10MB) and copy the
 * resulting classic-BPF instruction stream into `out` (at most max_insns
 * entries). Returns the instruction count (>= 0) on success, or -1 on a syntax
 * error / overflow (errbuf filled). On error `out` is left untouched. */
int cbpf_compile(const char *expr, struct ub_cbpf_insn *out, int max_insns,
                 char *errbuf, int errlen);

#endif /* XDP_CBPF_H */
