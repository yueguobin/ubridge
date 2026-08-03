/* ubridge_xdp.bpf.c — the ubridge XDP dataplane (Phase 2).
 *
 * This is the eBPF program loaded onto each node's TAP. It is compiled
 * separately (clang -target bpf) into an object, turned into a libbpf
 * skeleton, and driven by the userspace loader (xdp_load.c).
 *
 * Phase 2 increment A (this file): the FOUNDATION only — prove the pipeline
 * end to end (compile -> skeleton -> load -> attach -> run -> read a counter).
 * The program does XDP_PASS and counts packets in a per-CPU array. Forwarding
 * (DEVMAP bpf_redirect_map), marker, and filter are layered on in later
 * increments; see doc/xdp-tap-mode.md.
 *
 * Build (see Makefile):
 *   clang -g -O2 -target bpf -c ubridge_xdp.bpf.c -o ubridge_xdp.bpf.o
 *   bpftool gen skeleton ubridge_xdp.bpf.o > ubridge_xdp.skel.h
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Per-CPU packet counter: lets the userspace loader prove the program actually
 * ran on real packets (an attach alone could be a no-op). Summed across CPUs
 * by xdp_load_pkt_count(). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1);
} pkt_count SEC(".maps");

SEC("xdp")
int ubridge_xdp_main(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&pkt_count, &key);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
