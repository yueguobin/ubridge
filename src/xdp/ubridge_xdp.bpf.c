/* ubridge_xdp.bpf.c — the ubridge XDP dataplane (Phase 2).
 *
 * Compiled separately (clang -target bpf) into an object, turned into a libbpf
 * skeleton, and driven by the userspace loader (xdp_load.c).
 *
 *   A: load/attach/counter foundation (XDP_PASS + per-CPU count).
 *   B: forwarding via DEVMAP egress redirect (bpf_redirect_map, flags=0).
 *   C1 (this file): ingress tx-marker. When enabled, an IPv4 match (placeholder
 *      until real cBPF->eBPF in increment F) reserves a marker event in the
 *      ringbuf; the userspace consumer formats it into the contract MARK line
 *      and sendto()s the sink. The marker runs BEFORE forwarding so it fires
 *      whether or not a peer is configured. Bidirectional rx-coverage (the
 *      shared observation map + sender-side peer marker) is C2. See
 *      doc/xdp-tap-mode.md.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_events.h"

/* Per-CPU packet counter (proves the program ran). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1);
} pkt_count SEC(".maps");

/* Forwarding map: key 0 -> peer TAP ifindex (DEVMAP). Empty => XDP_PASS;
 * populated by xdp_load_set_peer() => egress redirect to the peer. */
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct bpf_devmap_val));
    __uint(max_entries, 1);
} fwd SEC(".maps");

/* Marker control: key 0 -> enabled (0/1). Set by userspace (pause/resume). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1);
} marker_ctrl SEC(".maps");

/* Marker events → userspace. Drained by the ringbuf consumer (xdp_marker). */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} events SEC(".maps");

SEC("xdp")
int ubridge_xdp_main(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&pkt_count, &key);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);

    /* Marker (C1): emit on IPv4 match when enabled. Placeholder match — real
     * tcpdump/cBPF->eBPF expressions come in increment F. */
    __u32 *enabled = bpf_map_lookup_elem(&marker_ctrl, &key);
    if (enabled && *enabled) {
        void *data     = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;
        struct ethhdr *eth = data;
        if ((void *)(eth + 1) <= data_end &&
            eth->h_proto == bpf_htons(ETH_P_IP)) {
            struct xdp_marker_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
            if (e) {
                e->ts_ns     = bpf_ktime_get_ns();
                e->len       = (__u32)(data_end - data);
                e->dir       = XDP_DIR_TX;        /* C1: ingress marker = node tx */
                e->marker_id = 0;
                bpf_ringbuf_submit(e, 0);
            }
        }
    }

    /* Forward: redirect to peer egress if configured, else PASS. */
    if (bpf_map_lookup_elem(&fwd, &key))
        return bpf_redirect_map(&fwd, key, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
