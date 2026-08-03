/* ubridge_xdp.bpf.c — the ubridge XDP dataplane (Phase 2).
 *
 *   A: load/attach/counter foundation (XDP_PASS + per-CPU count).
 *   B: forwarding via DEVMAP egress redirect (bpf_redirect_map, flags=0).
 *   C1: ingress tx-marker — IPv4 match -> ringbuf event -> MARK line -> sink.
 *   C2 (this file): marker-coverage seam. When forwarding, the sender also
 *      emits a dir=RX event for the peer if the peer's observation entry has
 *      rx_enabled — because the egress redirect does not run the peer's netdev
 *      XDP, the receiver's rx-direction marker must run on the sender. The
 *      observation map is keyed by peer ifindex (read from the DEVMAP value).
 *
 * Marker match is a placeholder (IPv4) until real cBPF->eBPF in increment F.
 * See doc/xdp-tap-mode.md.
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

/* Marker events -> userspace. Drained by the ringbuf consumer (xdp_marker). */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} events SEC(".maps");

/* Marker-observation map (the seam): keyed by TAP ifindex -> rx_enabled.
 * Read by the sender before an egress redirect to decide whether to emit the
 * peer's dir=RX marker. Populated by xdp_load_set_peer_rx(). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct xdp_obs_val));
    __uint(max_entries, 64);
} observation SEC(".maps");

static __always_inline void emit_marker(__u32 dir, __u32 len, __u32 marker_id)
{
    struct xdp_marker_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;
    e->ts_ns     = bpf_ktime_get_ns();
    e->len       = len;
    e->dir       = dir;
    e->marker_id = marker_id;
    bpf_ringbuf_submit(e, 0);
}

SEC("xdp")
int ubridge_xdp_main(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&pkt_count, &key);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);

    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    int is_ipv4 = ((void *)(eth + 1) <= data_end) &&
                  (eth->h_proto == bpf_htons(ETH_P_IP));
    __u32 len = (__u32)(data_end - data);

    __u32 *enabled = bpf_map_lookup_elem(&marker_ctrl, &key);
    int menabled = enabled && *enabled;

    /* Own tx-marker (ingress). */
    if (menabled && is_ipv4)
        emit_marker(XDP_DIR_TX, len, 0);

    /* Forward + the peer's rx-marker (the seam), run on the sender. */
    struct bpf_devmap_val *peer = bpf_map_lookup_elem(&fwd, &key);
    if (peer) {
        if (menabled && is_ipv4) {
            struct xdp_obs_val *obs = bpf_map_lookup_elem(&observation, &peer->ifindex);
            if (obs && obs->rx_enabled)
                emit_marker(XDP_DIR_RX, len, 0);
        }
        return bpf_redirect_map(&fwd, key, 0);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
