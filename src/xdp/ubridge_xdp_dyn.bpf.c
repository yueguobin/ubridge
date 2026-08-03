/* ubridge_xdp_dyn.bpf.c — the ubridge XDP dataplane, DYNAMIC match (Phase 2 F).
 *
 * The match predicate is a tcpdump/libpcap expression TRANSLATED to eBPF at
 * runtime (see xdp_translate.c) — not interpreted in eBPF. To keep the complex
 * marker/filter/forward logic in compiled C (and avoid hand-emitting ~100 insns
 * of bytecode), the dataplane is split across a tail-call chain:
 *
 *   dispatcher (XDP entry, attached)         prog_array[0] = generated match
 *     |                                        |
 *     +-- pkt_count++; tail_call(prog_array,0) -->  match: translate cBPF over
 *         (fallback XDP_PASS)                     |   the packet, write matched
 *                                                 |   to scratch[0], tail_call(.,1)
 *                                                 v
 *                                          epilogue (compiled C, prog_array[1]):
 *                                            read scratch[0]=matched -> marker ->
 *                                            filter(DROP/PASS) -> forward/redirect.
 *
 * Changing the expression = generate a new match program and swap prog_array[0]
 * (a map update); the dispatcher (the XDP hook) is never re-attached. scratch is
 * PERCPU so the match->epilogue handoff on the same packet/CPU is race-free.
 *
 * Maps mirror ubridge_xdp.bpf.c (the A-E baseline) so the control plane
 * (marker_ctrl / filter_ctrl / fwd / observation / events) is identical; only the
 * match source differs. See doc/xdp-tap-mode.md.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "xdp_events.h"

/* Per-CPU packet counter (proves the dispatcher ran). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1);
} pkt_count SEC(".maps");

/* Tail-call chain: [0] = generated match program, [1] = epilogue. */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 2);
} prog_array SEC(".maps");

/* match -> epilogue handoff: 1 = the packet matched the cBPF expression. PERCPU
 * so it is private to the CPU/packet running the chain (no cross-CPU race). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1);
} scratch SEC(".maps");

/* Forwarding map: key 0 -> peer TAP ifindex (DEVMAP). Empty => XDP_PASS. */
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct bpf_devmap_val));
    __uint(max_entries, 1);
} fwd SEC(".maps");

/* Marker control: key 0 -> enabled (0/1). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1);
} marker_ctrl SEC(".maps");

/* Marker events -> userspace (ringbuf). */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} events SEC(".maps");

/* Filter control (D): key 0 -> {action, enabled, direction}. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct xdp_filter_val));
    __uint(max_entries, 8);
} filter_ctrl SEC(".maps");

/* Marker-observation map (the seam): peer ifindex -> rx_enabled. */
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

/* XDP entry: count, then hand the packet to the generated match program. If no
 * match program is installed yet (prog_array[0] empty), tail_call returns and we
 * PASS. Installed by attaching this program to the interface. */
SEC("xdp")
int ubridge_xdp_dispatcher(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&pkt_count, &key);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);

    bpf_tail_call(ctx, &prog_array, 0);
    return XDP_PASS;            /* no match program installed -> pass through */
}

/* Epilogue (tail-call target prog_array[1]): the match program wrote `matched`
 * to scratch[0]; do the observation (marker) + action (filter) + forward. This
 * is the baseline (A-E) marker/filter/forward logic with is_ipv4 replaced by the
 * scratch `matched` flag. Not attached to an interface — its fd goes into
 * prog_array[1]. */
SEC("xdp")
int ubridge_xdp_epilogue(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u32 *matched_p = bpf_map_lookup_elem(&scratch, &key);
    int matched = matched_p && *matched_p;

    __u32 len = (__u32)((long)ctx->data_end - (long)ctx->data);

    __u32 *enabled = bpf_map_lookup_elem(&marker_ctrl, &key);
    int menabled = enabled && *enabled;

    /* Own tx-marker (ingress) — observed whether or not a filter drops it. */
    if (menabled && matched)
        emit_marker(XDP_DIR_TX, len, 0);

    /* Filter (D): DROP stops the packet before the redirect (so the seam's
     * dir=RX marker is suppressed too). */
    struct xdp_filter_val *filt = bpf_map_lookup_elem(&filter_ctrl, &key);
    if (filt && filt->enabled && matched &&
        (filt->direction == XDP_FILT_DIR_BOTH || filt->direction == XDP_FILT_DIR_TX) &&
        filt->action == XDP_FILT_ACT_DROP)
        return XDP_DROP;

    /* Forward + the peer's rx-marker (the seam), run on the sender. */
    struct bpf_devmap_val *peer = bpf_map_lookup_elem(&fwd, &key);
    if (peer) {
        if (menabled && matched) {
            struct xdp_obs_val *obs = bpf_map_lookup_elem(&observation, &peer->ifindex);
            if (obs && obs->rx_enabled)
                emit_marker(XDP_DIR_RX, len, 0);
        }
        return bpf_redirect_map(&fwd, key, 0);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
