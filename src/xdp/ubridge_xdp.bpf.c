/* ubridge_xdp.bpf.c — the ubridge XDP dataplane (Phase 2).
 *
 * Compiled separately (clang -target bpf) into an object, turned into a libbpf
 * skeleton, and driven by the userspace loader (xdp_load.c).
 *
 * Increment A: load/attach/counter foundation (XDP_PASS + per-CPU count).
 * Increment B (this file): forwarding via DEVMAP egress redirect. If a peer
 *   ifindex is configured in `fwd[0]`, the program bpf_redirect_map()s the
 *   packet to the peer TAP's egress — the peer node's read() gets it, never
 *   through the kernel network stack (constraint #6, no BPF_F_INGRESS). With no
 *   peer entry the program falls back to XDP_PASS (the foundation/no-peer mode,
 *   so the A test keeps passing).
 *
 * Marker/filter are layered on in later increments; see doc/xdp-tap-mode.md.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Per-CPU packet counter: lets the userspace loader prove the program ran. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1);
} pkt_count SEC(".maps");

/* Forwarding map: key 0 -> peer TAP ifindex (DEVMAP). Empty (no entry) =>
 * XDP_PASS; populated by xdp_load_set_peer() => bpf_redirect_map to the peer's
 * egress. struct bpf_devmap_val also carries an optional redirect program
 * (left 0 here; the receiver's rx-marker is added in increment C). */
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct bpf_devmap_val));
    __uint(max_entries, 1);
} fwd SEC(".maps");

SEC("xdp")
int ubridge_xdp_main(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&pkt_count, &key);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);

    /* Peer configured? Redirect to its egress (delivers to the peer node's fd,
     * no network-stack traversal). flags=0 == egress, per constraint #6. */
    if (bpf_map_lookup_elem(&fwd, &key))
        return bpf_redirect_map(&fwd, key, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
