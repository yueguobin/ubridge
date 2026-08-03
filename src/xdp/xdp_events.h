/* xdp_events.h — shared layout between the eBPF program and userspace.
 *
 * Included by both ubridge_xdp.bpf.c (kernel) and the userspace drivers. The
 * marker event carries only what the kernel can know at match time; the
 * name-bearing fields (node/filter/link/tag strings) live in userspace, keyed
 * by marker_id, so the eBPF stays free of string handling. */
#ifndef XDP_EVENTS_H
#define XDP_EVENTS_H

#include <linux/types.h>

#define XDP_DIR_TX 0   /* packet entered on the capture node's side (node sending) */
#define XDP_DIR_RX 1   /* packet entered on the link side (node receiving) */

/* One marker match, reserved in the ringbuf and submitted from XDP. */
struct xdp_marker_event {
    __u64 ts_ns;       /* bpf_ktime_get_ns() at match time        */
    __u32 len;         /* frame length (ctx data_end - data)      */
    __u32 dir;         /* XDP_DIR_TX / XDP_DIR_RX                 */
    __u32 marker_id;   /* which marker fired (userspace owns names) */
};

/* Marker-observation entry, keyed by TAP ifindex in the shared `observation`
 * map. Read by the *sender's* XDP right before an egress redirect: if the peer
 * has rx_enabled, the sender emits a dir=RX event on the peer's behalf — the
 * marker-coverage seam (egress redirect does not run the peer's netdev XDP, so
 * the receiver's rx-direction marker must run on the sender). See
 * doc/xdp-tap-mode.md. */
struct xdp_obs_val {
    __u32 rx_enabled;  /* peer wants its rx-direction marker observed */
};

#endif /* XDP_EVENTS_H */
