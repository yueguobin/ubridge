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

/* --- Filter (increment D) ---------------------------------------------------
 * The XDP dataplane's action layer, separate from the marker (observation):
 * the marker emits events for every match; the filter decides DROP/PASS and so
 * whether a packet is forwarded. Match is the IPv4 placeholder (ethertype
 * 0x0800) until real cBPF->eBPF reuse in increment F.
 *
 * A node's own TAP XDP only sees that node's TX (the packets the local node
 * writes). So `direction` selects whether a filter applies HERE:
 *   BOTH / TX -> applies on this (sending) XDP;
 *   RX        -> does not apply here (it would apply to this node's rx, seen on
 *                the peer's XDP — out of scope for D; the seam is marker-only).
 * Action semantics with the (default) empty filter map = forward:
 *   DROP -> XDP_DROP before the redirect (the peer never receives it, so the
 *           seam's dir=RX marker is suppressed too);
 *   PASS -> explicitly allow; indistinguishable from "no filter" while the
 *           default remains forward (a real override needs chaining, later). */
#define XDP_FILT_ACT_DROP 0      /* drop matching packets (no forward)            */
#define XDP_FILT_ACT_PASS 1      /* allow matching packets (default = forward)    */

#define XDP_FILT_DIR_BOTH 0      /* apply on this XDP                            */
#define XDP_FILT_DIR_TX   1      /* apply only when the local node is sending    */
#define XDP_FILT_DIR_RX   2      /* skip on this (sending) XDP                   */

struct xdp_filter_val {
    __u32 action;     /* XDP_FILT_ACT_*                                  */
    __u32 enabled;    /* 0 = bypassed (treated as no filter), 1 = active */
    __u32 direction;  /* XDP_FILT_DIR_*                                  */
};

#endif /* XDP_EVENTS_H */
