/* xdp_load.h — libbpf loader for the ubridge XDP dataplane.
 *
 * Reusable open/load/attach/detach + counter read around the generated
 * skeleton (ubridge_xdp.skel.h). Drives the eBPF object in ubridge_xdp.bpf.c.
 * Today exercised by xdp_smoke.c; later called from ubridge's XDP module. */
#ifndef XDP_LOAD_H
#define XDP_LOAD_H

struct xdp_load;

/* Open + load the XDP object and attach it in generic (SKB) mode to `ifname`.
 * (TAPs only support generic XDP; see doc/xdp-tap-mode.md constraint #1.)
 * On success returns 0 and sets *out; on failure returns a negative -errno and
 * leaves *out untouched. */
int xdp_load_attach(const char *ifname, struct xdp_load **out);

/* Sum of the per-CPU XDP packet counter — packets that ran the program.
 * Returns -1 on a lookup failure. */
long long xdp_load_pkt_count(struct xdp_load *x);

/* Detach from the interface and destroy the loaded object. Safe on NULL. */
void xdp_load_detach(struct xdp_load *x);

/* Configure forwarding: set the peer TAP (egress redirect target) in the
 * DEVMAP. After this, the XDP program bpf_redirect_map()s every packet to the
 * peer's egress. With no peer set the program does XDP_PASS. Returns 0 / -errno. */
int xdp_load_set_peer(struct xdp_load *x, const char *peer_ifname);

/* Configure the marker-coverage seam (C2): mark that `peer_ifname` wants its
 * rx-direction marker observed. The sender's XDP reads this before an egress
 * redirect and, if set, emits a dir=RX event on the peer's behalf. rx_enabled
 * = 1 to observe, 0 to clear. Returns 0 / -errno. */
int xdp_load_set_peer_rx(struct xdp_load *x, const char *peer_ifname, int rx_enabled);

/* Configure the XDP filter (D): writes filter_ctrl[filter_id] = {action,
 * direction, enabled}. action is XDP_FILT_ACT_DROP/PASS; direction is
 * XDP_FILT_DIR_BOTH/TX/RX; enabled 1 = active, 0 = bypassed. Match is the IPv4
 * placeholder until real cBPF->eBPF (F). DROP stops a matching packet before
 * forwarding; PASS is the default forward. Returns 0 / -errno. */
int xdp_load_set_filter(struct xdp_load *x, int filter_id, int action, int direction, int enabled);

/* Control-plane translation (E): change ONE field of an already-installed filter
 * via a read-modify-write on filter_ctrl[filter_id] — the runtime equivalent of
 * ubridge's `enable_packet_filter <name> on|off` (enable) and direction/action
 * changes. These let a control verb flip the live dataplane's behavior without
 * re-stating the whole filter. Each returns 0 / -errno. */
int xdp_load_filter_set_enabled(struct xdp_load *x, int filter_id, int enabled);
int xdp_load_filter_set_action(struct xdp_load *x, int filter_id, int action);
int xdp_load_filter_set_direction(struct xdp_load *x, int filter_id, int direction);

/* File descriptor of the marker-events ringbuf (for ring_buffer__new). */
int xdp_load_events_fd(struct xdp_load *x);

/* Enable/disable the ingress marker (writes marker_ctrl[0]). 1 = emit, 0 = off. */
int xdp_load_set_marker_enabled(struct xdp_load *x, int enabled);

#endif /* XDP_LOAD_H */
