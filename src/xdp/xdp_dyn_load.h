/* xdp_dyn_load.h — loader for the dynamic-dataplane eBPF object.
 *
 * Wraps the ubridge_xdp_dyn.skel.h skeleton (dispatcher + epilogue + maps +
 * prog_array + scratch).  In addition to the standard attach/control (set_peer,
 * set_filter, etc.), it provides:
 *   - install_match(insns, len)   -> load the generated match program, insert it
 *                                    as prog_array[0], enabling the dataplane.
 *   - swap_match(insns, len)      -> replace prog_array[0] atomically with a new
 *                                    match program (runtime expression change).
 *
 * Because we own all maps in the one skeleton object, no cross-process pinning
 * is needed — the generated match program references scratch and prog_array by
 * fd obtained from the skeleton. */
#ifndef XDP_DYN_LOAD_H
#define XDP_DYN_LOAD_H

#include <linux/bpf.h>       /* struct bpf_insn */
#include "xdp_events.h"

struct xdp_dyn_load;

/* Open + load the dynamic dataplane skeleton, attach its DISPATCHER to `ifname`
 * in SKB mode, insert epilogue fd -> prog_array[1], apply initial control state
 * (set_peer, set_peer_rx, and optionally set_filter + set_marker_enabled).
 * On success returns 0 and sets *out. */
int xdp_dyn_attach(const char *ifname, const char *peer_ifname,
                   struct xdp_dyn_load **out);

/* Detach dispatcher, destroy skeleton. Safe on NULL.  Also destroys any
 * currently-installed match program (swapping prog_array[0] to empty). */
void xdp_dyn_detach(struct xdp_dyn_load *x);

/* Run the counter (pkt_count via the dispatcher).  -1 on failure. */
long long xdp_dyn_pkt_count(struct xdp_dyn_load *x);

/* Setters for the control-surface maps (identical to xdp_load semantics). */
int xdp_dyn_set_peer(struct xdp_dyn_load *x, const char *peer_ifname);
int xdp_dyn_set_peer_rx(struct xdp_dyn_load *x, const char *peer_ifname, int rx_enabled);
int xdp_dyn_set_filter(struct xdp_dyn_load *x, int filter_id, int action,
                       int direction, int enabled);
int xdp_dyn_set_marker_enabled(struct xdp_dyn_load *x, int enabled);
int xdp_dyn_filter_set_enabled(struct xdp_dyn_load *x, int filter_id, int enabled);
int xdp_dyn_filter_set_action(struct xdp_dyn_load *x, int filter_id, int action);
int xdp_dyn_filter_set_direction(struct xdp_dyn_load *x, int filter_id, int direction);
int xdp_dyn_events_fd(struct xdp_dyn_load *x);

/* File descriptors for the maps the translator needs. */
int xdp_dyn_scratch_fd(struct xdp_dyn_load *x);
int xdp_dyn_prog_array_fd(struct xdp_dyn_load *x);

/* Load a generated match program (eBPF insn array) and install it as
 * prog_array[0]. If a match program is already installed it will replace it, BUT
 * there is a transient moment (after ld_map_fd bakes the fds) where the old
 * program fd is closed. Use the first match install after attach; call
 * xdp_dyn_swap_match() for subsequent changes.  Returns 0 / -errno. */
int xdp_dyn_install_match(struct xdp_dyn_load *x,
                          const struct bpf_insn *insns, int insn_len);

/* Atomically swap the match program: load a new one, replace prog_array[0],
 * close the old fd.  Returns 0 / -errno.  State in other maps is untouched. */
int xdp_dyn_swap_match(struct xdp_dyn_load *x,
                       const struct bpf_insn *insns, int insn_len);

#endif /* XDP_DYN_LOAD_H */
