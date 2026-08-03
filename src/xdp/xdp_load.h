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

#endif /* XDP_LOAD_H */
