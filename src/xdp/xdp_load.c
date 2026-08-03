/* xdp_load.c — libbpf loader for the ubridge XDP dataplane.
 *
 * Wraps the generated skeleton (ubridge_xdp.skel.h, built from
 * ubridge_xdp.bpf.c by the Makefile). open -> load -> attach(generic/SKB) ->
 * read per-CPU counter -> detach. The attach is SKB-mode because TAPs cannot
 * attach native XDP (doc/xdp-tap-mode.md constraint #1). */
#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <linux/if_link.h>   /* XDP_FLAGS_SKB_MODE */
#include <linux/bpf.h>       /* struct bpf_devmap_val */
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "xdp_load.h"
#include "ubridge_xdp.skel.h"

struct xdp_load {
    struct ubridge_xdp_bpf *skel;
    int ifindex;
};

int xdp_load_attach(const char *ifname, struct xdp_load **out)
{
    struct ubridge_xdp_bpf *skel;
    int ifindex, err;

    skel = ubridge_xdp_bpf__open();
    if (!skel)
        return -errno;

    err = ubridge_xdp_bpf__load(skel);          /* verifies + loads programs/maps */
    if (err) {
        ubridge_xdp_bpf__destroy(skel);
        return err;                              /* libbpf returns a negative errno-ish */
    }

    ifindex = (int)if_nametoindex(ifname);
    if (!ifindex) {
        ubridge_xdp_bpf__destroy(skel);
        return -ENODEV;
    }

    err = bpf_xdp_attach(ifindex,
                         bpf_program__fd(skel->progs.ubridge_xdp_main),
                         XDP_FLAGS_SKB_MODE, NULL);
    if (err) {
        int saved = err;
        ubridge_xdp_bpf__destroy(skel);
        return saved;
    }

    struct xdp_load *x = calloc(1, sizeof(*x));
    if (!x) {
        bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
        ubridge_xdp_bpf__destroy(skel);
        return -ENOMEM;
    }
    x->skel = skel;
    x->ifindex = ifindex;
    *out = x;
    return 0;
}

long long xdp_load_pkt_count(struct xdp_load *x)
{
    int nr_cpus, i;
    long long sum = 0;
    __u32 key = 0;

    if (!x)
        return -1;

    nr_cpus = libbpf_num_possible_cpus();
    if (nr_cpus <= 0)
        return -1;

    long long values[nr_cpus];
    memset(values, 0, sizeof(values));

    if (bpf_map_lookup_elem(bpf_map__fd(x->skel->maps.pkt_count), &key, values))
        return -1;

    for (i = 0; i < nr_cpus; i++)
        sum += values[i];
    return sum;
}

void xdp_load_detach(struct xdp_load *x)
{
    if (!x)
        return;
    bpf_xdp_detach(x->ifindex, XDP_FLAGS_SKB_MODE, NULL);
    ubridge_xdp_bpf__destroy(x->skel);
    free(x);
}

int xdp_load_set_peer(struct xdp_load *x, const char *peer_ifname)
{
    struct bpf_devmap_val val;
    __u32 key = 0;
    int ifindex;

    if (!x)
        return -EINVAL;

    ifindex = (int)if_nametoindex(peer_ifname);
    if (!ifindex)
        return -ENODEV;

    memset(&val, 0, sizeof(val));
    val.ifindex = ifindex;          /* bpf_prog stays 0 (added in increment C) */

    if (bpf_map_update_elem(bpf_map__fd(x->skel->maps.fwd), &key, &val, BPF_ANY))
        return -errno;
    return 0;
}

int xdp_load_events_fd(struct xdp_load *x)
{
    if (!x)
        return -1;
    return bpf_map__fd(x->skel->maps.events);
}

int xdp_load_set_marker_enabled(struct xdp_load *x, int enabled)
{
    __u32 key = 0, val = enabled ? 1 : 0;
    if (!x)
        return -EINVAL;
    if (bpf_map_update_elem(bpf_map__fd(x->skel->maps.marker_ctrl), &key, &val, BPF_ANY))
        return -errno;
    return 0;
}
