/* xdp_dyn_load.c — loader for the dynamic-dataplane eBPF object (dispatcher +
 * epilogue).  See xdp_dyn_load.h. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "xdp_dyn_load.h"
#include "ubridge_xdp_dyn.skel.h"

struct xdp_dyn_load {
    struct ubridge_xdp_dyn_bpf *skel;
    int ifindex;
    int match_fd;        /* fd of the installed match program, or -1 */
};

/* Load a generated match program (raw eBPF insns, XDP type).  Caller frees
 * insns. Returns the new program fd or -errno. */
static int load_match_prog(const struct bpf_insn *insns, int insn_len, char *log, int logsz)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type      = BPF_PROG_TYPE_XDP;
    attr.insns          = (unsigned long)insns;
    attr.insn_cnt       = (__u32)insn_len;
    attr.license        = (unsigned long)"GPL";
    attr.log_buf        = (unsigned long)log;
    attr.log_size       = (__u32)logsz;
    attr.log_level      = 1;
    return (int)syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
}

int xdp_dyn_attach(const char *ifname, const char *peer_ifname,
                   struct xdp_dyn_load **out)
{
    struct ubridge_xdp_dyn_bpf *skel;
    int ifindex, err;
    char logbuf[256 * 1024];

    skel = ubridge_xdp_dyn_bpf__open();
    if (!skel)
        return -errno;

    /* give the dispatcher + epilogue a generous log (they are simple but belt
     * and suspenders) */
    bpf_program__set_log_buf(skel->progs.ubridge_xdp_dispatcher, logbuf, sizeof(logbuf));

    err = ubridge_xdp_dyn_bpf__load(skel);
    if (err) {
        ubridge_xdp_dyn_bpf__destroy(skel);
        return err;
    }

    ifindex = (int)if_nametoindex(ifname);
    if (!ifindex) {
        ubridge_xdp_dyn_bpf__destroy(skel);
        return -ENODEV;
    }

    /* attach dispatcher (the XDP entry) */
    err = bpf_xdp_attach(ifindex,
                         bpf_program__fd(skel->progs.ubridge_xdp_dispatcher),
                         XDP_FLAGS_SKB_MODE, NULL);
    if (err) {
        int saved = err;
        ubridge_xdp_dyn_bpf__destroy(skel);
        return saved;
    }

    /* insert epilogue into prog_array[1] */
    __u32 key1 = 1;
    int epilogue_fd = bpf_program__fd(skel->progs.ubridge_xdp_epilogue);
    err = bpf_map_update_elem(bpf_map__fd(skel->maps.prog_array), &key1,
                              &epilogue_fd, BPF_ANY);
    if (err) {
        bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
        ubridge_xdp_dyn_bpf__destroy(skel);
        return -errno;
    }

    struct xdp_dyn_load *x = calloc(1, sizeof(*x));
    if (!x) {
        bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
        ubridge_xdp_dyn_bpf__destroy(skel);
        return -ENOMEM;
    }
    x->skel     = skel;
    x->ifindex  = ifindex;
    x->match_fd = -1;

    /* apply peer forwarding (the DEVMAP and observation seam) */
    if (peer_ifname) {
        xdp_dyn_set_peer(x, peer_ifname);
        xdp_dyn_set_peer_rx(x, peer_ifname, 1);
    }

    *out = x;
    return 0;
}

void xdp_dyn_detach(struct xdp_dyn_load *x)
{
    if (!x)
        return;
    /* remove match from prog_array to detach it */
    __u32 key0 = 0;
    int zero = 0;
    bpf_map_update_elem(bpf_map__fd(x->skel->maps.prog_array), &key0,
                        &zero, BPF_ANY);

    bpf_xdp_detach(x->ifindex, XDP_FLAGS_SKB_MODE, NULL);
    if (x->match_fd >= 0)
        close(x->match_fd);
    ubridge_xdp_dyn_bpf__destroy(x->skel);
    free(x);
}

long long xdp_dyn_pkt_count(struct xdp_dyn_load *x)
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

int xdp_dyn_set_peer(struct xdp_dyn_load *x, const char *peer_ifname)
{
    struct bpf_devmap_val val;
    __u32 key = 0;
    int ifindex;

    if (!x) return -EINVAL;
    ifindex = if_nametoindex(peer_ifname);
    if (!ifindex) return -ENODEV;
    memset(&val, 0, sizeof(val));
    val.ifindex = ifindex;
    if (bpf_map_update_elem(bpf_map__fd(x->skel->maps.fwd), &key, &val, BPF_ANY))
        return -errno;
    return 0;
}

int xdp_dyn_set_peer_rx(struct xdp_dyn_load *x, const char *peer_ifname, int rx_enabled)
{
    struct xdp_obs_val val;
    __u32 ifindex;

    if (!x) return -EINVAL;
    ifindex = if_nametoindex(peer_ifname);
    if (!ifindex) return -ENODEV;
    memset(&val, 0, sizeof(val));
    val.rx_enabled = rx_enabled ? 1 : 0;
    if (bpf_map_update_elem(bpf_map__fd(x->skel->maps.observation), &ifindex,
                            &val, BPF_ANY))
        return -errno;
    return 0;
}

int xdp_dyn_set_filter(struct xdp_dyn_load *x, int filter_id, int action,
                       int direction, int enabled)
{
    struct xdp_filter_val val;
    __u32 key = filter_id;

    if (!x) return -EINVAL;
    memset(&val, 0, sizeof(val));
    val.action    = (__u32)action;
    val.direction = (__u32)direction;
    val.enabled   = enabled ? 1 : 0;
    if (bpf_map_update_elem(bpf_map__fd(x->skel->maps.filter_ctrl), &key,
                            &val, BPF_ANY))
        return -errno;
    return 0;
}

int xdp_dyn_set_marker_enabled(struct xdp_dyn_load *x, int enabled)
{
    __u32 key = 0, val = enabled ? 1 : 0;
    if (!x) return -EINVAL;
    if (bpf_map_update_elem(bpf_map__fd(x->skel->maps.marker_ctrl), &key,
                            &val, BPF_ANY))
        return -errno;
    return 0;
}

static int dyn_filter_update(struct xdp_dyn_load *x, int filter_id, int field, __u32 newv)
{
    struct xdp_filter_val val;
    __u32 key = filter_id;
    int fd;

    if (!x) return -EINVAL;
    fd = bpf_map__fd(x->skel->maps.filter_ctrl);
    if (bpf_map_lookup_elem(fd, &key, &val))
        return -errno;
    switch (field) {
    case 0: val.enabled   = newv; break;
    case 1: val.action    = newv; break;
    case 2: val.direction = newv; break;
    default: return -EINVAL;
    }
    if (bpf_map_update_elem(fd, &key, &val, BPF_ANY))
        return -errno;
    return 0;
}

int xdp_dyn_filter_set_enabled(struct xdp_dyn_load *x, int filter_id, int enabled)
    { return dyn_filter_update(x, filter_id, 0, enabled ? 1 : 0); }
int xdp_dyn_filter_set_action(struct xdp_dyn_load *x, int filter_id, int action)
    { return dyn_filter_update(x, filter_id, 1, (__u32)action); }
int xdp_dyn_filter_set_direction(struct xdp_dyn_load *x, int filter_id, int direction)
    { return dyn_filter_update(x, filter_id, 2, (__u32)direction); }

int xdp_dyn_events_fd(struct xdp_dyn_load *x)
{
    if (!x) return -1;
    return bpf_map__fd(x->skel->maps.events);
}

int xdp_dyn_scratch_fd(struct xdp_dyn_load *x)
{
    if (!x) return -1;
    return bpf_map__fd(x->skel->maps.scratch);
}

int xdp_dyn_prog_array_fd(struct xdp_dyn_load *x)
{
    if (!x) return -1;
    return bpf_map__fd(x->skel->maps.prog_array);
}

static int insert_match_prog(struct xdp_dyn_load *x, int prog_fd)
{
    __u32 key = 0;
    return bpf_map_update_elem(bpf_map__fd(x->skel->maps.prog_array), &key,
                               &prog_fd, BPF_ANY);
}

int xdp_dyn_install_match(struct xdp_dyn_load *x,
                          const struct bpf_insn *insns, int insn_len)
{
    char logbuf[256 * 1024];
    int fd;

    if (!x || !insns || insn_len <= 0)
        return -EINVAL;

    fd = load_match_prog(insns, insn_len, logbuf, sizeof(logbuf));
    if (fd < 0) {
        fprintf(stderr, "load_match_prog failed: %d\n%s\n", fd, logbuf);
        return fd;
    }

    int err = insert_match_prog(x, fd);
    if (err) {
        close(fd);
        return -errno ? -errno : -EIO;
    }
    /* close the old match if there was one */
    if (x->match_fd >= 0)
        close(x->match_fd);
    x->match_fd = fd;
    return 0;
}

int xdp_dyn_swap_match(struct xdp_dyn_load *x,
                       const struct bpf_insn *insns, int insn_len)
{
    char logbuf[256 * 1024];
    int new_fd, err;

    if (!x || !insns || insn_len <= 0)
        return -EINVAL;

    new_fd = load_match_prog(insns, insn_len, logbuf, sizeof(logbuf));
    if (new_fd < 0) {
        fprintf(stderr, "swap: load_match_prog failed: %d\n%s\n", new_fd, logbuf);
        return new_fd;
    }

    err = insert_match_prog(x, new_fd);
    if (err) {
        close(new_fd);
        return -errno ? -errno : -EIO;
    }
    if (x->match_fd >= 0)
        close(x->match_fd);
    x->match_fd = new_fd;
    return 0;
}
