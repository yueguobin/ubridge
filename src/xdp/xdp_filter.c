/* xdp_filter.c — Phase 2 increment D: the XDP filter action layer (DROP/PASS).
 *
 *   xdp_filter <ifname> <peer_ifname> <action=drop|pass> [direction=both|tx|rx] [enabled=1|0] [window=4]
 *
 * Attaches the XDP program, configures forwarding to the peer (DEVMAP egress
 * redirect), then installs one filter (action + direction + enabled) via the
 * filter_ctrl map. Holds the window open so a test can inject on the peer veth
 * and observe — at the far end of the redirect target — whether the frame
 * arrived (PASS / disabled / non-match / wrong-direction) or did not (DROP).
 *
 * Match is the IPv4 placeholder until real cBPF->eBPF in increment F.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>

#include "xdp_load.h"
#include "xdp_events.h"

static int parse_action(const char *s)
{
    if (!strcmp(s, "drop")) return XDP_FILT_ACT_DROP;
    if (!strcmp(s, "pass")) return XDP_FILT_ACT_PASS;
    return -1;
}

static int parse_direction(const char *s)
{
    if (!strcmp(s, "both")) return XDP_FILT_DIR_BOTH;
    if (!strcmp(s, "tx"))   return XDP_FILT_DIR_TX;
    if (!strcmp(s, "rx"))   return XDP_FILT_DIR_RX;
    return -1;
}

int main(int argc, char **argv)
{
    const char *ifname, *peer;
    int action, direction, enabled, window, err;
    struct xdp_load *x = NULL;

    setvbuf(stdout, NULL, _IOLBF, 0);

    if (argc < 4) {
        fprintf(stderr, "usage: %s <ifname> <peer_ifname> <action=drop|pass> "
                "[direction=both|tx|rx] [enabled=1|0] [window=4]\n", argv[0]);
        return 2;
    }
    ifname  = argv[1];
    peer    = argv[2];
    action  = parse_action(argv[3]);
    if (action < 0) {
        fprintf(stderr, "bad action: %s (drop|pass)\n", argv[3]);
        return 2;
    }
    direction = (argc > 4) ? parse_direction(argv[4]) : XDP_FILT_DIR_BOTH;
    if (direction < 0) {
        fprintf(stderr, "bad direction: %s (both|tx|rx)\n", argv[4]);
        return 2;
    }
    enabled = (argc > 5) ? atoi(argv[5]) : 1;
    window  = (argc > 6) ? atoi(argv[6]) : 4;
    if (window < 1) window = 1;

    err = xdp_load_attach(ifname, &x);
    if (err) {
        fprintf(stderr, "xdp_load_attach(%s) failed: %d (%s)\n", ifname, err, strerror(-err));
        return 1;
    }

    err = xdp_load_set_peer(x, peer);
    if (err) {
        fprintf(stderr, "xdp_load_set_peer(%s) failed: %d (%s)\n", peer, err, strerror(-err));
        xdp_load_detach(x); return 1;
    }

    err = xdp_load_set_filter(x, 0, action, direction, enabled);
    if (err) {
        fprintf(stderr, "xdp_load_set_filter failed: %d (%s)\n", err, strerror(-err));
        xdp_load_detach(x); return 1;
    }

    printf("READY action=%s direction=%s enabled=%d\n",
           action == XDP_FILT_ACT_DROP ? "drop" : "pass",
           direction == XDP_FILT_DIR_BOTH ? "both" : direction == XDP_FILT_DIR_TX ? "tx" : "rx",
           enabled);
    fflush(stdout);

    sleep(window);                       /* test injects here; observes the far end */

    xdp_load_detach(x);
    return 0;
}
