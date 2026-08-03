/* xdp_fwd.c — Phase 2 increment B: prove XDP forwarding via DEVMAP egress redirect.
 *
 *   xdp_fwd <ifname> <peer_ifname> [window_seconds=4]
 *
 * Attaches the XDP program to <ifname>, points its DEVMAP at <peer_ifname>
 * (so the program bpf_redirect_map()s every packet to the peer's egress),
 * signals READY, waits the window while the test injects on the far side of
 * <ifname> and receives on the far side of <peer_ifname>, then reports the
 * counter delta (packets the program forwarded) and detaches.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xdp_load.h"

int main(int argc, char **argv)
{
    const char *ifname, *peer;
    int window, err;
    struct xdp_load *x = NULL;
    long long before, after;

    setvbuf(stdout, NULL, _IOLBF, 0);

    if (argc < 3) {
        fprintf(stderr, "usage: %s <ifname> <peer_ifname> [window_seconds=4]\n", argv[0]);
        return 2;
    }
    ifname = argv[1];
    peer = argv[2];
    window = (argc > 3) ? atoi(argv[3]) : 4;
    if (window < 1) window = 1;

    err = xdp_load_attach(ifname, &x);
    if (err) {
        fprintf(stderr, "xdp_load_attach(%s) failed: %d (%s)\n", ifname, err, strerror(-err));
        return 1;
    }
    err = xdp_load_set_peer(x, peer);
    if (err) {
        fprintf(stderr, "xdp_load_set_peer(%s) failed: %d (%s)\n", peer, err, strerror(-err));
        xdp_load_detach(x);
        return 1;
    }

    before = xdp_load_pkt_count(x);
    printf("READY peer=%s\n", peer);
    fflush(stdout);

    sleep(window);

    after = xdp_load_pkt_count(x);
    printf("DELTA=%lld\n", (after - before));

    xdp_load_detach(x);
    return 0;
}
