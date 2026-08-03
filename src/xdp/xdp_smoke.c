/* xdp_smoke.c — standalone proof of the XDP foundation.
 *
 * Loads the eBPF object via xdp_load, attaches it to an interface, signals
 * READY on stdout, waits for a window, then reports how many packets ran the
 * program and detaches. Driven by tests/xdp/test_xdp_attach.py, which injects
 * packets during the window.
 *
 *   xdp_smoke <ifname> [window_seconds=3]
 * Exit 0 on a clean attach+detach, non-zero on failure. Prints:
 *   READY            (after attach; flush so the test can sync)
 *   DELTA=<n>        (packets counted during the window)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "xdp_load.h"

int main(int argc, char **argv)
{
    const char *ifname;
    int window;
    struct xdp_load *x = NULL;
    long long before, after;

    setvbuf(stdout, NULL, _IOLBF, 0);            /* line-buffered so READY flushes */

    if (argc < 2) {
        fprintf(stderr, "usage: %s <ifname> [window_seconds=3]\n", argv[0]);
        return 2;
    }
    ifname = argv[1];
    window = (argc > 2) ? atoi(argv[2]) : 3;
    if (window < 1) window = 1;

    int err = xdp_load_attach(ifname, &x);
    if (err) {
        fprintf(stderr, "xdp_load_attach(%s) failed: %d (%s)\n",
                ifname, err, strerror(-err));
        return 1;
    }

    before = xdp_load_pkt_count(x);
    printf("READY ifindex_window=%d\n", window);
    fflush(stdout);

    /* window: the test injects packets here */
    sleep(window);

    after = xdp_load_pkt_count(x);
    printf("DELTA=%lld\n", (after - before));

    xdp_load_detach(x);
    return 0;
}
