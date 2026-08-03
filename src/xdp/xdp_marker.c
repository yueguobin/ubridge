/* xdp_marker.c — Phase 2 increment C1: ingress tx-marker -> ringbuf -> MARK line -> sink.
 *
 *   xdp_marker <ifname> <sink_host> <sink_port> [node] [filter] [window=4]
 *
 * Attaches the XDP program, enables the ingress marker, drains the events
 * ringbuf on a thread, and for each match sends one MARK datagram to the sink
 * (same line format as the userspace marker module). Prints READY, then
 * EMITTED=<n> after the window.
 *
 * The marker name fields (node/filter) are userspace config; the eBPF event
 * carries only ts/len/dir/marker_id (see xdp_events.h).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>

#include "xdp_load.h"
#include "xdp_events.h"

struct marker_ctx {
    int sink_fd;
    const char *node;
    const char *filter;
};

static atomic_int g_emitted;
static atomic_int g_stop;

static int handle_event(void *arg, void *data, size_t sz)
{
    struct marker_ctx *mc = arg;
    struct xdp_marker_event *e = data;
    if (sz < sizeof(*e))
        return 0;
    unsigned long long sec  = e->ts_ns / 1000000000ULL;
    unsigned long long usec = (e->ts_ns / 1000ULL) % 1000000ULL;
    char line[256];
    int n = snprintf(line, sizeof(line),
        "MARK %llu.%06llu node=%s filter=%s link=- tag=- len=%u dir=%s\n",
        sec, usec, mc->node, mc->filter, e->len,
        e->dir == XDP_DIR_TX ? "tx" : "rx");
    if (n > 0)
        send(mc->sink_fd, line, (size_t)n, 0);
    atomic_fetch_add(&g_emitted, 1);
    return 0;
}

static void *consumer_thread(void *arg)
{
    struct ring_buffer *rb = arg;
    while (!atomic_load(&g_stop))
        ring_buffer__poll(rb, 100);   /* drains + invokes handle_event */
    return NULL;
}

int main(int argc, char **argv)
{
    const char *ifname, *sink_host, *node, *filter;
    int sink_port, window, err, sink_fd;
    struct xdp_load *x = NULL;
    struct sockaddr_in sa;

    setvbuf(stdout, NULL, _IOLBF, 0);

    if (argc < 4) {
        fprintf(stderr, "usage: %s <ifname> <sink_host> <sink_port> [node] [filter] [window=4]\n", argv[0]);
        return 2;
    }
    ifname    = argv[1];
    sink_host = argv[2];
    sink_port = atoi(argv[3]);
    node      = (argc > 4) ? argv[4] : "node";
    filter    = (argc > 5) ? argv[5] : "filter";
    window    = (argc > 6) ? atoi(argv[6]) : 4;
    if (window < 1) window = 1;

    err = xdp_load_attach(ifname, &x);
    if (err) {
        fprintf(stderr, "xdp_load_attach(%s) failed: %d (%s)\n", ifname, err, strerror(-err));
        return 1;
    }

    sink_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sink_fd < 0) { perror("socket"); xdp_load_detach(x); return 1; }
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(sink_port);
    if (inet_pton(AF_INET, sink_host, &sa.sin_addr) != 1) {
        fprintf(stderr, "bad sink host: %s\n", sink_host);
        close(sink_fd); xdp_load_detach(x); return 1;
    }
    connect(sink_fd, (struct sockaddr *)&sa, sizeof(sa));   /* default dest for send() */

    struct marker_ctx mc = { sink_fd, node, filter };
    struct ring_buffer *rb = ring_buffer__new(xdp_load_events_fd(x), handle_event, &mc, NULL);
    if (!rb) {
        fprintf(stderr, "ring_buffer__new failed\n");
        close(sink_fd); xdp_load_detach(x); return 1;
    }

    pthread_t t;
    pthread_create(&t, NULL, consumer_thread, rb);

    err = xdp_load_set_marker_enabled(x, 1);
    if (err)
        fprintf(stderr, "xdp_load_set_marker_enabled: %d (%s)\n", err, strerror(-err));

    atomic_store(&g_emitted, 0);
    printf("READY node=%s filter=%s\n", node, filter);
    fflush(stdout);

    sleep(window);                       /* test injects here; sink receives MARK lines */

    atomic_store(&g_stop, 1);
    pthread_join(t, NULL);
    ring_buffer__free(rb);

    printf("EMITTED=%d\n", atomic_load(&g_emitted));
    xdp_load_set_marker_enabled(x, 0);
    close(sink_fd);
    xdp_load_detach(x);
    return 0;
}
