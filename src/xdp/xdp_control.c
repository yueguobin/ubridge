/* xdp_control.c — Phase 2 increment E: control-plane translation.
 *
 *   xdp_control <ifname> <peer_ifname> <sink_host> <sink_port> [node] [filter_name] [window=30]
 *
 * Runs the full forward+marker+filter dataplane live, then reads ubridge-style
 * control verbs from stdin (one per line) and translates each into a BPF map
 * update that flips the running dataplane's behavior — the XDP equivalent of the
 * userspace flag flips the marker/filter modules do today. Prints READY, then
 * `OK <...>` after each applied verb so a test can sync before injecting. EOF,
 * `quit`, or the window watchdog ends the run.
 *
 * Verbs (the runtime subset of ubridge's marker/filter control plane):
 *   marker pause | marker resume                      -> marker_ctrl[0]        (global gate)
 *   enable_packet_filter <name> on|off                 -> filter_ctrl[id].enabled
 *   filter <name> action drop|pass                     -> filter_ctrl[id].action
 *   filter <name> direction both|tx|rx                 -> filter_ctrl[id].direction
 *
 * No new eBPF (E is pure userspace): every verb is a partial update on one of the
 * two control maps already added in C1/D. Match is still the IPv4 placeholder;
 * real cBPF->eBPF (change-BPF) is increment F.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>

#include "xdp_load.h"
#include "xdp_events.h"

#define MAX_FILTERS 8

struct marker_ctx { int sink_fd; const char *node; const char *filter; };
struct filter_name { char name[64]; int id; };

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
    return 0;
}

static void *consumer_thread(void *arg)
{
    struct ring_buffer *rb = arg;
    while (!atomic_load(&g_stop))
        ring_buffer__poll(rb, 100);
    return NULL;
}

static int name_to_id(struct filter_name *f, int n, const char *name)
{
    int i;
    for (i = 0; i < n; i++)
        if (!strcmp(f[i].name, name))
            return f[i].id;
    return -1;
}

static int parse_onoff(const char *s)
{
    if (!strcmp(s, "on"))  return 1;
    if (!strcmp(s, "off")) return 0;
    return -1;
}

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

/* Translate one verb line to a map update. Returns 1 to continue, 0 to end
 * (quit/EOF), <0 on a parse/apply error (an ERR line is printed here). */
static int apply_verb(struct xdp_load *x, struct filter_name *f, int nfilters, char *line)
{
    char *tok[8];
    int n = 0, id, v, err;
    char *save = NULL;

    for (n = 0; n < 8 && (tok[n] = strtok_r(n ? NULL : line, " \t\r\n", &save)); n++)
        ;

    if (n == 0)
        return 1;                       /* blank line */

    if (!strcmp(tok[0], "quit"))
        return 0;

    if (!strcmp(tok[0], "marker") && n == 2 &&
        (!strcmp(tok[1], "pause") || !strcmp(tok[1], "resume"))) {
        err = xdp_load_set_marker_enabled(x, !strcmp(tok[1], "resume"));
        if (err) { printf("ERR marker %s: %s\n", tok[1], strerror(-err)); return 1; }
        printf("OK marker %s\n", tok[1]);
        return 1;
    }

    if (!strcmp(tok[0], "enable_packet_filter") && n == 3) {
        id = name_to_id(f, nfilters, tok[1]);
        v  = parse_onoff(tok[2]);
        if (id < 0) { printf("ERR no filter '%s'\n", tok[1]); return 1; }
        if (v < 0)  { printf("ERR expected on|off, got '%s'\n", tok[2]); return 1; }
        err = xdp_load_filter_set_enabled(x, id, v);
        if (err) { printf("ERR enable: %s\n", strerror(-err)); return 1; }
        printf("OK filter %s %s\n", tok[1], v ? "enabled" : "paused");
        return 1;
    }

    if (!strcmp(tok[0], "filter") && n == 4) {
        id = name_to_id(f, nfilters, tok[1]);
        if (id < 0) { printf("ERR no filter '%s'\n", tok[1]); return 1; }
        if (!strcmp(tok[2], "action")) {
            v = parse_action(tok[3]);
            if (v < 0) { printf("ERR action drop|pass, got '%s'\n", tok[3]); return 1; }
            err = xdp_load_filter_set_action(x, id, v);
        } else if (!strcmp(tok[2], "direction")) {
            v = parse_direction(tok[3]);
            if (v < 0) { printf("ERR direction both|tx|rx, got '%s'\n", tok[3]); return 1; }
            err = xdp_load_filter_set_direction(x, id, v);
        } else {
            printf("ERR filter field '%s' (action|direction)\n", tok[2]);
            return 1;
        }
        if (err) { printf("ERR filter %s: %s\n", tok[2], strerror(-err)); return 1; }
        printf("OK filter %s %s %s\n", tok[1], tok[2], tok[3]);
        return 1;
    }

    printf("ERR unknown verb '%s'\n", tok[0]);
    return 1;
}

int main(int argc, char **argv)
{
    const char *ifname, *peer, *sink_host, *node, *fname;
    int sink_port, window, err, sink_fd;
    struct xdp_load *x = NULL;
    struct sockaddr_in sa;
    struct filter_name fnames[MAX_FILTERS];
    int nfilters = 0;

    setvbuf(stdout, NULL, _IOLBF, 0);

    if (argc < 5) {
        fprintf(stderr, "usage: %s <ifname> <peer_ifname> <sink_host> <sink_port> "
                "[node] [filter_name] [window=30]\n", argv[0]);
        return 2;
    }
    ifname    = argv[1];
    peer      = argv[2];
    sink_host = argv[3];
    sink_port = atoi(argv[4]);
    node      = (argc > 5) ? argv[5] : "node";
    fname     = (argc > 6) ? argv[6] : "filter";
    window    = (argc > 7) ? atoi(argv[7]) : 30;
    if (window < 1) window = 30;

    err = xdp_load_attach(ifname, &x);
    if (err) {
        fprintf(stderr, "xdp_load_attach(%s) failed: %d (%s)\n", ifname, err, strerror(-err));
        return 1;
    }

    err = xdp_load_set_peer(x, peer);
    if (err) { fprintf(stderr, "set_peer(%s): %s\n", peer, strerror(-err)); xdp_load_detach(x); return 1; }

    /* one DROP filter, both directions, enabled — the test flips these live. */
    err = xdp_load_set_filter(x, 0, XDP_FILT_ACT_DROP, XDP_FILT_DIR_BOTH, 1);
    if (err) { fprintf(stderr, "set_filter: %s\n", strerror(-err)); xdp_load_detach(x); return 1; }
    snprintf(fnames[0].name, sizeof(fnames[0].name), "%s", fname);
    fnames[0].id = 0;
    nfilters = 1;

    sink_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sink_fd < 0) { perror("socket"); xdp_load_detach(x); return 1; }
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(sink_port);
    if (inet_pton(AF_INET, sink_host, &sa.sin_addr) != 1) {
        fprintf(stderr, "bad sink host: %s\n", sink_host);
        close(sink_fd); xdp_load_detach(x); return 1;
    }
    connect(sink_fd, (struct sockaddr *)&sa, sizeof(sa));

    struct marker_ctx mc = { sink_fd, node, fname };
    struct ring_buffer *rb = ring_buffer__new(xdp_load_events_fd(x), handle_event, &mc, NULL);
    if (!rb) { fprintf(stderr, "ring_buffer__new failed\n"); close(sink_fd); xdp_load_detach(x); return 1; }

    pthread_t t;
    atomic_store(&g_stop, 0);
    pthread_create(&t, NULL, consumer_thread, rb);

    err = xdp_load_set_marker_enabled(x, 1);   /* marker on at start */
    if (err) fprintf(stderr, "marker enable: %s\n", strerror(-err));

    printf("READY filter=%s\n", fname);
    fflush(stdout);

    signal(SIGALRM, SIG_DFL);                  /* default = terminate (watchdog) */
    alarm(window);

    char line[256];
    while (fgets(line, sizeof(line), stdin)) {
        if (apply_verb(x, fnames, nfilters, line) == 0)
            break;
        fflush(stdout);
    }

    alarm(0);
    atomic_store(&g_stop, 1);
    pthread_join(t, NULL);
    ring_buffer__free(rb);

    xdp_load_set_marker_enabled(x, 0);
    close(sink_fd);
    xdp_load_detach(x);
    return 0;
}
