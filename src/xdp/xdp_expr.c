/* xdp_expr.c — Phase 2 increment F: cBPF → eBPF TRANSLATION (not interpretation).
 *
 *   xdp_expr <ifname> <peer_ifname> <sink_host> <sink_port> [node] [filter] [init_expr=ip] [window=30]
 *
 * Architecture (tail-call split):
 *   dispatcher (compiled C, XDP entry) – count + tail_call(prog_array, 0)
 *   prog_array[0] = generated match (cBPF translated to eBPF, fixed-offset reads)
 *     → writes scratch[0] = matched → tail_call(prog_array, 1)
 *   epilogue    (compiled C, prog_array[1]) – marker/filter/forward
 *
 * Changing the expression = re-translate, bpf_prog_load the new match, replace
 * prog_array[0] atomically (a map update; the dispatcher is never re-attached).
 * Control verbs (marker/filter) touch the epilogue's maps (in-process, no pinning
 * needed).  See xdp_translate.c for the cBPF→eBPF translator. */
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

#include "xdp_dyn_load.h"
#include "xdp_translate.h"
#include "xdp_cbpf.h"

struct marker_ctx { int sink_fd; const char *node; const char *filter; };
struct filter_name { char name[64]; int id; };

static atomic_int g_stop;

static int handle_event(void *arg, void *data, size_t sz)
{
    struct marker_ctx *mc = arg;
    struct xdp_marker_event *e = data;
    if (sz < sizeof(*e)) return 0;
    unsigned long long sec  = e->ts_ns / 1000000000ULL;
    unsigned long long usec = (e->ts_ns / 1000ULL) % 1000000ULL;
    char line[256];
    int n = snprintf(line, sizeof(line),
        "MARK %llu.%06llu node=%s filter=%s link=- tag=- len=%u dir=%s\n",
        sec, usec, mc->node, mc->filter, e->len,
        e->dir == XDP_DIR_TX ? "tx" : "rx");
    if (n > 0) send(mc->sink_fd, line, (size_t)n, 0);
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
        if (!strcmp(f[i].name, name)) return f[i].id;
    return -1;
}

static int parse_action(const char *s) {
    if (!strcmp(s, "drop")) return XDP_FILT_ACT_DROP;
    if (!strcmp(s, "pass")) return XDP_FILT_ACT_PASS;
    return -1;
}
static int parse_direction(const char *s) {
    if (!strcmp(s, "both")) return XDP_FILT_DIR_BOTH;
    if (!strcmp(s, "tx"))   return XDP_FILT_DIR_TX;
    if (!strcmp(s, "rx"))   return XDP_FILT_DIR_RX;
    return -1;
}

/* trim leading / trailing whitespace + newline in place */
static char *trim_rest(char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    char *end = s + strlen(s);
    while (end > s && (end[-1] == '\n' || end[-1] == '\r' ||
                       end[-1] == ' '  || end[-1] == '\t'))
        *--end = 0;
    return s;
}

/* Compile expr → cBPF → eBPF → swap prog_array[0]. */
static int push_expr(struct xdp_dyn_load *x, const char *expr,
                     int scratch_fd, int prog_array_fd,
                     char *errbuf, size_t errlen)
{
    struct ub_cbpf_insn buf[UB_CBPF_MAX_INSNS];
    int n = cbpf_compile(expr, buf, UB_CBPF_MAX_INSNS, errbuf, (int)errlen);
    if (n < 0) return -1;

    struct bpf_insn *einsns = NULL;
    int elen = 0;
    int err;

    err = cbpf_translate(buf, n, scratch_fd, prog_array_fd,
                         &einsns, &elen, errbuf, (int)errlen);
    if (err < 0) return -1;

    err = xdp_dyn_swap_match(x, einsns, elen);
    free(einsns);
    if (err < 0) { snprintf(errbuf, errlen, "swap match: %s", strerror(-err)); return -1; }
    return n;  /* return cBPF insn count */
}

static int apply_verb(struct xdp_dyn_load *x, struct filter_name *f, int nfilters,
                      int scratch_fd, int prog_array_fd, char *line)
{
    char *tok[8];
    int n = 0, id, v, err;
    char *save = NULL;

    /* `expr <tcpdump...>` takes the rest of the line verbatim */
    if (!strncmp(line, "expr", 4) && (line[4] == ' ' || line[4] == '\t')) {
        char *e = trim_rest(line + 4);
        char errbuf[256];
        if (*e == 0) { printf("ERR expr: empty\n"); return 1; }
        int ninsn = push_expr(x, e, scratch_fd, prog_array_fd, errbuf, sizeof(errbuf));
        if (ninsn < 0) { printf("ERR expr: %s\n", errbuf); return 1; }
        printf("OK expr (%d cBPF insns)\n", ninsn);
        return 1;
    }

    for (n = 0; n < 8 && (tok[n] = strtok_r(n ? NULL : line, " \t\r\n", &save)); n++)
        ;

    if (n == 0) return 1;

    if (!strcmp(tok[0], "quit")) return 0;

    if (!strcmp(tok[0], "marker") && n == 2 &&
        (!strcmp(tok[1], "pause") || !strcmp(tok[1], "resume"))) {
        err = xdp_dyn_set_marker_enabled(x, !strcmp(tok[1], "resume"));
        if (err) { printf("ERR marker %s: %s\n", tok[1], strerror(-err)); return 1; }
        printf("OK marker %s\n", tok[1]);
        return 1;
    }

    if (!strcmp(tok[0], "filter") && n == 4) {
        id = name_to_id(f, nfilters, tok[1]);
        if (id < 0) { printf("ERR no filter '%s'\n", tok[1]); return 1; }
        if (!strcmp(tok[2], "action")) {
            v = parse_action(tok[3]);
            if (v < 0) { printf("ERR action drop|pass, got '%s'\n", tok[3]); return 1; }
            err = xdp_dyn_filter_set_action(x, id, v);
        } else if (!strcmp(tok[2], "direction")) {
            v = parse_direction(tok[3]);
            if (v < 0) { printf("ERR direction both|tx|rx, got '%s'\n", tok[3]); return 1; }
            err = xdp_dyn_filter_set_direction(x, id, v);
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
    const char *ifname, *peer, *sink_host, *node, *fname, *init_expr;
    int sink_port, window, err, sink_fd;
    struct xdp_dyn_load *x = NULL;
    struct sockaddr_in sa;
    struct filter_name fnames[1];
    char errbuf[256];

    setvbuf(stdout, NULL, _IOLBF, 0);

    if (argc < 5) {
        fprintf(stderr, "usage: %s <ifname> <peer_ifname> <sink_host> <sink_port> "
                "[node] [filter] [init_expr=ip] [window=30]\n", argv[0]);
        return 2;
    }
    ifname    = argv[1];
    peer      = argv[2];
    sink_host = argv[3];
    sink_port = atoi(argv[4]);
    node      = (argc > 5) ? argv[5] : "node";
    fname     = (argc > 6) ? argv[6] : "filter";
    init_expr = (argc > 7) ? argv[7] : "ip";
    window    = (argc > 8) ? atoi(argv[8]) : 30;
    if (window < 1) window = 30;

    err = xdp_dyn_attach(ifname, peer, &x);
    if (err) {
        fprintf(stderr, "xdp_dyn_attach(%s) failed: %d (%s)\n", ifname, err, strerror(-err));
        return 1;
    }

    /* one DROP filter, both directions, enabled (test flips these live) */
    err = xdp_dyn_set_filter(x, 0, XDP_FILT_ACT_DROP, XDP_FILT_DIR_BOTH, 1);
    if (err) { fprintf(stderr, "set_filter: %s\n", strerror(-err)); xdp_dyn_detach(x); return 1; }
    snprintf(fnames[0].name, sizeof(fnames[0].name), "%s", fname);
    fnames[0].id = 0;

    err = xdp_dyn_set_marker_enabled(x, 1);
    if (err) fprintf(stderr, "marker enable: %s\n", strerror(-err));

    /* the map fds the translator needs */
    int scratch_fd    = xdp_dyn_scratch_fd(x);
    int prog_array_fd = xdp_dyn_prog_array_fd(x);

    /* compile the initial expression and install the first match */
    int init_n = push_expr(x, init_expr, scratch_fd, prog_array_fd,
                           errbuf, sizeof(errbuf));
    if (init_n < 0) {
        fprintf(stderr, "init expr '%s': %s\n", init_expr, errbuf);
        xdp_dyn_detach(x);
        return 1;
    }

    /* ringbuf consumer -> MARK lines -> UDP sink */
    sink_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sink_fd < 0) { perror("socket"); xdp_dyn_detach(x); return 1; }
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(sink_port);
    if (inet_pton(AF_INET, sink_host, &sa.sin_addr) != 1) {
        fprintf(stderr, "bad sink host: %s\n", sink_host);
        close(sink_fd); xdp_dyn_detach(x); return 1;
    }
    connect(sink_fd, (struct sockaddr *)&sa, sizeof(sa));

    struct marker_ctx mc = { sink_fd, node, fname };
    struct ring_buffer *rb = ring_buffer__new(xdp_dyn_events_fd(x), handle_event, &mc, NULL);
    if (!rb) { fprintf(stderr, "ring_buffer__new failed\n"); close(sink_fd); xdp_dyn_detach(x); return 1; }

    pthread_t t;
    atomic_store(&g_stop, 0);
    pthread_create(&t, NULL, consumer_thread, rb);

    printf("READY filter=%s expr='%s' (%d cBPF insns)\n", fname, init_expr, init_n);
    fflush(stdout);

    signal(SIGALRM, SIG_DFL);
    alarm(window);

    char line[512];
    while (fgets(line, sizeof(line), stdin)) {
        if (apply_verb(x, fnames, 1, scratch_fd, prog_array_fd, line) == 0)
            break;
        fflush(stdout);
    }

    alarm(0);
    atomic_store(&g_stop, 1);
    pthread_join(t, NULL);
    ring_buffer__free(rb);

    xdp_dyn_set_marker_enabled(x, 0);
    close(sink_fd);
    xdp_dyn_detach(x);
    return 0;
}
