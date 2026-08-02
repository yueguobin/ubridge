/* marker_bench.c — high-rate data-plane benchmark for the `mark` filter.
 *
 * WHY THIS EXISTS
 *   The Python perf suite (tests/marker/test_marker_perf.py) tops out near
 *   ~130k pps because three Python threads fight over the GIL — that is the
 *   *harness* limit, not ubridge's. To find ubridge's real ceiling (the pps at
 *   which its relay thread — cBPF match + per-packet marker_emit under a mutex
 *   + relay sendto — can no longer keep up and starts dropping on its NIO input
 *   buffer), we need a native sender. This tool is that sender.
 *
 * DESIGN — control plane in Python, data plane in C
 *   A launcher (bench/run_bench.py) spawns ubridge and configures the bridge +
 *   signal sink + `mark` filter over the control channel, then execs this
 *   binary with five UDP ports. This binary does ONLY the hot path:
 *     • sender  : bind <send_src>, sendmmsg batches to <send_dst> at a target
 *                 rate (0 = full speed, -1 = built-in sweep);
 *     • drainer x2: recvmmsg on <relay_recv> (relayed frames) and <signal_recv>
 *                 (MARK signals), counting concurrently.
 *   After each window we report sent / relayed / signals pps and the loss
 *   ratios. relay/sent < 100%  => ubridge (or its input buffer) is the limiter;
 *   signal/relay < 100%        => marker_emit is dropping — the real ceiling.
 *
 * BUILD
 *   cc -O2 -o bench/marker_bench bench/marker_bench.c
 *   (run_bench.py builds it automatically if the binary is missing)
 *
 * USAGE
 *   marker_bench <send_dst=la> <send_src=ra> <relay_recv=rb> <signal_recv=sink> [pps] [window_s]
 *   pps: 0 = full speed (default), -1 = sweep {50k,100k,200k,500k,1M,full}
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BATCH       64          /* msgs per sendmmsg/recvmmsg syscall         */
#define PAYLOAD_LEN 34          /* eth(14) + ipv4(20), matches the BPF `ip`   */
#define BUF_LEN     256         /* drain buf: fits relayed frames AND signals */
#define BIG_RCVBUF  (8 * 1024 * 1024)
#define DRAIN_GRACE 1.0         /* keep draining after the send window (s)     */

/* Ethernet+broadcast + a minimal IPv4 header. BPF `ip` matches ethertype
 * 0x0800 at offset 12; identical to tests' _ip_frame(). */
static const unsigned char FRAME[PAYLOAD_LEN] = {
    /* eth: dst bc, src, ethertype 0x0800 (BPF `ip` matches here) */
    0xff,0xff,0xff,0xff,0xff,0xff, 0x00,0x11,0x22,0x33,0x44,0x55, 0x08,0x00,
    /* ipv4 (20): ver/ihl, tos, len=20, id, flags/frag, ttl=64, proto=UDP, csum, src, dst */
    0x45,0x00, 0x00,0x14, 0x12,0x34, 0x00,0x00, 0x40,0x11, 0x00,0x00,
    10,0,0,1, 10,0,0,2
};

static _Atomic long g_sent = 0, g_relayed = 0, g_signals = 0;
static _Atomic int  g_stop = 0;

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void sleep_until(double deadline)
{
    double dt = deadline - now_sec();
    if (dt <= 0) return;
    struct timespec ts;
    ts.tv_sec  = (time_t)dt;
    ts.tv_nsec = (long)((dt - ts.tv_sec) * 1e9);
    nanosleep(&ts, NULL);
}

struct drain_args { int fd; _Atomic long *ctr; };

/* Drain thread: non-blocking recvmmsg in a tight loop, brief nanosleep when
 * idle so we recheck g_stop ~every 10 ms (a blocking recvmmsg with a timeout
 * does NOT reliably wake on this kernel, so the join would deadlock). Counts
 * packets, not latency, so the idle sleep is cost-free for the measurement.
 * A final non-blocking flush drains whatever is still in flight. */
static void *drain_thread(void *arg)
{
    struct drain_args *d = arg;
    struct mmsghdr msg[BATCH];
    struct iovec   iov[BATCH];
    unsigned char  buf[BATCH][BUF_LEN];
    for (int i = 0; i < BATCH; i++) {
        iov[i].iov_base = buf[i];
        iov[i].iov_len  = BUF_LEN;
        msg[i].msg_hdr.msg_iov        = &iov[i];
        msg[i].msg_hdr.msg_iovlen     = 1;
        msg[i].msg_hdr.msg_name       = NULL;
        msg[i].msg_hdr.msg_namelen    = 0;
        msg[i].msg_hdr.msg_control    = NULL;
        msg[i].msg_hdr.msg_controllen = 0;
    }
    struct timespec idle = { 0, 10 * 1000 * 1000 };   /* 10 ms */
    while (!atomic_load(&g_stop)) {
        int n = recvmmsg(d->fd, msg, BATCH, MSG_DONTWAIT, NULL);
        if (n > 0) atomic_fetch_add(d->ctr, n);
        else nanosleep(&idle, NULL);
    }
    for (;;) {                                         /* final flush */
        int n = recvmmsg(d->fd, msg, BATCH, MSG_DONTWAIT, NULL);
        if (n <= 0) break;
        atomic_fetch_add(d->ctr, n);
    }
    return NULL;
}

/* Send PAYLOAD frames to dst at target_pps (0 = full speed) for window seconds. */
static void run_sender(int fd, struct sockaddr_in *dst, double target_pps, double window)
{
    struct mmsghdr msg[BATCH];
    struct iovec   iov[BATCH];
    for (int i = 0; i < BATCH; i++) {
        iov[i].iov_base = (void *)FRAME;
        iov[i].iov_len  = PAYLOAD_LEN;
        msg[i].msg_hdr.msg_iov        = &iov[i];
        msg[i].msg_hdr.msg_iovlen     = 1;
        msg[i].msg_hdr.msg_name       = dst;
        msg[i].msg_hdr.msg_namelen    = sizeof(*dst);
        msg[i].msg_hdr.msg_control    = NULL;
        msg[i].msg_hdr.msg_controllen = 0;
        msg[i].msg_hdr.msg_flags      = 0;
    }
    double t0 = now_sec();
    long sent = 0;
    while (now_sec() - t0 < window) {
        if (target_pps > 0)
            sleep_until(t0 + (double)(sent + BATCH) / target_pps);
        int n = sendmmsg(fd, msg, BATCH, 0);
        if (n > 0) sent += n;
        else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            perror("sendmmsg");
    }
    atomic_fetch_add(&g_sent, sent);
}

static int bind_udp(unsigned short port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); exit(2); }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    int sz = BIG_RCVBUF;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    struct sockaddr_in a = {0};
    a.sin_family      = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port        = htons(port);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
        fprintf(stderr, "bind :%d: %s\n", port, strerror(errno));
        exit(2);
    }
    return fd;
}

/* Run one window: zero the counters, send, give ubridge a grace period to flush
 * in-flight packets and the drainers to catch up, then snapshot. */
static void run_window(int send_fd, struct sockaddr_in *dst,
                       double target_pps, double window, const char *label)
{
    atomic_store(&g_sent, 0);
    atomic_store(&g_relayed, 0);
    atomic_store(&g_signals, 0);
    double t0 = now_sec();
    run_sender(send_fd, dst, target_pps, window);
    sleep_until(t0 + window + DRAIN_GRACE);   /* let in-flight + drains settle */
    long sent    = atomic_load(&g_sent);
    long relayed = atomic_load(&g_relayed);
    long signals = atomic_load(&g_signals);
    double dt    = window;   /* packets flow during the send window (grace only
                              * drains the in-flight backlog, so /window is the
                              * true sustained rate for keep-up rows and shows
                              * the processing ceiling for saturated rows) */
    double r_pct  = sent    ? 100.0 * relayed / sent    : 0;
    double sr_pct = relayed ? 100.0 * signals / relayed : 0;
    printf("%-12s %-14ld %-14ld (%6.0f pps)  %-14ld (%6.0f pps)  %5.1f%%  %5.1f%%\n",
           label, sent, relayed, relayed / dt, signals, signals / dt, r_pct, sr_pct);
}

int main(int argc, char **argv)
{
    if (argc < 5) {
        fprintf(stderr,
            "usage: %s <send_dst=la> <send_src=ra> <relay_recv=rb> <signal_recv=sink> [pps] [window_s]\n"
            "  pps: 0 = full speed, -1 = sweep (default 0)\n", argv[0]);
        return 2;
    }
    unsigned short la   = (unsigned short)atoi(argv[1]);
    unsigned short ra   = (unsigned short)atoi(argv[2]);
    unsigned short rb   = (unsigned short)atoi(argv[3]);
    unsigned short sink = (unsigned short)atoi(argv[4]);
    long pps   = (argc > 5) ? atol(argv[5]) : 0;
    double win = (argc > 6) ? atof(argv[6]) : 2.0;
    setvbuf(stdout, NULL, _IONBF, 0);   /* unbuffered so progress isn't lost on kill */

    int send_fd = bind_udp(ra);                 /* sender source = NIO-A remote */
    int rel_fd  = bind_udp(rb);                 /* relayed frames land here      */
    int sig_fd  = bind_udp(sink);               /* MARK signals land here        */

    struct sockaddr_in dst = {0};
    dst.sin_family      = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dst.sin_port        = htons(la);            /* send into NIO-A (tx)          */

    /* drainers run for the lifetime of the process */
    struct drain_args rargs = { rel_fd, &g_relayed };
    struct drain_args sargs = { sig_fd, &g_signals };
    pthread_t rt, st;
    pthread_create(&rt, NULL, drain_thread, &rargs);
    pthread_create(&st, NULL, drain_thread, &sargs);

    printf("send_dst=:%d  send_src=:%d  relay_recv=:%d  signal_recv=:%d  window=%.1fs\n",
           la, ra, rb, sink, win);
    printf("%-12s %-14s %-26s %-26s %-6s %-6s\n",
           "rate", "sent", "relayed", "signals", "rel%", "sig/rel%");
    printf("---------------------------------------------------------------------------------------------\n");

    if (pps == -1) {
        double rates[] = {50000, 100000, 200000, 500000, 1000000, 0};
        char buf[16];
        for (size_t i = 0; i < sizeof(rates)/sizeof(rates[0]); i++) {
            snprintf(buf, sizeof(buf), rates[i] ? "%.0fk" : "full", rates[i]/1000.0);
            run_window(send_fd, &dst, rates[i], win, buf);
        }
    } else {
        char buf[16];
        snprintf(buf, sizeof(buf), pps ? "%.0fk" : "full", pps/1000.0);
        run_window(send_fd, &dst, (double)pps, win, buf);
    }

    atomic_store(&g_stop, 1);
    pthread_join(rt, NULL);
    pthread_join(st, NULL);
    return 0;
}
