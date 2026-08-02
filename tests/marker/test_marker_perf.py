"""Performance / scale regression for the `mark` filter.

The mark filter's hot path (filter-loop iteration + cBPF match + marker_emit's
per-call UDP sendto under a mutex) runs on every packet, so a regression there
silently collapses relay throughput or loses signals. This is a *regression
guard*, not a ceiling measurement: two checks at a paced rate (deterministic
counts — an instant burst just tests the kernel UDP buffer, not ubridge):

  1. no collapse — a paced stream is still relayed at ~full rate with a `mark`
     filter attached (the passive tap adds no blocking work);
  2. sink keeps up — every match emits a UDP signal; assert the sink drains
     ~all of them (no marker_emit loss under sustained load).

The ABSOLUTE ceiling lives in bench/ (a native sendmmsg/recvmmsg tool, since
Python's ~130k pps GIL limit can't stress ubridge). That benchmark measured
ubridge sustaining ~200k pps lossless (relay AND signal) with the mark filter,
hard-saturating near ~209k pps — and signal/relay stayed 100% right through
saturation. So the ~2k pps paced rate here is ~1% of capacity: deliberately
conservative for a stable, deterministic regression check, not a performance
claim.

RECEIVER BUFFERS: the sink (`ms`) and relay receiver (`rbs`) MUST have a large
SO_RCVBUF. Without it, their default ~212 KB kernel buffer (~221 datagrams)
overflows during the send window (the test drains only AFTER sending), which
shows up as a false ~37% "loss" that is pure test-harness buffer overflow, not
ubridge dropping — ubridge never lost a packet in any run.

Pure user-space (UDP + libpcap cBPF) — no sudo.
"""
import os
import sys
import socket
import struct
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "brctl"))
from common import Ubridge, Results  # noqa: E402

PORT = 13100
HOST = "127.0.0.1"
REPO_UBRIDGE = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "ubridge"))
N = 200          # packets per stream
GAP = 0.0005     # 0.5ms pacing -> ~2000 pps (~1% of ubridge's ~200k pps ceiling;
                 # conservative + deterministic — see bench/ for the real ceiling)


def _free_udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _ip_frame():
    eth = b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55" + struct.pack("!H", 0x0800)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20, 0x1234, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    return eth + ip


def _drain(sock, timeout=2.0):
    sock.settimeout(timeout)
    n = 0
    try:
        while True:
            sock.recvfrom(65535); n += 1
    except socket.timeout:
        return n


def main():
    r = Results()
    marker_port = _free_udp()
    la, lb = _free_udp(), _free_udp()
    ra, rb = _free_udp(), _free_udp()

    # Large SO_RCVBUF on the receivers: without it their default ~212 KB kernel
    # buffer overflows during the send window (drain happens only after), faking a
    # ~37% loss that is harness buffer overflow, not ubridge. See module docstring.
    BIG = 4 * 1024 * 1024
    ms = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); ms.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, BIG); ms.bind((HOST, marker_port))   # signal sink
    rbs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); rbs.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, BIG); rbs.bind((HOST, rb))          # relay receiver
    inj = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); inj.bind((HOST, ra))           # injector (=> tx)

    frame = _ip_frame()

    def paced():
        """Send N frames at ~2000 pps; return (relayed_count, elapsed_s)."""
        _drain(rbs, timeout=0.3)
        t0 = time.monotonic()
        for _ in range(N):
            inj.sendto(frame, (HOST, la))
            time.sleep(GAP)
        count = _drain(rbs, timeout=2.0)
        return count, time.monotonic() - t0

    try:
        with Ubridge(port=PORT, binary=REPO_UBRIDGE) as ub:
            c = ub.connect()
            try:
                c.send("marker sink %s %d" % (HOST, marker_port))
                c.send("marker node perfnode")
                c.send("bridge create br0")
                c.send("bridge add_nio_udp br0 %d %s %d" % (la, HOST, ra))
                c.send("bridge add_nio_udp br0 %d %s %d" % (lb, HOST, rb))
                c.send("bridge start br0")
                time.sleep(0.2)

                # 1. baseline — paced stream relayed at ~full rate.
                base, base_dt = paced()
                base_pps = base / base_dt if base_dt else 0
                r.check("perf: baseline sustains the paced stream (>= 90%%)",
                        base >= 0.9 * N, "%d/%d (%.0f pps)" % (base, N, base_pps))

                # 2. same stream WITH a mark filter — must not collapse, and the
                #    sink must drain ~every match.
                c.send("bridge add_packet_filter br0 f mark ip")
                _drain(ms, timeout=0.3)
                mark, mark_dt = paced()
                mark_pps = mark / mark_dt if mark_dt else 0
                sig = _drain(ms, timeout=2.0)
                r.check("perf: mark filter sustains the paced stream (>= 90%%)",
                        mark >= 0.9 * N, "%d/%d (%.0f pps)" % (mark, N, mark_pps))
                r.check("perf: sink keeps up — signals ~= relayed (>= 90%%)",
                        mark > 0 and sig >= 0.9 * mark,
                        "signals=%d relayed=%d" % (sig, mark))
            finally:
                c.send("bridge stop br0")
                c.send("bridge delete br0")
                c.close()
    finally:
        for s in (ms, rbs, inj):
            s.close()

    return 0 if r.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
