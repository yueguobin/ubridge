"""Performance / scale regression for the `mark` filter.

The mark filter's hot path (filter-loop iteration + cBPF match + marker_emit's
per-call UDP sendto under a mutex) runs on every packet, so a regression there
silently collapses relay throughput or loses signals. Two guards, both at a
paced rate so counts are deterministic (an instant burst just tests the kernel
UDP buffer, not ubridge):

  1. no collapse — a paced stream is still relayed at ~full rate with a `mark`
     filter attached (the passive tap adds no blocking work);
  2. sink keeps up — every match emits a UDP signal; assert the sink drains
     ~all of them (no marker_emit loss under sustained load).

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
GAP = 0.0005     # 0.5ms pacing -> ~2000 pps (well under ubridge's ceiling, no buf loss)


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

    ms = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); ms.bind((HOST, marker_port))   # signal sink
    rbs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); rbs.bind((HOST, rb))           # relay receiver
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
