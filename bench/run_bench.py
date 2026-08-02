#!/usr/bin/env python3
"""Launch bench/marker_bench against a freshly-configured ubridge.

Control plane here (spawn ubridge, configure sink + bridge + `mark` filter),
data plane in the C tool (native sendmmsg/recvmmsg — Python's ~130k pps GIL
ceiling can't stress ubridge). Reuses the test helpers (common.Ubridge) so the
control path is identical to the regression suite.

    python3 bench/run_bench.py [pps] [window_s]
      pps: 0 = full speed, -1 = sweep (default). Forwarded to the C bench.
"""
import os
import sys
import socket
import subprocess
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(REPO, "tests", "brctl"))
from common import Ubridge  # noqa: E402

HOST = "127.0.0.1"
PORT = 13300
SRC = os.path.join(HERE, "marker_bench.c")
BIN = os.path.join(HERE, "marker_bench")
UBRIDGE = os.path.join(REPO, "ubridge")


def _free():
    """Discover a free UDP port (bind+close) — same TOCTOU pattern as the tests."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _build():
    if os.path.exists(BIN) and os.path.getmtime(BIN) >= os.path.getmtime(SRC):
        return
    print("[build] cc -O2 marker_bench.c")
    subprocess.check_call(
        ["cc", "-O2", "-Wall", "-Wextra", "-o", BIN, SRC, "-lpthread"]
    )


def main():
    pps = sys.argv[1] if len(sys.argv) > 1 else "-1"
    window = sys.argv[2] if len(sys.argv) > 2 else "2"

    _build()
    # la/lb: ubridge binds these (NIO locals). ra/rb/sink: the C bench binds these.
    la, lb, ra, rb, sink = _free(), _free(), _free(), _free(), _free()

    with Ubridge(port=PORT, binary=UBRIDGE) as ub:
        c = ub.connect()
        try:
            assert c.code("marker sink %s %d" % (HOST, sink)) == "100"
            assert c.code("marker node bench") == "100"
            assert c.code("bridge create br0") == "100"
            assert c.code("bridge add_nio_udp br0 %d %s %d" % (la, HOST, ra)) == "100"
            assert c.code("bridge add_nio_udp br0 %d %s %d" % (lb, HOST, rb)) == "100"
            assert c.code("bridge start br0") == "100"
            time.sleep(0.2)
            assert c.code("bridge add_packet_filter br0 f mark ip") == "100"
            time.sleep(0.2)
            print("[config] sink=%d la=%d(ra=%d) lb=%d(rb=%d)  mark filter on\n" % (sink, la, ra, lb, rb))

            rc = subprocess.call(
                [BIN, str(la), str(ra), str(rb), str(sink), str(pps), str(window)]
            )
        finally:
            c.send("bridge stop br0")
            c.send("bridge delete br0")
            c.close()
    return rc


if __name__ == "__main__":
    sys.exit(main())
