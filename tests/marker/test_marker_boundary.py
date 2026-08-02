"""Boundary tests for the `mark` filter + the generic enable/disable flag.

Edges the happy-path suites (test_basic / test_dir_filter / test_pause) skip:

  1. an invalid `dir` value is rejected at add time (setup returns an error);
  2. the default — no `dir` keyword — fires on BOTH directions;
  3. a near-MTU IP frame still matches (signal + pcap) and a 1-byte packet is
     relayed without trouble (it just doesn't match `ip`);
  4. a bad pcap path is rejected at add time;
  5. `enable_packet_filter` is GENERIC: pausing a `bpf` (drop) filter stops the
     drop, proving the relay-loop bypass works for any filter type, not just
     `mark`.

Pure user-space (UDP + libpcap cBPF) — no sudo.
"""
import os
import sys
import socket
import struct
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "brctl"))
from common import Ubridge, Results  # noqa: E402

PORT = 13090
REPO_UBRIDGE = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "ubridge"))
PCAP = "/tmp/ubmark_boundary.pcap"


def _free_udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _ip_frame(payload_len=0):
    """Ethernet + IPv4 frame with `payload_len` bytes of IP payload. BPF `ip`
    matches on ethertype 0x0800 + IP version, so padding after a valid 20B header
    still matches — used to build a near-MTU frame."""
    eth = b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55" + struct.pack("!H", 0x0800)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + payload_len, 0x1234, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    return eth + ip + (b"\x00" * payload_len)


def main():
    r = Results()
    marker_port = _free_udp()
    la, lb = _free_udp(), _free_udp()
    ra, rb = _free_udp(), _free_udp()

    ms = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); ms.settimeout(0.4); ms.bind(("127.0.0.1", marker_port))
    rbs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); rbs.settimeout(0.4); rbs.bind(("127.0.0.1", rb))
    inj_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); inj_a.bind(("127.0.0.1", ra))   # => tx
    # rbs (bound to rb, NIO-B's remote) doubles as the rx-side injector: sending
    # to lb from rb injects into NIO-B (the rx direction).

    frame = _ip_frame()

    def drain():
        n = 0
        while True:
            try:
                ms.recvfrom(4096); n += 1
            except socket.timeout:
                return n

    def clear_rbs():
        try:
            while True:
                rbs.recvfrom(65535)
        except socket.timeout:
            pass

    try:
        with Ubridge(port=PORT, binary=REPO_UBRIDGE) as ub:
            c = ub.connect()
            try:
                c.send("marker sink 127.0.0.1 %d" % marker_port)
                c.send("marker node bnode")
                c.send("bridge create br0")
                c.send("bridge add_nio_udp br0 %d 127.0.0.1 %d" % (la, ra))   # NIO-A = source (tx)
                c.send("bridge add_nio_udp br0 %d 127.0.0.1 %d" % (lb, rb))   # NIO-B = dest  (rx)
                c.send("bridge start br0")
                time.sleep(0.2)

                # 1. invalid `dir` value rejected at add time.
                r.check("invalid dir rejected at add",
                        c.send("bridge add_packet_filter br0 fbad mark ip dir sideways").startswith("2"))
                c.send("bridge delete_packet_filter br0 fbad")   # tidy (it's appended before setup fails)

                # 2. default (no dir) fires on BOTH directions.
                c.send("bridge add_packet_filter br0 fboth mark ip")
                drain(); inj_a.sendto(frame, ("127.0.0.1", la)); time.sleep(0.2)
                rbs.sendto(frame, ("127.0.0.1", lb)); time.sleep(0.2)   # inject NIO-B (rx)
                n = drain()
                r.check("no dir: fires both directions (2)", n == 2, "got %d" % n)
                c.send("bridge delete_packet_filter br0 fboth")

                # 3. near-MTU frame matches; 1-byte packet is relayed, no crash.
                if os.path.exists(PCAP):
                    os.remove(PCAP)
                c.send("bridge add_packet_filter br0 fbig mark ip pcap %s" % PCAP)
                big = _ip_frame(1400)                  # ~1414B ethernet frame (near MTU)
                drain(); clear_rbs(); inj_a.sendto(big, ("127.0.0.1", la)); time.sleep(0.2)
                r.check("near-MTU IP frame matches (signal)", drain() == 1)
                r.check("near-MTU IP captured to pcap",
                        os.path.exists(PCAP) and os.path.getsize(PCAP) > 24 + 16)
                tiny = b"\x01"                          # 1 byte — won't match `ip`, must still relay
                clear_rbs(); inj_a.sendto(tiny, ("127.0.0.1", la)); time.sleep(0.2)
                try:
                    rel, _ = rbs.recvfrom(65535)
                    r.check("1-byte packet relayed, no crash", rel == tiny)
                except socket.timeout:
                    r.check("1-byte packet relayed, no crash", False, "timeout")
                c.send("bridge delete_packet_filter br0 fbig")

                # 4. bad pcap path rejected at add time.
                r.check("bad pcap path rejected",
                        c.send("bridge add_packet_filter br0 fbadpcap mark ip pcap /no/such/dir/x.pcap").startswith("2"))
                c.send("bridge delete_packet_filter br0 fbadpcap")   # tidy (appended before setup fails)

                # 5. enable_packet_filter is generic: a paused `bpf` (drop) filter
                #    stops dropping, so traffic flows again.
                c.send("bridge add_packet_filter br0 fdrop bpf ip")   # drops IP on match
                clear_rbs(); inj_a.sendto(frame, ("127.0.0.1", la)); time.sleep(0.2)
                try:
                    rbs.recvfrom(65535); dropped_when_active = False
                except socket.timeout:
                    dropped_when_active = True
                r.check("bpf filter drops IP when active", dropped_when_active)

                r.check("pause bpf filter", c.send("bridge enable_packet_filter br0 fdrop off").startswith("100-"))
                clear_rbs(); inj_a.sendto(frame, ("127.0.0.1", la)); time.sleep(0.2)
                try:
                    rbs.recvfrom(65535); passes_when_paused = True
                except socket.timeout:
                    passes_when_paused = False
                r.check("bpf filter bypassed when paused (relay resumes)", passes_when_paused)
            finally:
                c.send("bridge stop br0")
                c.send("bridge delete br0")
                c.close()
    finally:
        for s in (ms, rbs, inj_a):
            s.close()
        if os.path.exists(PCAP):
            os.remove(PCAP)

    return 0 if r.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
