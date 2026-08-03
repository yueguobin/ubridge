"""Regression: marker/filter/capture on a linux_raw (AF_PACKET) NIO.

Phase 1 of the tap+XDP mode (see doc/xdp-tap-mode.md): the node<->ubridge join
is `bridge add_nio_linux_raw`, where ubridge raw-attaches a real interface the
node process owns. This stands up a veth pair as a stand-in for a node TAP:
ubridge raw-attaches one end, we AF_PACKET-inject on the peer (playing the node
writing its tap fd), and assert the mark filter's enable/disable, marker
pause/resume, pcap capture, direction, and passive relay behave identically to
the UDP-NIO path in test_basic — which they should, since the bridge filter
loop is NIO-type-agnostic (marker/filter/capture ride on every relayed packet).

Direction mapping (see src/ubridge.c bridge_nios):
  NIO-A = source_nio      -> injecting into it is device-side ingress (tx)
  NIO-B = destination_nio -> injecting into it is link-side ingress  (rx)
Here NIO-A is the raw veth end, so injected frames carry dir=tx.

Needs root: creating a veth pair (CAP_NET_ADMIN) and opening AF_PACKET raw
sockets (CAP_NET_RAW). Skips gracefully otherwise, keeping run_all green.
"""
import os
import sys
import socket
import struct
import subprocess
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "brctl"))
from common import Ubridge, Results  # noqa: E402

PORT = 13080
REPO_UBRIDGE = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "ubridge"))

VETH_A = "ubmtest0"   # ubridge raw-attaches this (source_nio => tx)
VETH_B = "ubmtest1"   # we AF_PACKET-inject here (plays the node writing its tap fd)
ETH_P_ALL = 0x0003


def _free_udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _ip_frame():
    """Minimal Ethernet + IPv4 frame (matches BPF `ip`)."""
    eth = b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55" + struct.pack("!H", 0x0800)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20, 0x1234, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    return eth + ip


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def _veth_ready():
    """Create the veth pair (both ends UP). Returns True on success."""
    if os.geteuid() != 0:
        return False
    _run(["ip", "link", "del", VETH_A])                      # drop a stale pair, ignore errors
    r = _run(["ip", "link", "add", VETH_A, "type", "veth", "peer", "name", VETH_B])
    if r.returncode != 0:
        print("  [NOTE] could not create veth pair: %s" % r.stderr.strip())
        return False
    # Suppress kernel IPv6 autoconf on the veth ends: a freshly-upped interface
    # emits NS/RS (~90-byte) frames that the promisc raw socket would capture and
    # relay, clobbering the first relayed-frame comparison. addrgenmode none
    # stops the link-local generation that triggers them.
    _run(["ip", "link", "set", VETH_A, "addrgenmode", "none"])
    _run(["ip", "link", "set", VETH_B, "addrgenmode", "none"])
    _run(["ip", "link", "set", VETH_A, "up"])
    _run(["ip", "link", "set", VETH_B, "up"])
    return True


def _veth_teardown():
    _run(["ip", "link", "del", VETH_A])                      # deletes both ends


def main():
    r = Results()

    if not _veth_ready():
        print("SKIP: needs root (CAP_NET_ADMIN for veth + CAP_NET_RAW for AF_PACKET); "
              "re-run via sudo to exercise the linux_raw marker path.")
        return 0

    marker_port = _free_udp()
    lb, rb = _free_udp(), _free_udp()      # NIO-B (UDP relay dest): ubridge binds lb, remote rb

    ms = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); ms.settimeout(0.5); ms.bind(("127.0.0.1", marker_port))
    rbs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); rbs.settimeout(0.5); rbs.bind(("127.0.0.1", rb))
    inj = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    inj.bind((VETH_B, 0))                  # send-only: route egress by interface name

    frame = _ip_frame()

    def drain_signals():
        n = 0
        while True:
            try:
                ms.recvfrom(4096); n += 1
            except socket.timeout:
                return n

    def inject():
        inj.send(frame)
        time.sleep(0.3)

    try:
        with Ubridge(port=PORT, binary=REPO_UBRIDGE) as ub:
            c = ub.connect()
            try:
                c.send("marker sink 127.0.0.1 %d" % marker_port)
                c.send("marker node rawnode")
                r.check("bridge create", c.code("bridge create br0") == "100")
                # NIO-A = source_nio (raw) ; NIO-B = destination_nio (udp relay sink)
                r.check("add_nio_linux_raw",
                        c.send("bridge add_nio_linux_raw br0 %s" % VETH_A).startswith("100-"))
                r.check("add_nio_udp (relay dest)",
                        c.send("bridge add_nio_udp br0 %d 127.0.0.1 %d" % (lb, rb)).startswith("100-"))
                r.check("add mark filter",
                        c.send("bridge add_packet_filter br0 f1 mark ip tag 7 link 9").startswith("100-"))
                r.check("bridge start", c.code("bridge start br0") == "100")
                time.sleep(0.2)

                # Safety net for any residual link-up L2 noise (IPv6 NS/RS, MLD)
                # the kernel emits on a freshly-upped veth: the relay forwards
                # everything, so drain rbs before the first asserted relay.
                def drain_rbs():
                    while True:
                        try:
                            rbs.recvfrom(4096)
                        except socket.timeout:
                            return
                drain_rbs()

                # 1. signal + fields + direction arrive on the raw path
                inject()
                try:
                    data, _ = ms.recvfrom(4096)
                    sig = data.decode(errors="replace")
                    r.check("marker signal on raw NIO", sig.startswith("MARK "), sig.strip())
                    r.check("signal fields + dir=tx",
                            all(x in sig for x in
                                ("node=rawnode", "filter=f1", "link=9", "tag=7", "dir=tx")), sig.strip())
                    r.check("signal len", ("len=%d" % len(frame)) in sig, sig.strip())
                except socket.timeout:
                    r.check("marker signal on raw NIO", False, "timeout")

                # 2. passive tap: the frame was still relayed to the UDP dest
                try:
                    rel, _ = rbs.recvfrom(4096)
                    r.check("frame relayed on raw NIO (passive)", rel == frame, "len=%d" % len(rel))
                except socket.timeout:
                    r.check("frame relayed on raw NIO (passive)", False, "timeout")

                # 3. per-filter enable/disable: off => no signal, frame still relayed
                r.check("disable f1", c.send("bridge enable_packet_filter br0 f1 off").startswith("100-"))
                inject()
                r.check("no signal when filter disabled", drain_signals() == 0)
                try:
                    rel, _ = rbs.recvfrom(4096)
                    r.check("still relayed when filter disabled", rel == frame)
                except socket.timeout:
                    r.check("still relayed when filter disabled", False, "timeout")
                r.check("re-enable f1", c.send("bridge enable_packet_filter br0 f1 on").startswith("100-"))
                inject()
                r.check("signal returns after enable", drain_signals() == 1)

                # 4. global pause/resume
                c.send("marker pause")
                inject()
                r.check("no signal while paused", drain_signals() == 0)
                c.send("marker resume")
                inject()
                r.check("signal after resume", drain_signals() == 1)

                # 5. marker sink off => no signals; re-enable for pcap step
                c.send("marker sink off")
                inject()
                r.check("no signal after sink off", drain_signals() == 0)
                c.send("marker sink 127.0.0.1 %d" % marker_port)

                # 6. pcap capture on the raw path
                c.send("bridge delete_packet_filter br0 f1")
                PCAP = "/tmp/ubmark_raw.pcap"
                if os.path.exists(PCAP):
                    os.remove(PCAP)
                r.check("add mark+pcap on raw NIO",
                        c.send("bridge add_packet_filter br0 f2 mark ip pcap %s" % PCAP).startswith("100-"))
                inject()
                time.sleep(0.1)
                c.send("bridge delete_packet_filter br0 f2")    # flush/close the pcap
                time.sleep(0.1)
                r.check("pcap written on raw NIO", os.path.exists(PCAP))
                if os.path.exists(PCAP):
                    blob = open(PCAP, "rb").read()
                    # 24B global header + 16B record header + frame; the frame must be present
                    r.check("pcap has the frame", frame in blob and len(blob) > 24 + 16, "size=%d" % len(blob))
                if os.path.exists(PCAP):
                    os.remove(PCAP)
            finally:
                c.send("bridge stop br0")
                c.send("bridge delete br0")
                c.close()
    finally:
        for s in (ms, rbs, inj):
            s.close()
        _veth_teardown()

    return 0 if r.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
