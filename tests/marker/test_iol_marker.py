"""IOL-bridge marker regression.

The rest of the marker suite only drives the generic UDP `bridge`. IOL bridges
run their own filter loops (iol_nio_listener / iol_bridge_listener) with their
own direction constants, and `iol_bridge enable_packet_filter` is a separate
command path — none of which is covered without this test. It stands up a fake
IOL instance over the netio unix-domain socket and checks direction semantics
from BOTH sides plus the per-port pause/resume.

IOL direction mapping (see hypervisor_iol_bridge.c):
  IOL instance -> bridge  =>  PKT_DIR_TX  (so `dir tx` fires)
  NIO          -> bridge  =>  PKT_DIR_RX  (so `dir rx` fires)
The mark filter is applied to &pkt[IOL_HDR_SIZE] (IOL_HDR_SIZE == 8), so the
BPF sees the ethernet+IP payload behind the 8-byte IOL header.
"""
import os
import sys
import socket
import struct
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "brctl"))
from common import Ubridge, Results  # noqa: E402

PORT = 13110
HOST = "127.0.0.1"
REPO_UBRIDGE = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "ubridge"))
UID = os.getuid()
NETIO_DIR = "/tmp/netio%u" % UID
APP_ID, IOL_ID = 9101, 9102
BRIDGE_SOCK = "%s/%d" % (NETIO_DIR, APP_ID)
IOL_SOCK = "%s/%d" % (NETIO_DIR, IOL_ID)
LPORT, RPORT = 15110, 15111
PK = 0


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


def _iol_frame(dst_id, src_id, port_key, payload):
    f = bytearray(8)
    f[0], f[1] = (dst_id >> 8) & 0xff, dst_id & 0xff    # DST_IDS
    f[2], f[3] = (src_id >> 8) & 0xff, src_id & 0xff    # SRC_IDS
    f[4] = port_key & 0xff                              # DST_PORT
    f[5] = port_key & 0xff                              # SRC_PORT
    f[6] = 1                                            # MSG_TYPE = DATA
    f[7] = 0                                            # CHANNEL
    return bytes(f) + payload


def main():
    r = Results()
    marker_port = _free_udp()
    frame = _ip_frame()
    try:
        os.makedirs(NETIO_DIR, 0o777)
    except FileExistsError:
        pass

    ms = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); ms.settimeout(0.5); ms.bind((HOST, marker_port))
    iol = None
    tx = None
    try:
        with Ubridge(port=PORT, binary=REPO_UBRIDGE) as ub:
            c = ub.connect()
            try:
                # fake IOL instance + the NIO-side injector (bound to the NIO's remote).
                iol = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                try:
                    os.unlink(IOL_SOCK)
                except OSError:
                    pass
                iol.bind(IOL_SOCK); iol.settimeout(0.5)
                tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                tx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                tx.bind((HOST, RPORT))

                assert c.code("marker sink %s %d" % (HOST, marker_port)) == "100"
                assert c.code("marker node iolnode") == "100"
                assert c.code("iol_bridge create iol1 %d" % APP_ID) == "100"
                assert c.code("iol_bridge add_nio_udp iol1 %d 0 0 %d %s %d" % (IOL_ID, LPORT, HOST, RPORT)) == "100"
                assert c.code("iol_bridge start iol1") == "100"
                time.sleep(0.3)

                def drain():
                    n = 0
                    try:
                        while True:
                            ms.recvfrom(4096); n += 1
                    except socket.timeout:
                        return n

                def from_iol():
                    iol.sendto(_iol_frame(APP_ID, IOL_ID, PK, frame), BRIDGE_SOCK)

                def from_nio():
                    tx.sendto(frame, (HOST, LPORT))

                # warm up both directions so connected sockets don't ICMP-refuse.
                drain(); from_iol(); time.sleep(0.2); drain()
                drain(); from_nio(); time.sleep(0.2); drain()

                # 1. dir tx fires only from the IOL instance side.
                assert c.code("iol_bridge add_packet_filter iol1 0 0 ft mark ip dir tx") == "100"
                drain(); from_iol(); time.sleep(0.2); a = drain()
                drain(); from_nio(); time.sleep(0.2); b = drain()
                r.check("IOL dir tx: fires from IOL side only", a == 1 and b == 0,
                        "iol=%d nio=%d" % (a, b))
                assert c.code("iol_bridge delete_packet_filter iol1 0 0 ft") == "100"

                # 2. dir rx fires only from the NIO side.
                assert c.code("iol_bridge add_packet_filter iol1 0 0 fr mark ip dir rx") == "100"
                drain(); from_iol(); time.sleep(0.2); a = drain()
                drain(); from_nio(); time.sleep(0.2); b = drain()
                r.check("IOL dir rx: fires from NIO side only", a == 0 and b == 1,
                        "iol=%d nio=%d" % (a, b))
                assert c.code("iol_bridge delete_packet_filter iol1 0 0 fr") == "100"

                # 3. iol_bridge enable_packet_filter off/on (both-direction filter).
                assert c.code("iol_bridge add_packet_filter iol1 0 0 fb mark ip") == "100"
                drain(); from_iol(); time.sleep(0.2); a = drain()
                r.check("IOL mark baseline fires", a == 1, "got %d" % a)
                assert c.code("iol_bridge enable_packet_filter iol1 0 0 fb off") == "100"
                drain(); from_iol(); time.sleep(0.2); a = drain()
                r.check("IOL enable off: paused (0)", a == 0, "got %d" % a)
                assert c.code("iol_bridge enable_packet_filter iol1 0 0 fb on") == "100"
                drain(); from_iol(); time.sleep(0.2); a = drain()
                r.check("IOL enable on: resumed (1)", a == 1, "got %d" % a)
            finally:
                c.send("iol_bridge stop iol1")
                c.send("iol_bridge delete iol1")
                c.close()
    finally:
        if iol is not None:
            iol.close()
        if tx is not None:
            tx.close()
        ms.close()
        for p in (IOL_SOCK, BRIDGE_SOCK):
            try:
                os.unlink(p)
            except OSError:
                pass

    return 0 if r.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
