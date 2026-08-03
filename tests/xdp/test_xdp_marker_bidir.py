"""Phase 2 increment C2: the marker-coverage seam (bidirectional coverage).

With a peer configured, the sender forwards (DEVMAP egress redirect) AND, per the
seam, emits a dir=RX marker on the peer's behalf — because the egress redirect
does not run the peer's netdev XDP, the receiver's rx-direction marker must run
on the sender. So injecting one IPv4 frame A->B yields TWO MARK lines at the
sink: dir=tx (a0's own ingress marker) and dir=rx (the peer's, emitted on a0).
b0 has no XDP program — proves coverage without the peer's XDP running.

Needs root (veth + AF_PACKET + XDP attach). Skips cleanly in a user namespace.
"""
import os
import sys
import socket
import struct
import subprocess
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "brctl"))
from common import Results  # noqa: E402

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
MARKER = os.path.join(REPO, "src", "xdp", "xdp_marker")

A0, A1 = "ubxb0", "ubxb1"     # a0 = XDP attach + sender ; a1 = inject
B0, B1 = "ubxb2", "ubxb3"     # b0 = peer / redirect target (no XDP) ; b1 = unused peer of b0
ETH_P_ALL = 0x0003


def _ipv4_frame():
    eth = b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55" + struct.pack("!H", 0x0800)
    return eth + b"\x45\x00" + b"\x00\x14" + b"\x00" * 16


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def _links_ready():
    if os.geteuid() != 0:
        return False
    for p in (A0, B0):
        _run(["ip", "link", "del", p])
    for a, b in ((A0, A1), (B0, B1)):
        if _run(["ip", "link", "add", a, "type", "veth", "peer", "name", b]).returncode != 0:
            return False
    for ifc in (A0, A1, B0, B1):
        _run(["ip", "link", "set", ifc, "addrgenmode", "none"])
        _run(["ip", "link", "set", ifc, "up"])
    return True


def _links_teardown():
    for p in (A0, B0):
        _run(["ip", "link", "del", p])


def _free_udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def main():
    r = Results()

    if not os.path.exists(MARKER):
        print("SKIP: %s not built (run `make xdp`)." % MARKER)
        return 0
    if not _links_ready():
        print("SKIP: needs root (veth + AF_PACKET + XDP attach); re-run via sudo "
              "or `unshare -Urn` to exercise the marker-coverage seam.")
        return 0

    sink_port = _free_udp()
    ms = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); ms.settimeout(0.5); ms.bind(("127.0.0.1", sink_port))
    inj = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)); inj.bind((A1, 0))
    frame = _ipv4_frame()

    proc = None
    try:
        # peer=b0 => forward to b0 AND emit the peer's rx-marker (the seam)
        proc = subprocess.Popen([MARKER, A0, "127.0.0.1", str(sink_port), "nodeA", "filtA", "6", B0],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        ready = False
        pre = []
        deadline = time.time() + 6
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.strip()
            if line.startswith("READY"):
                ready = True
                break
            if line:
                pre.append(line)

        if not ready:
            rest, _ = proc.communicate(timeout=5)
            full = "\n".join(pre + ([rest.strip()] if rest and rest.strip() else []))
            if any(k in full for k in ("EPERM", "Operation not permitted",
                                       "Couldn't load BPF", "memlock")):
                print("SKIP: BPF/XDP load denied (needs real root with CAP_BPF). Re-run via sudo.")
                return 0
            r.check("marker attach (READY)", False, full[:160])
            return 0 if r.summary() else 1

        r.check("marker attach (READY)", True)
        time.sleep(0.3)
        while True:                       # drain pre-inject noise
            try:
                ms.recvfrom(4096)
            except socket.timeout:
                break

        # one IPv4 frame A->B => expect tx (a0) + rx (peer, seam) MARKs
        inj.send(frame)
        dirs = set()
        lines = []
        deadline = time.time() + 2
        while time.time() < deadline and len(lines) < 4:
            try:
                data, _ = ms.recvfrom(4096)
            except socket.timeout:
                break
            s = data.decode(errors="replace")
            lines.append(s)
            for tok in s.split():
                if tok.startswith("dir="):
                    dirs.add(tok[4:])

        r.check("got dir=tx (a0 own ingress marker)", "tx" in dirs, "lines=%d dirs=%s" % (len(lines), sorted(dirs)))
        r.check("got dir=rx (peer marker via the seam)", "rx" in dirs, "dirs=%s" % sorted(dirs))

        rest, _ = proc.communicate(timeout=10)
        full = "\n".join(pre + ([rest.strip()] if rest and rest.strip() else []))
        emitted = None
        for line in full.splitlines():
            if line.startswith("EMITTED="):
                emitted = int(line.split("=", 1)[1])
        r.check("EMITTED == 2 (tx + rx for one frame)", emitted == 2, "emitted=%s" % emitted)
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        ms.close()
        inj.close()
        _links_teardown()

    return 0 if r.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
