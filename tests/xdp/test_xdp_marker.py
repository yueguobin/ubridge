"""Phase 2 increment C1: ingress tx-marker -> ringbuf -> MARK line -> sink.

Attaches the XDP program with the marker enabled, injects an IPv4 frame on the
veth peer, and asserts a MARK datagram arrives at the UDP sink with the contract
fields (node/filter/len/dir=tx) — same format the userspace marker module emits.
Then injects a non-IPv4 frame and asserts NO marker fires, proving the
placeholder match is selective (real cBPF->eBPF expressions land in increment F).

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

A0, A1 = "ubxm0", "ubxm1"     # a0 = XDP attach (ingress marker) ; a1 = inject
ETH_P_ALL = 0x0003


def _frame(proto):
    """34-byte Ethernet frame with the given ethertype (0x0800=IPv4 to match)."""
    eth = b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55" + struct.pack("!H", proto)
    return eth + b"\x45\x00" + b"\x00\x14" + b"\x00" * 16   # filler to reach 34


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def _links_ready():
    if os.geteuid() != 0:
        return False
    _run(["ip", "link", "del", A0])
    if _run(["ip", "link", "add", A0, "type", "veth", "peer", "name", A1]).returncode != 0:
        return False
    for ifc in (A0, A1):
        _run(["ip", "link", "set", ifc, "addrgenmode", "none"])
        _run(["ip", "link", "set", ifc, "up"])
    return True


def _links_teardown():
    _run(["ip", "link", "del", A0])


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
              "or `unshare -Urn` to exercise the XDP marker.")
        return 0

    sink_port = _free_udp()
    ms = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); ms.settimeout(0.5); ms.bind(("127.0.0.1", sink_port))
    inj = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)); inj.bind((A1, 0))

    ip_frame = _frame(0x0800)
    nonip_frame = _frame(0x1234)

    proc = None
    try:
        proc = subprocess.Popen([MARKER, A0, "127.0.0.1", str(sink_port), "testnode", "mfilt", "6"],
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
        while True:                       # drain any pre-inject noise from ms
            try:
                ms.recvfrom(4096)
            except socket.timeout:
                break

        # 1. IPv4 frame -> one MARK line with the contract fields
        inj.send(ip_frame)
        sig = None
        try:
            data, _ = ms.recvfrom(4096)
            sig = data.decode(errors="replace").strip()
        except socket.timeout:
            pass
        r.check("MARK signal on XDP path", sig is not None and sig.startswith("MARK "),
                sig if sig else "timeout")
        if sig:
            r.check("MARK fields + dir=tx",
                    all(x in sig for x in ("node=testnode", "filter=mfilt", "len=%d" % len(ip_frame), "dir=tx")),
                    sig)
            r.check("link/tag default to '-'",
                    "link=-" in sig and "tag=-" in sig, sig)

        # 2. non-IPv4 frame -> no MARK (placeholder match is selective)
        inj.send(nonip_frame)
        time.sleep(0.3)
        got = 0
        while True:
            try:
                ms.recvfrom(4096); got += 1
            except socket.timeout:
                break
        r.check("no MARK on non-IPv4 (selective)", got == 0, "extra=%d" % got)

        rest, _ = proc.communicate(timeout=10)
        full = "\n".join(pre + ([rest.strip()] if rest and rest.strip() else []))
        emitted = None
        for line in full.splitlines():
            if line.startswith("EMITTED="):
                emitted = int(line.split("=", 1)[1])
        r.check("EMITTED == 1 (one IPv4 match)", emitted == 1, "emitted=%s" % emitted)
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
