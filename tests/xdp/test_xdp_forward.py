"""Phase 2 increment B: prove XDP forwarding via DEVMAP egress redirect.

Two veth pairs stand in for a two-node link. The forwarder attaches the XDP
program to a0 and points its DEVMAP at b0 (the peer "TAP"); injecting on a1
(for a0's RX) must arrive on b1 (b0's egress), proving packets cross A->B
entirely in the kernel XDP path — no userspace relay, no network stack traversal
(doc/xdp-tap-mode.md constraint #6: egress bpf_redirect_map, no BPF_F_INGRESS).

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
FWD = os.path.join(REPO, "src", "xdp", "xdp_fwd")

A0, A1 = "ubxfwd0", "ubxfwd1"     # a0 = XDP attach point ; a1 = inject here
B0, B1 = "ubxfwd2", "ubxfwd3"     # b0 = redirect target  ; b1 = receive here
ETH_P_ALL = 0x0003


def _frame():
    """60-byte Ethernet+IPv4 frame (padded to min Ethernet so the byte-for-byte
    comparison survives L2 padding on the veth path)."""
    eth = b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55" + struct.pack("!H", 0x0800)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20, 0x1234, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    return (eth + ip).ljust(60, b"\x00")


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


def main():
    r = Results()

    if not os.path.exists(FWD):
        print("SKIP: %s not built (run `make xdp`)." % FWD)
        return 0
    if not _links_ready():
        print("SKIP: needs root (veth + AF_PACKET + XDP attach); re-run via sudo "
              "or `unshare -Urn` to exercise XDP forwarding.")
        return 0

    inj = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)); inj.bind((A1, 0))
    rcv = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)); rcv.bind((B1, 0))
    rcv.settimeout(0.5)
    frame = _frame()
    N = 5

    proc = None
    try:
        proc = subprocess.Popen([FWD, A0, B0, "6"],
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
            r.check("forwarder attach (READY)", False, full[:160])
            return 0 if r.summary() else 1

        r.check("forwarder attach (READY)", True)
        time.sleep(0.3)
        # drain any residual noise before injecting
        while True:
            try:
                rcv.recvfrom(4096)
            except socket.timeout:
                break
        for _ in range(N):
            inj.send(frame)

        # receive the forwarded frames on the far side of the peer (b1)
        got = 0
        for _ in range(N):
            try:
                data, _ = rcv.recvfrom(4096)
                if data == frame:
                    got += 1
            except socket.timeout:
                break
        r.check("frames forwarded A->B over XDP (got %d)" % N, got == N, "got=%d" % got)

        rest, _ = proc.communicate(timeout=10)
        full = "\n".join(pre + ([rest.strip()] if rest and rest.strip() else []))
        delta = None
        for line in full.splitlines():
            if line.startswith("DELTA="):
                delta = int(line.split("=", 1)[1])
        r.check("XDP program ran on forwarded packets (>= %d)" % N,
                delta is not None and delta >= N, "delta=%s" % delta)
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        inj.close()
        rcv.close()
        _links_teardown()

    return 0 if r.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
