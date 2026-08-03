"""Phase 2 increment D: the XDP filter action layer (DROP/PASS) + control bits.

Two veth pairs stand in for a two-node link. The driver attaches XDP to a0,
forwards to b0 (DEVMAP egress redirect) and installs one filter (action +
direction + enabled) via filter_ctrl. Injecting on a1 (a0's RX) we observe at
b1 (b0's egress) whether the frame arrived. The filter's match is the IPv4
placeholder (ethertype 0x0800) until real cBPF->eBPF in increment F.

Scenarios:
  1. PASS, IPv4      -> forwarded (action path does not drop).
  2. DROP, IPv4      -> dropped   (the action; nothing at b1).
  3. DROP, non-IP    -> forwarded (match is IPv4 only; non-match passes).
  4. DROP disabled   -> forwarded (enabled control bit bypasses the filter).
  5. DROP direction=rx -> forwarded (a0 is the sending/TX side; an rx-direction
                          filter does not apply here — see xdp_events.h).

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
FILTER = os.path.join(REPO, "src", "xdp", "xdp_filter")

A0, A1 = "ubxflt0", "ubxflt1"     # a0 = XDP attach + sender ; a1 = inject here
B0, B1 = "ubxflt2", "ubxflt3"     # b0 = redirect target     ; b1 = receive here
ETH_P_ALL = 0x0003


def _ipv4_frame():
    """60-byte Ethernet+IPv4 frame: matches the filter's IPv4 placeholder."""
    eth = b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55" + struct.pack("!H", 0x0800)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20, 0x1234, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    return (eth + ip).ljust(60, b"\x00")


def _nonip_frame():
    """60-byte Ethernet frame with a non-IP ethertype (0x1234): never matches the
    IPv4 placeholder, so a DROP filter must let it through."""
    eth = b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55" + struct.pack("!H", 0x1234)
    return eth.ljust(60, b"\x00")


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

    if not os.path.exists(FILTER):
        print("SKIP: %s not built (run `make xdp`)." % FILTER)
        return 0
    if not _links_ready():
        print("SKIP: needs root (veth + AF_PACKET + XDP attach); re-run via sudo "
              "or `unshare -Urn` to exercise the XDP filter.")
        return 0

    inj = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)); inj.bind((A1, 0))
    rcv = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)); rcv.bind((B1, 0))
    rcv.settimeout(0.5)   # default for the drain loops; the count loop sets its own

    def run(action, direction, enabled, frame, expect, label):
        """Attach+forward+filter via the driver, inject `frame` on a1, check b1.
        expect=True  -> frame should be forwarded;
        expect=False -> the DROP filter should stop it (nothing at b1).
        Returns 'skip' on BPF EPERM (only the first caller acts on it)."""
        proc = subprocess.Popen([FILTER, A0, B0, action, direction, str(int(enabled)), "2"],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
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
                    return "skip"
                r.check(label + " (attach)", False, full[:160])
                return "ok"

            time.sleep(0.3)
            while True:                       # drain pre-inject noise on b1
                try:
                    rcv.recvfrom(4096)
                except socket.timeout:
                    break

            for _ in range(3):
                inj.send(frame)

            got = 0
            end = time.time() + 1.0
            rcv.settimeout(0.3)
            while time.time() < end:
                try:
                    data, _ = rcv.recvfrom(4096)
                except socket.timeout:
                    continue
                if data == frame:
                    got += 1
                    if expect:
                        break            # arrived — no need to wait further

            if expect:
                r.check(label, got >= 1, "got=%d (expected >=1)" % got)
            else:
                r.check(label, got == 0, "got=%d (expected 0 — dropped)" % got)
        finally:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        return "ok"

    ipv4 = _ipv4_frame()
    nonip = _nonip_frame()
    scenarios = [
        ("pass", "both", 1, ipv4,  True,  "PASS forwards matching IPv4"),
        ("drop", "both", 1, ipv4,  False, "DROP drops matching IPv4 (nothing at b1)"),
        ("drop", "both", 1, nonip, True,  "DROP passes non-matching (non-IP) frame"),
        ("drop", "both", 0, ipv4,  True,  "disabled filter bypassed (IPv4 forwarded)"),
        ("drop", "rx",   1, ipv4,  True,  "direction=rx skips on the sending XDP (forwarded)"),
    ]

    try:
        for action, direction, enabled, frame, expect, label in scenarios:
            if run(action, direction, enabled, frame, expect, label) == "skip":
                return 0
    finally:
        inj.close()
        rcv.close()
        _links_teardown()

    return 0 if r.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
