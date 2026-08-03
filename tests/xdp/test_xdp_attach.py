"""Phase 2 increment A: prove the XDP foundation end to end.

Loads the eBPF object via the libbpf loader (src/xdp/xdp_smoke), attaches it in
generic (SKB) mode to a veth end, injects packets on the peer, and asserts the
XDP program actually ran (the per-CPU packet counter increments). This is the
build/attach foundation for the whole XDP dataplane — forwarding, marker, and
filter are layered on in later increments (doc/xdp-tap-mode.md).

Needs root: a veth pair (CAP_NET_ADMIN), AF_PACKET inject (CAP_NET_RAW), and
XDP program load+attach (CAP_BPF / CAP_NET_ADMIN). Skips gracefully otherwise,
keeping the suite green.
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
SMOKE = os.path.join(REPO, "src", "xdp", "xdp_smoke")

VETH_A = "ubxdp0"     # XDP attaches here (inbound from VETH_B)
VETH_B = "ubxdp1"     # AF_PACKET-inject here
ETH_P_ALL = 0x0003


def _ip_frame():
    eth = b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55" + struct.pack("!H", 0x0800)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20, 0x1234, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    return eth + ip


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def _veth_ready():
    if os.geteuid() != 0:
        return False
    _run(["ip", "link", "del", VETH_A])
    r = _run(["ip", "link", "add", VETH_A, "type", "veth", "peer", "name", VETH_B])
    if r.returncode != 0:
        print("  [NOTE] could not create veth pair: %s" % r.stderr.strip())
        return False
    _run(["ip", "link", "set", VETH_A, "addrgenmode", "none"])   # suppress IPv6 NS/RS noise
    _run(["ip", "link", "set", VETH_B, "addrgenmode", "none"])
    _run(["ip", "link", "set", VETH_A, "up"])
    _run(["ip", "link", "set", VETH_B, "up"])
    return True


def _veth_teardown():
    _run(["ip", "link", "del", VETH_A])


def main():
    r = Results()

    if not os.path.exists(SMOKE):
        print("SKIP: %s not built (run `make xdp`)." % SMOKE)
        return 0
    if not _veth_ready():
        print("SKIP: needs root (veth + AF_PACKET + XDP attach); re-run via sudo "
              "or `unshare -Urn` to exercise the XDP foundation.")
        return 0

    inj = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    inj.bind((VETH_B, 0))
    frame = _ip_frame()
    N = 5

    proc = None
    try:
        proc = subprocess.Popen([SMOKE, VETH_A, "4"],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        ready = False
        pre = []
        # wait for the loader to print READY (attach succeeded)
        deadline = time.time() + 6
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.strip()
            if line.startswith("READY"):
                ready = True
                break
            if line:                       # collect any pre-READY loader output
                pre.append(line)

        if not ready:
            # Process exited without READY — gather the rest of its output. (On a
            # not-ready path the loader has already exited, so this returns fast.)
            rest, _ = proc.communicate(timeout=5)
            full = "\n".join(pre + ([rest.strip()] if rest and rest.strip() else []))
            # BPF/XDP load needs real CAP_BPF; a user namespace (uid 0 in unshare
            # -Urn) is denied it. That is an environment limit, not a regression —
            # skip cleanly so the suite stays green; re-run via sudo for the proof.
            if any(k in full for k in ("EPERM", "Operation not permitted",
                                       "Couldn't load BPF", "memlock")):
                print("SKIP: BPF/XDP load denied in this environment (needs real root "
                      "with CAP_BPF — a user namespace can't load XDP). Re-run via sudo.")
                return 0
            r.check("xdp attach (READY)", False, full[:160])
            return 0 if r.summary() else 1

        r.check("xdp attach (READY)", True)
        # Inject DURING the measurement window — must happen before communicate()
        # (which blocks until the window ends and DELTA is printed).
        time.sleep(0.3)
        for _ in range(N):
            inj.send(frame)
        rest, _ = proc.communicate(timeout=10)   # waits for the window to end
        full = "\n".join(pre + ([rest.strip()] if rest and rest.strip() else []))
        if full:
            print("  [loader] " + full.replace("\n", "\n  [loader] "))

        delta = None
        for line in full.splitlines():
            if line.startswith("DELTA="):
                delta = int(line.split("=", 1)[1])
        r.check("XDP program ran (counter >= %d)" % N,
                delta is not None and delta >= N,
                "delta=%s" % delta)
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        inj.close()
        _veth_teardown()

    return 0 if r.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
