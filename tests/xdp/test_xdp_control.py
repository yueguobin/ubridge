"""Phase 2 increment E: control-plane translation — verbs -> map updates.

The driver runs the full forward+marker+filter dataplane live (marker ON, one
DROP/BOTH/enabled filter, forwarding to the peer) and reads ubridge-style control
verbs from stdin, translating each into a BPF map update. We drive it over a pipe
and, after each verb, inject an IPv4 frame on a1 and observe TWO outputs:
  - the marker sink (UDP)  -> did a MARK fire?  (marker_ctrl gate)
  - the far end b1         -> was it forwarded? (filter_ctrl action/enabled/direction)

So every assertion is a *live* behavior flip caused by a control verb landing as a
map update — the XDP equivalent of the userspace flag flips the marker/filter
modules do today. No new eBPF; E is pure userspace control translation.

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
CONTROL = os.path.join(REPO, "src", "xdp", "xdp_control")

A0, A1 = "ubxctl0", "ubxctl1"     # a0 = XDP attach + sender ; a1 = inject here
B0, B1 = "ubxctl2", "ubxctl3"     # b0 = redirect target     ; b1 = receive here
ETH_P_ALL = 0x0003
OBSERVE_S = 0.5                    # window to confirm presence/absence at each output


def _ipv4_frame():
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


def _free_udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def main():
    r = Results()

    if not os.path.exists(CONTROL):
        print("SKIP: %s not built (run `make xdp`)." % CONTROL)
        return 0
    if not _links_ready():
        print("SKIP: needs root (veth + AF_PACKET + XDP attach); re-run via sudo "
              "or `unshare -Urn` to exercise control-plane translation.")
        return 0

    sink_port = _free_udp()
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sink.settimeout(0.15); sink.bind(("127.0.0.1", sink_port))
    inj = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)); inj.bind((A1, 0))
    rcv = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)); rcv.bind((B1, 0)); rcv.settimeout(0.15)
    frame = _ipv4_frame()

    def drain():
        for s in (sink, rcv):
            while True:
                try:
                    s.recvfrom(4096)
                except socket.timeout:
                    break

    def send_verb(verb):
        """Write a verb to the driver's stdin and wait for its OK/ERR ack (so the
        map update is applied before we inject). Returns the ack line."""
        proc.stdin.write(verb + "\n")
        proc.stdin.flush()
        deadline = time.time() + 3
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                return None
            line = line.strip()
            if line.startswith("OK") or line.startswith("ERR"):
                return line
        return None

    def observe(label, want_mark, want_fwd):
        """Inject the IPv4 frame, then check the marker sink and the forwarding
        peer against expectations (each is a live result of the current maps)."""
        drain()
        for _ in range(3):
            inj.send(frame)

        mark_seen = False
        end = time.time() + OBSERVE_S
        while time.time() < end:
            try:
                data, _ = sink.recvfrom(4096)
            except socket.timeout:
                continue
            if b"MARK" in data:
                mark_seen = True
                break

        fwd_seen = False
        end = time.time() + OBSERVE_S
        while time.time() < end:
            try:
                data, _ = rcv.recvfrom(4096)
            except socket.timeout:
                continue
            if data == frame:
                fwd_seen = True
                break

        r.check(label + " (marker)", mark_seen == want_mark,
                "mark=%s want_mark=%s" % (mark_seen, want_mark))
        r.check(label + " (forward)", fwd_seen == want_fwd,
                "fwd=%s want_fwd=%s" % (fwd_seen, want_fwd))

    proc = None
    try:
        proc = subprocess.Popen([CONTROL, A0, B0, "127.0.0.1", str(sink_port), "nodeE", "f0", "30"],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)
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
            rest = proc.communicate(timeout=5)[0]
            full = "\n".join(pre + ([rest.strip()] if rest and rest.strip() else []))
            if any(k in full for k in ("EPERM", "Operation not permitted", "Couldn't load BPF", "memlock")):
                print("SKIP: BPF/XDP load denied (needs real root with CAP_BPF). Re-run via sudo.")
                return 0
            r.check("control attach (READY)", False, full[:160])
            return 0 if r.summary() else 1
        r.check("control attach (READY)", True)

        # initial state: marker ON, filter f0 = DROP / BOTH / enabled.
        observe("baseline DROP + marker on",          want_mark=True,  want_fwd=False)
        ack = send_verb("marker pause");               r.check("marker pause acked", ack and ack.startswith("OK"), str(ack))
        observe("marker pause: no MARK, still dropped", want_mark=False, want_fwd=False)
        ack = send_verb("marker resume");              r.check("marker resume acked", ack and ack.startswith("OK"), str(ack))
        observe("marker resume: MARK back, dropped",   want_mark=True,  want_fwd=False)
        ack = send_verb("enable_packet_filter f0 off"); r.check("filter off acked", ack and ack.startswith("OK"), str(ack))
        observe("filter off: forwarded, MARK on",      want_mark=True,  want_fwd=True)
        ack = send_verb("enable_packet_filter f0 on");  r.check("filter on acked", ack and ack.startswith("OK"), str(ack))
        observe("filter on: dropped again",            want_mark=True,  want_fwd=False)
        ack = send_verb("filter f0 direction rx");      r.check("direction rx acked", ack and ack.startswith("OK"), str(ack))
        observe("direction rx: forwarded (sending side skips)", want_mark=True, want_fwd=True)
        ack = send_verb("filter f0 direction both");    r.check("direction both acked", ack and ack.startswith("OK"), str(ack))
        observe("direction both: dropped again",       want_mark=True,  want_fwd=False)
        ack = send_verb("filter f0 action pass");       r.check("action pass acked", ack and ack.startswith("OK"), str(ack))
        observe("action pass: forwarded",              want_mark=True,  want_fwd=True)
        ack = send_verb("filter f0 action drop");       r.check("action drop acked", ack and ack.startswith("OK"), str(ack))
        observe("action drop: dropped again",          want_mark=True,  want_fwd=False)

        proc.stdin.close()
        proc.wait(timeout=5)
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        for s in (sink, inj, rcv):
            s.close()
        _links_teardown()

    return 0 if r.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
