"""Phase 2 increment F: cBPF->eBPF — a real tcpdump/libpcap expression drives the match.

The driver runs the full forward+marker+filter dataplane with a *real* cBPF
expression (compiled by pcap_compile, interpreted in eBPF) as the shared match
predicate for BOTH the marker (observation) and the filter (action). We drive it
over a pipe and inject two IPv4/UDP frames that differ only in dest port:

  UDP/53   — matches `udp port 53`
  UDP/9999 — does NOT match `udp port 53`, but DOES match `ip`

So with expr=`udp port 53`, a :53 frame hits the marker + (DROP) is not forwarded,
while a :9999 frame is neither marked nor dropped (it forwards). Then we send
`expr ip` as a runtime MAP UPDATE (no XDP reload) and the same :9999 frame now
matches. That is the whole point of approach (A): change-BPF is a map update.

Needs root (veth + AF_PACKET + XDP attach + BPF load). Skips cleanly in a user
namespace; a verifier rejection under real root surfaces as a READY failure.
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
EXPR = os.path.join(REPO, "src", "xdp", "xdp_expr")

A0, A1 = "ubxexp0", "ubxexp1"     # a0 = XDP attach + sender ; a1 = inject here
B0, B1 = "ubxexp2", "ubxexp3"     # b0 = redirect target     ; b1 = receive here
ETH_P_ALL = 0x0003
OBSERVE_S = 0.5                    # window to confirm presence/absence at each output


def _udp_frame(dport):
    eth = b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55" + struct.pack("!H", 0x0800)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + 8, 0x1234, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))   # proto 17 = UDP
    udp = struct.pack("!HHHH", 1234, dport, 8, 0)                  # sport, dport, ulen, csum
    return (eth + ip + udp).ljust(60, b"\x00")


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

    if not os.path.exists(EXPR):
        print("SKIP: %s not built (run `make xdp`)." % EXPR)
        return 0
    if not _links_ready():
        print("SKIP: needs root (veth + AF_PACKET + XDP attach); re-run via sudo "
              "or `unshare -Urn` to exercise the cBPF dataplane.")
        return 0

    sink_port = _free_udp()
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sink.settimeout(0.15); sink.bind(("127.0.0.1", sink_port))
    inj = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)); inj.bind((A1, 0))
    rcv = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)); rcv.bind((B1, 0)); rcv.settimeout(0.15)
    f53   = _udp_frame(53)
    f9999 = _udp_frame(9999)

    def drain():
        for s in (sink, rcv):
            while True:
                try:
                    s.recvfrom(4096)
                except socket.timeout:
                    break

    def send_verb(verb):
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

    def observe(label, frame, want_mark, want_fwd):
        """Inject `frame`, then check the marker sink and the forwarding peer."""
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
        # init expr "ip": every IPv4 frame matches; filter f0 = DROP / BOTH / on.
        proc = subprocess.Popen([EXPR, A0, B0, "127.0.0.1", str(sink_port), "nodeF", "f0", "ip", "30"],
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
            # A verifier rejection of the cBPF interpreter surfaces here.
            r.check("expr attach (READY)", False, full[:200])
            return 0 if r.summary() else 1
        r.check("expr attach (READY)", True)

        # 1. baseline: expr "ip" matches every IPv4 frame -> marker + DROP (no forward).
        observe("baseline ip DROP on :9999", f9999, want_mark=True,  want_fwd=False)

        # 2. narrow the expression to udp port 53 (runtime map update, no reload).
        ack = send_verb("expr udp port 53"); r.check("expr udp port 53 acked", ack and ack.startswith("OK"), str(ack))
        observe("udp/53 matches :53",        f53,   want_mark=True,  want_fwd=False)
        observe("udp/53 misses :9999",       f9999, want_mark=False, want_fwd=True)

        # 3. change the expression at runtime to ip -> :9999 now matches.
        ack = send_verb("expr ip");          r.check("expr ip acked", ack and ack.startswith("OK"), str(ack))
        observe("runtime change: ip matches :9999", f9999, want_mark=True, want_fwd=False)

        # 4. a syntax error must ERR and leave the last good expression running.
        ack = send_verb("expr host 1.2.3.4 and");  # trailing 'and' is a syntax error
        r.check("bad expr returns ERR", ack and ack.startswith("ERR"), str(ack))
        observe("after bad expr, last good still runs", f53, want_mark=True, want_fwd=False)

        # 5. flip the filter to PASS -> matched frames now forward (marker still fires).
        ack = send_verb("filter f0 action pass"); r.check("action pass acked", ack and ack.startswith("OK"), str(ack))
        observe("action pass forwards :53", f53, want_mark=True, want_fwd=True)

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
