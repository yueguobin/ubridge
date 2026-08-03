# TAP + XDP/eBPF dataplane mode

A second dataplane for ubridge, alongside the UDP-tunnel userspace relay. The
north star: **nodes attach via real TAP interfaces and forwarding happens in
XDP/eBPF maps — never through the Linux kernel network stack.** ubridge
recedes from "userspace relay that copies every packet" to "control + observation
plane" while the kernel XDP program does the forwarding.

This document is the contract: what already exists, what must not change, the
resolved XDP topology model, and the Phase 1 / Phase 2 deliverables.

---

## Goal

```
node-A.write(tapA) → tapA ingress XDP ─bpf_redirect_map─▶ tapB egress → node-B.read(tapB)
                       (match/forward/marker, all in one kernel pass)
```

The packet crosses from one node's TAP to the other entirely inside the kernel
XDP/softirq path. It does **not** traverse `netif_receive_skb → netfilter →
routing → TCP/IP → socket`. Zero userspace wakeups on the forwarding path; zero
copies. marker / filter / capture are observed *along* that path, not by pulling
the packet into userspace.

---

## What already exists (do not rebuild)

| Capability | Where |
|------------|-------|
| `bridge add_nio_linux_raw <bridge> <ifname>` — AF_PACKET (`ETH_P_ALL`, promisc) attach | `src/nio_linux_raw.c`, `src/hypervisor_bridge.c` |
| NIO-agnostic relay loop + packet-filter engine (cBPF) | `src/packet_filter.c`, bridge relay |
| `mark` filter + `marker` module (`sink`/`node`/`pause`/`resume`/`status`, per-filter `enable_packet_filter`) | `src/hypervisor_marker.c` |
| capture (pcap) | `src/hypervisor_capture.c` |
| Persistent TAP lifecycle: `tap create` / `set_owner` / `delete` | `src/hypervisor_tap.c` |

Because the filter loop runs on **every relayed packet regardless of NIO type**,
marker / filter / capture already behave identically on a `linux_raw` NIO as on
a `nio_udp` NIO. Phase 1 is mostly verification, not new code.

---

## Hard constraints (non-negotiable)

1. **TAP = generic (skb-mode) XDP only.** A TAP has no driver RX hook, so native
   XDP cannot attach. Do not spend effort on native mode.
2. **Filter/marker expressions reuse tcpdump / libpcap cBPF → eBPF.** No new DSL.
   gns3server, the webui, and users already speak this format.
3. **Control-plane contract is unchanged.** gns3server's existing
   enable/disable, pause/resume, direction, marker-definitions, REST and MCP
   APIs all keep working. ubridge only swaps the *implementation* (userspace
   flag flip → BPF map update). gns3server adapts to whatever verb style
   ubridge exposes underneath.
4. **Two datapaths coexist, switch, and fall back.** `udp_tunnel` (the current
   userspace bridge, zero-privilege) stays. `tap + XDP` is tap-mode's other
   dataplane. If XDP cannot attach (unsupported kernel, privilege denied), the
   tap-mode link falls back to the Phase-1 userspace raw relay. **The userspace
   bridge loop is never deleted** — it is the fallback.
5. **fd ownership stays with the node.** The node process (QEMU / VPCS /
   Dynamips) opens and holds its TAP fd. ubridge never opens or steals that fd;
   it raw-attaches and XDP-attaches the *interface by name*.
6. **Forwarding is egress `bpf_redirect_map`.** Redirect to the peer TAP's
   **egress** (so the peer node's `read()` gets the packet). Never use
   `BPF_F_INGRESS` / ingress redirect — that would push the packet up the peer's
   kernel networking stack, violating the goal.

---

## The resolved XDP topology model

**Per-node ubridge = one self-contained XDP / marker / filter / capture unit.**
Each ubridge loads its own XDP program onto its own node's TAP and owns its own
maps. Cross-node forwarding needs **no shared forwarding state**:

- The forwarding map (DEVMAP) holds `self → peer TAP ifindex`.
- `ifindex` is kernel-global (within the netns), so either end resolves the
  peer by name via `if_nametoindex()`. It does not matter which process owns
  the peer TAP.
- gns3server coordinates both ends (it already talks to both endpoints'
  computes to allocate UDP lport/rport today; populating each end's DEVMAP with
  the peer's ifindex is the same coordination shape).

```
create link A↔B:                       delete link A↔B:
  ubridge-A: DEVMAP[0] = ifindex(B.tap)   ubridge-A: detach XDP, drop DEVMAP entry
  ubridge-B: DEVMAP[0] = ifindex(A.tap)   ubridge-B: detach XDP, drop DEVMAP entry
```

Rollback is required: if one end attaches and the other fails, gns3server must
tear the successful end down (a real distributed-state concern, gns3server's to
orchestrate).

### The marker-coverage seam — why there is *one* shared map

This is the one place "fully self-contained, no shared map" does not hold, and
it is deliberate.

**XDP runs on ingress only.** An egress redirect to the peer TAP delivers the
packet to the peer node's fd but does **not** re-run the peer TAP's XDP program.
So each TAP's XDP only sees packets the *local* node writes:

- `tapA` XDP sees A→B (A sending).
- `tapB` XDP sees B→A (B sending).

Consequence: a `mark` filter on capture-node **B** sees B's own tx (B→A) in B's
XDP, but **A→B (B's rx) is invisible to B's XDP** — it arrives on B's egress.
That would lose the documented `dir rx` coverage (see `doc/marker.md`).

**Resolution:** the receiver's rx-direction marker runs on the **sender's** XDP,
just before the redirect. The sender looks up the peer's marker program from a
single **shared marker-observation map** (pinned in bpffs, keyed by ifindex:
marker prog + `enabled` / `paused` / `direction` bits) and runs it on the
sending CPU in XDP context (DEVMAP-entry program, or `bpf_tail_call` into the
marker prog). On match → `bpf_perf_event_output`; the owning ubridge drains its
ring and emits the MARK line.

Only the *observation* map is shared (read-mostly, per-ifindex lookup table).
The forwarding DEVMAPs stay per-node and self-contained. This keeps per-node
architecture intact while preserving bidirectional marker coverage.

> Alternative considered and rejected: accept the rx-coverage gap (each side
> only sees its own tx). Rejected because `dir rx` is a documented, used
> feature; silently losing it is a regression users would notice.

---

## Phase 1 — full-TAP attach (thin: verification + small glue)

Goal: a node joins via a real TAP interface; ubridge raw-attaches the same
interface; filter / marker / capture behave exactly as on `nio_udp`. No eBPF.

| # | Work | Kind |
|---|------|------|
| 1 | Verify marker / filter / capture parity on a `linux_raw` NIO vs `nio_udp` (expected: free, given the NIO-agnostic filter loop). | verify |
| 2 | `tests/marker/test_raw_marker.py` — veth pair standing in for a node TAP; ubridge `add_nio_linux_raw` on one end, inject on the peer. Assert signal + fields, passive relay, `marker sink off`, per-filter enable/disable, `marker pause`/`resume`, pcap, `dir`. Root-gated skip otherwise. | **the one real deliverable** |
| 3 | Document the fd-ownership boundary: ubridge does **not** open the tap fd; it raw-attaches by interface name only (already true — no code). | doc |
| 4 | `CAP_NET_ADMIN` / `CAP_NET_RAW` become the常态 in tap mode (create TAP, raw-attach). Add a startup capability probe + advisory log. | small, optional |
| 5 | Acceptance: in tap mode, gns3server issues `bridge add_nio_linux_raw <br> <tap>`; marker enable/disable/pause/resume/filter/capture match UDP mode. | acceptance |

Phase 1 does not touch eBPF and can ship and be accepted independently.

---

## Phase 2 — XDP/eBPF forwarding + marker/filter elevation

**A. Build + libbpf integration**
- Link libbpf (system lib or vendored); compile eBPF objects with clang
  (`*.bpf.c → *.o`); generate skeletons with `bpftool gen skeleton`. New
  Makefile targets. Encapsulate load/attach/map-mgmt in a new `src/xdp_*` module.

**B. XDP attach + map lifecycle (per link, per-node)**
- Attach **generic/skb-mode** XDP to the node TAP.
- **DEVMAP** (forwarding, per-node self-contained): `self → peer ifindex`.
- **Shared marker-observation map** (bpffs-pinned, keyed by ifindex): marker
  prog + control bits (`enabled` / `paused` / `direction`).
- **filter map** + **control map** (global `enabled` / `paused`).
- Lifecycle follows the link: create link → attach + populate maps; delete link
  → detach + clear maps. Coordinated across both ends by gns3server, with
  rollback on partial failure.

**C. XDP eBPF pipeline (one kernel pass per packet)**
- **Forward:** DEVMAP lookup → `bpf_redirect_map(devmap, peer, 0)` (egress).
- **Peer rx-marker before redirect:** look up the peer's marker prog in the
  shared observation map and run it on the sending CPU (DEVMAP-entry program or
  `bpf_tail_call`); on match → `bpf_perf_event_output` + counter.
- **Own tx-marker:** runs in the local ingress XDP as usual.
- **filter:** `XDP_DROP` / `XDP_PASS`.
- **control bits:** `paused` suppresses marker events; `enabled` gates a single
  marker.
- **Expressions:** tcpdump/libpcap → cBPF → trans to eBPF (or direct eBPF
  rewrite). No new DSL.

**D. Userspace observation sinks (the part ubridge keeps in user-space)**
- perf-ring / ringbuf consumer: marker events → format the **MARK line** →
  `sendto` the sink. **Signal format unchanged.**
- capture-sink consumer: redirected packets → pcap. **Capture format unchanged.**

**E. Control-plane translation**
- enable/disable, pause/resume, change-BPF, direction → translated to **map
  updates** (control bits / marker prog / direction).
- Verb style is ubridge's choice: new `xdp marker set …`, or reuse
  `enable_packet_filter` / `marker pause` names with a new implementation.
  gns3server adapts underneath; the REST/MCP contract to clients is unchanged.

**F. Coexistence / switch / fallback**
- `udp_tunnel` (Phase-1 userspace bridge) always available — zero-privilege
  fallback.
- tap + XDP is tap-mode's dataplane; on XDP attach failure / unsupported
  kernel, fall back to the Phase-1 userspace raw relay.
- Mode detection + selection at link setup.

---

## Build & dependencies

- **Phase 1:** none new (existing C build).
- **Phase 2 (XDP/eBPF):** `clang` (with the bpf target), `libbpf` (dev),
  `bpftool`, `libelf` (dev), `zlib` (dev).

Verify the toolchain before building (`scripts/check-xdp-deps.sh` probes each,
looks in `/usr/sbin` too, and prints the install line for the detected distro
on any miss):

```
make check-xdp          # OK: clang=… libbpf=… bpftool=…
```

Or install directly:

| Distro | Command |
|--------|---------|
| openSUSE | `sudo zypper install clang libbpf-devel bpftool libelf-devel zlib-devel` |
| Debian/Ubuntu | `sudo apt install clang libbpf-dev bpftool libelf-dev zlib1g-dev` |
| Fedora/RHEL | `sudo dnf install clang libbpf-devel bpftool elfutils-libelf-devel zlib-devel` |
| Arch | `sudo pacman -S clang libbpf bpftool libelf zlib` |

Then:

```
make xdp                # eBPF object + libbpf skeleton + src/xdp/xdp_smoke
```

Runtime: loading/attaching XDP needs real `CAP_BPF`/`CAP_NET_ADMIN` — a user
namespace is denied it (and `kernel.unprivileged_bpf_disabled=2` is locked on
many distros). ubridge runs privileged in tap+XDP mode regardless (constraint
#3). The foundation test lives in `tests/xdp/`.

## Testing

- **Phase 1:** `tests/marker/test_raw_marker.py` (this branch) — raw-NIO marker
  parity.
- **Phase 2:** extend `tests/marker/` for the XDP path (forwarding + bidirectional
  marker + map control bits); add a `bench/` comparison of **UDP relay vs XDP
  forwarding** — XDP should exceed the current ~200k pps userspace ceiling
  (`bench/README.md`) by one to two orders of magnitude.
