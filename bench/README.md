# bench/ — native data-plane benchmark for the `mark` filter

The Python perf suite (`tests/marker/test_marker_perf.py`) is a **regression
guard** — it checks the mark filter doesn't collapse throughput at a paced,
deterministic rate. It is *not* a ceiling measurement, because Python tops out
near ~130k pps (three threads fighting over the GIL) — that's the **harness**
limit, not ubridge's. To find ubridge's real ceiling you need a native sender.

This directory is that native sender.

## Layout

| File | Role |
|------|------|
| `marker_bench.c` | Pure data-plane: `sendmmsg` a paced/full-speed stream into ubridge, `recvmmsg`-drain the relay + signal receivers concurrently, report per-window rates + loss. |
| `run_bench.py` | Control plane: spawn ubridge, configure sink + bridge + `mark` filter, hand the 5 UDP ports to the C tool, tear down. Reuses the test helpers (`common.Ubridge`). |

The split is deliberate — Python does what it's good at (control, port
management), C does the one thing Python can't (high pps).

## Build & run

```bash
make bench                                       # cc -O2 ... -o bench/marker_bench
python3 bench/run_bench.py                       # default: sweep {50k..1M,full}, 2s windows
python3 bench/run_bench.py 200000 2              # single rate: 200k pps, 2s
python3 bench/run_bench.py 0 3                   # full speed, 3s
```

## Reading the output

```
rate      sent      relayed (pps)        signals (pps)        rel%   sig/rel%
50k       100032    100032 ( 50016)      100032 ( 50016)      100.0  100.0
200k      400000    391056 (195528)      391056 (195528)       97.8  100.0
500k      999936    412359 (206180)      412359 (206180)       41.2  100.0
```

- **`rel%`** = relayed/sent. <100% means ubridge's relay thread can't drain its
  NIO input buffer fast enough → kernel drops on input. The knee is the ceiling.
- **`sig/rel%`** = signals/relayed. **This is the mark-filter integrity number.**
  It stayed **100.0%** through saturation in every measurement — `marker_emit`
  (per-packet UDP sendto under a mutex) never drops a signal, even when 60% of
  packets are being dropped at the input.

## Measured ceiling (2s windows, single bridge, 34-byte frames, mark `ip`)

- **~200k pps lossless** — relay AND signal stay ~100% up to ~200k pps input.
- **~209k pps hard saturation** — relayed rate caps there regardless of input;
  above it the relay thread is the bottleneck and drops on input.
- **signal/relay = 100% everywhere** — the mark filter adds zero signal loss
  right up to and past saturation.

So the perf suite's ~2k pps pace is ~1% of capacity — a deliberately stable
regression check, not a performance claim.
