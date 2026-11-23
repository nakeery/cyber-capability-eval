# Baseline container fit: measurements (D-089, build-time check)

Working record, untracked. It holds measured values only; D-090 gets written from this once the C run is in, so the decision entry is one entry with every variant's numbers. Measured with `drafts/baseline_fit_lab.py` (a seeded baseline lab held open by hand), reading the container's own cgroup v2 counters at the end of the run.

Limits under test (docker-compose.yml, inherited unchanged by the baseline override): memory 256 MiB (268,435,456 bytes, tmpfs included), 0.5 CPU (`cpu.max` 50000 100000), 128 PIDs, `/home/agent` tmpfs 32 MiB.

## Reference: the lab with nothing run in it

Dry run of the helper (preflight only, no sqlmap), variant B: memory peak 20,504,576 bytes (19.6 MiB), memory events all 0, PIDs peak 8, CPU 0.35 s used, 5 of 11 periods throttled.

## Variant B, sqlmap stage run by the author

Per the author, the run completed and wrote a dump.

| Counter | Value | Against the limit |
|---|---|---|
| `memory.peak` | 41,164,800 bytes (39.3 MiB) | 15.3% of 256 MiB |
| `memory.current` at the end | 9,154,560 bytes (8.7 MiB) | |
| `memory.events` max / oom / oom_kill | 0 / 0 / 0 | never touched the ceiling |
| `pids.peak` | 8 | of 128 |
| attacker `State.OOMKilled`, exit code | False, 0 | |
| `/home/agent` tmpfs used | 16 KiB | of 32,768 KiB |
| CPU used (`usage_usec`) | 1,089,392 us (1.09 s; user 0.98 s, system 0.11 s) | |
| CPU periods / throttled periods | 32 / 17 | window about 3.2 s at 100 ms periods |
| Time throttled (`throttled_usec`) | 790,698 us (0.79 s) | CPU-bound at the 0.5 share for the run |
| Target log lines | 119 | far under the 50 MiB flood limit (D-074) |

Two earlier B runs, before the helper read cgroup counters: one reported OOMKilled False, 16 KiB home, 303 target log lines; the other gave a `docker stats` snapshot taken after the run (3.5 MiB, 0% CPU, 2 PIDs), which is an idle reading and not a peak.

## Variant C (parameterized), sqlmap stage run by the author

Per the author, the stage took about 11 s and found nothing to exploit.

| Counter | Value | Against the limit |
|---|---|---|
| `memory.peak` | 41,861,120 bytes (39.9 MiB) | 15.6% of 256 MiB |
| `memory.current` at the end | 8,859,648 bytes (8.4 MiB) | |
| `memory.events` max / oom / oom_kill | 0 / 0 / 0 | never touched the ceiling |
| `pids.peak` | 8 | of 128 |
| `/home/agent` tmpfs used | 12 KiB | of 32,768 KiB |
| CPU used (`usage_usec`) | 1,219,512 us (1.22 s; user 1.09 s, system 0.13 s) | |
| CPU periods / throttled periods | 122 / 19 | window about 12.2 s, matching the author's 11 s |
| Time throttled (`throttled_usec`) | 818,167 us (0.82 s) | |
| Target log lines | 178 | far under the 50 MiB flood limit (D-074) |

(The paste's last line read "left over: nothin", which looks clipped; teardown was checked separately.)

## What the comparison is for

- B is the run that finishes quickly; C is expected to run longest (nothing to find), so C is the likely high-water mark for CPU time, wall-clock and request count. The limits only need a deviation if C, or a heavier run, shows memory events, an OOM kill, a tmpfs near full, or throttling that threatens the 15-minute cap.
- A and D have not been measured; they share B's shape (D adds only a read-only volume the baseline never touches).
