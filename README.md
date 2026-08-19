<p align="center">
  <img src="assets/icon.svg" width="96" height="96" alt="procwhy logo">
</p>

# procwhy

**Turn raw OS telemetry into actionable process diagnoses.**

<p align="center">
  <img src="https://img.shields.io/badge/Release-v1.0.0-blue" alt="Release">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen" alt="Status">
  <img src="https://img.shields.io/badge/Tests-29_passing-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/Latency-13ms_warm-brightgreen" alt="Latency">
  <img src="https://img.shields.io/badge/License-MIT-blue" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux_%7C_macOS-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/Language-Rust-orange" alt="Language">
</p>

`procwhy` is an opinionated process diagnostic CLI designed for incident response. It interrogates `/proc`, socket tables, and open file descriptors, evaluates heuristic diagnostic rules, and produces an actionable conclusion in **<500ms**.

Instead of dumping tables of raw counters and leaving you to connect the dots during an incident, `procwhy` evaluates diagnostic rules with explicit **confidence levels**, grounding every inference directly in evidence.

<p align="center">
  <img src="assets/demo.svg" alt="procwhy terminal demo" width="100%">
</p>

## Real-World Examples

### 1. Disk space isn't freed after deleting log files
> **Incident**: `df -h` reports `100% full`, but `du -sh *` doesn't show where the space went. You unlinked old log files, but the disk was never released.

```bash
$ procwhy myapp

WARN: [DELETED FILES]  [CONFIRMED]
  Observation:     1 deleted file descriptor held open (8.7 GB allocated on disk).
  Evidence:        1 deleted file descriptor | Sample path: /var/log/myapp.log (deleted)
  Interpretation:  The file was unlinked but remains allocated on disk because the process still holds an open descriptor.
  Recommendation:  Restart or reload the process to release the descriptor and free disk space.
```

### 2. Process won't terminate even with `kill -9`
> **Incident**: A worker process hangs indefinitely and ignores `SIGKILL` (`kill -9`).

```bash
$ procwhy worker

CRITICAL: [D-STATE HANG]  [CONFIRMED]
  Observation:     Process is in Uninterruptible Sleep (D-state) on kernel wait channel 'nfs_wait_client'.
  Evidence:        Scheduler state: TASK_UNINTERRUPTIBLE (D) | Kernel wait channel (wchan): nfs_wait_client
  Interpretation:  Process is blocked inside a kernel driver or storage I/O operation. POSIX signals (including SIGKILL) are deferred until the kernel I/O unblocks.
  Recommendation:  Inspect storage subsystem, hung NFS mounts, or kernel dmesg logs for storage/driver timeouts.
```

### 3. "What is using port 8080?"
> **Incident**: A deployment fails with `EADDRINUSE: address already in use :::8080`.

```bash
$ procwhy :8080

PORT :8080 ─> node (PID 4812)  node /srv/api/server.js
────────────────────────────────────────────────────────────

WARN: [PUBLIC LISTENER]  [POSSIBLE]
  Observation:     Process is bound to wildcard interface: TCP 0.0.0.0:8080 (LISTEN)
  Evidence:        Listener: TCP 0.0.0.0:8080 | Active external connections: 17
  Interpretation:  Socket accepts incoming traffic from all network interfaces if unfirewalled.
  Recommendation:  Verify whether public exposure is intended or bind to 127.0.0.1 for internal services.
```

---

## The Diagnostic Engine

Trust is the entire product. `procwhy` grounds every finding in a strict 4-part architecture:

1. **Observation**: Something directly measured from the OS.
2. **Evidence**: Concrete supporting metrics and telemetry triggers.
3. **Interpretation**: What the evidence probably indicates.
4. **Recommendation**: Practical next steps for the operator.

Findings are tagged with explicit confidence ratings:
- **`[CONFIRMED]`**: Verifiable OS state (e.g. unlinked file descriptors holding disk space, zombie status, D-state hang).
- **`[LIKELY]`**: Strong telemetry inferences (e.g. sustained CPU-bound execution over the sampling window, memory pressure approaching OOM limits).
- **`[POSSIBLE]`**: Potential operational risks (e.g. listener bound to wildcard `0.0.0.0`, high child worker count).

```text
DIAGNOSTICS
  WARN: [DELETED FILES]  [CONFIRMED]
    Observation:    5 deleted file descriptor(s) held open (4.2 GB allocated on disk).
    Evidence:       5 deleted file descriptors | Total disk space held: 4.2 GB | Largest: /var/log/app.log (4.2 GB)
    Interpretation: Filesystem space remains allocated and cannot be reclaimed until those descriptors close.
    Recommendation: Restart or signal the process to release deleted file handles and free disk space.

  WARN: [CPU PEGGING]    [LIKELY]
    Observation:    97.8% CPU utilization over the sampling window.
    Evidence:       CPU: 97.8% | Scheduler state: Running | wchan: - | Sample duration: 200ms
    Interpretation: Likely CPU-bound execution (busy-loop or unthrottled computation).
    Recommendation: Capture a stack profile (perf/pstack) to identify the hot code path.
```

## Supported Diagnostic Rules

- **Deleted File Leaks `[CONFIRMED]`**: Detects unlinked files still held open by descriptors, measuring exact bytes allocated on disk that cannot be freed.
- **Uninterruptible D-State Hangs `[CONFIRMED]`**: Identifies kernel wait channels (`wchan`) when a process is blocked in storage I/O and cannot receive signals (including `kill -9`).
- **Zombie / Defunct Processes `[CONFIRMED]`**: Identifies terminated child processes whose parent has not called `waitpid()` to reap them.
- **CPU Pegging `[LIKELY]`**: Differentiates between sustained CPU-bound execution (>90% CPU) and idle lock waits.
- **OOM Killer Risk `[LIKELY]`**: Calculates RSS consumption against host RAM and warns before the Linux OOM-killer intervenes.
- **Disk Thrashing `[LIKELY]`**: Computes real-time I/O delta throughput (>20 MB/s) to catch runaway logging or swap activity.
- **Public Wildcard Binds `[POSSIBLE]`**: Flags services listening on `0.0.0.0` or `[::]` exposed to external networks.
- **Connection Spikes `[POSSIBLE]`**: Monitors active external TCP connections and connection pool exhaustion.
- **Privileged Ports `[CONFIRMED]`**: Flags processes bound to reserved system ports (<1024).
- **Credential Masking**: Automatically masks API tokens, bearer keys, and database passwords in environment variables.

## Usage

```bash
# Inspect by PID
procwhy 1234

# Inspect the process listening on a port
procwhy :8080
procwhy --port 3000

# Inspect by process name
procwhy node
procwhy firefox

# Run latency benchmark
procwhy --benchmark

# Output structured JSON for automation or jq
procwhy --json :8080
procwhy --json 1234 | jq '.diagnostics'

# Show all items without truncation
procwhy -a 1234
procwhy --all node

# Disable automatic pager
procwhy --no-pager 1234
```

### Incident Benchmark

`procwhy` is built to be fast enough to use interactively during active incidents:

```bash
$ procwhy --benchmark
Running procwhy latency benchmark...

Cold startup: 63.6ms
Warm (p50):   14.2ms
Warm (p95):   20.9ms

Verdict: Well within the <500ms incident latency budget.
```

### JSON Automation

Use `--json` to integrate `procwhy` into monitoring agents, alerting pipelines, or incident automation:

```json
{
  "procwhy_version": "1.0.0",
  "pid": 4812,
  "name": "node",
  "health": "warning",
  "summary": "Process is consuming unusually high CPU and holding open file handles to deleted files.",
  "identity": {
    "binary": "/usr/bin/node",
    "user": "app (UID 1000)",
    "cwd": "/srv/api",
    "uptime_seconds": 13320,
    "uptime_human": "3h 42m"
  },
  "diagnostics": [
    {
      "category": "DELETED FILES",
      "severity": "warning",
      "confidence": "confirmed",
      "observation": "5 deleted file descriptor(s) held open (4.2 GB allocated on disk).",
      "evidence": [
        "5 deleted file descriptors",
        "Total disk space held: 4.2 GB",
        "Largest deleted file: /var/log/app.log (4.2 GB)"
      ],
      "interpretation": "Filesystem space remains allocated and cannot be reclaimed until those descriptors close.",
      "recommendation": "Restart or signal the process to release deleted file handles and free disk space."
    }
  ]
}
```

## Installation

### Build from Source

```bash
# Clone the repository
git clone https://github.com/CtxtArc/procwhy.git
cd procwhy

# Install the binary locally
cargo install --path .
```

Or build the release binary directly:
```bash
cargo build --release
# Binary available at target/release/procwhy
```

## License

[MIT](LICENSE)
