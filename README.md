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
    Observation:    Process holds 5 open descriptor(s) to unlinked/deleted files on disk.
    Evidence:       Deleted file count: 5 | Sample: /tmp/cache.db (deleted)
    Interpretation: Filesystem space remains allocated and cannot be reclaimed until those descriptors close.
    Recommendation: Restart or signal the process to release deleted file handles and free disk space.

  WARN: [CPU PEGGING]    [LIKELY]
    Observation:    97.8% CPU utilization over the sampling window.
    Evidence:       CPU: 97.8% | Scheduler state: Running | wchan: - | Sample duration: 200ms
    Interpretation: Likely CPU-bound execution (busy-loop or unthrottled computation).
    Recommendation: Capture a stack profile (perf/pstack) to identify the hot code path.
```

## Supported Diagnostic Rules

- **Deleted File Leaks `[CONFIRMED]`**: Detects unlinked files still held open by descriptors that prevent the filesystem from freeing disk blocks.
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

Cold startup: 84.6ms
Warm (p50):   13.3ms
Warm (p95):   16.0ms

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
      "observation": "Process holds 1 open descriptor(s) to unlinked/deleted files on disk (e.g. /tmp/cache.db (deleted)).",
      "evidence": ["Deleted file count: 1", "Sample unlinked path: /tmp/cache.db (deleted)"],
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
