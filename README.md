<p align="center">
  <img src="assets/icon.svg" width="96" height="96" alt="procwhy logo">
</p>

# procwhy

**What is wrong with this process right now?**

<p align="center">
  <img src="https://img.shields.io/badge/Release-v1.0.0-blue" alt="Release">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen" alt="Status">
  <img src="https://img.shields.io/badge/Tests-29_passing-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/License-MIT-blue" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux_%7C_macOS-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/Language-Rust-orange" alt="Language">
</p>

`procwhy` is an opinionated process diagnostic CLI that turns low-level process telemetry, open descriptors, socket state, and kernel wait channels into clear, structured findings.

Instead of dumping tables of raw numbers and leaving you to connect the dots during an incident, `procwhy` evaluates diagnostic rules with explicit **confidence levels**, distinguishing between hard OS facts and inferences.

<p align="center">
  <img src="assets/demo.svg" alt="procwhy terminal demo" width="100%">
</p>

## The Diagnostic Engine

Trust is the product. `procwhy` explicitly separates hard OS facts from diagnostic inferences:

- **`[CONFIRMED]`**: Verifiable OS state (e.g. unlinked file descriptors holding disk space, zombie status, D-state hang).
- **`[LIKELY]`**: Strong telemetry inferences (e.g. sustained CPU busy loop over sampling window, memory pressure approaching OOM killer limits).
- **`[POSSIBLE]`**: Potential operational risks (e.g. listener bound to wildcard `0.0.0.0`, high child process count).

```text
DIAGNOSTICS
  WARN: [DELETED FILES]  [CONFIRMED]
    Observed:    Process holds 5 open file handle(s) to unlinked/deleted files on disk.
    Inference:   Disk space will not be freed by the filesystem until descriptors close.
    Action:      Restart or signal the process to release deleted file handles and free disk space.

  WARN: [CPU PEGGING]  [LIKELY]
    Observed:    Process is consuming 96.8% CPU over the sampling window.
    Inference:   Sustained CPU-bound execution (busy loop or compute-heavy task).
    Action:      Profile active threads with perf/pstack before terminating.
```

### Deep Explanations (`--explain`)

Run with `--explain` (`-e`) for detailed kernel mechanics, evidence metrics, and investigation steps:

```bash
procwhy --explain 4812
```

## Supported Diagnostic Rules

- **Deleted File Leaks `[CONFIRMED]`**: Detects unlinked files still held open by descriptors that prevent the filesystem from freeing disk blocks.
- **Uninterruptible D-State Hangs `[CONFIRMED]`**: Identifies kernel wait channels (`wchan`) when a process is blocked in storage I/O and cannot be killed by signals.
- **Zombie / Defunct Processes `[CONFIRMED]`**: Identifies terminated child processes whose parent has not called `waitpid()` to reap them.
- **CPU Pegging `[LIKELY]`**: Differentiates between sustained CPU-bound execution (>90% CPU) and idle lock waits.
- **OOM Killer Risk `[LIKELY]`**: Calculates RSS consumption against host RAM and warns before the Linux OOM-killer intervenes.
- **Disk Thrashing `[LIKELY]`**: Computes real-time I/O delta throughput (>20 MB/s) to catch runaway logging or swap activity.
- **Public Wildcard Binds `[POSSIBLE]`**: Flags services listening on `0.0.0.0` or `[::]` exposed to external networks.
- **Connection Spikes `[POSSIBLE]`**: Monitors active external TCP connections and connection pool exhaustion.
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

# Deep explanation mode with evidence and kernel mechanics
procwhy --explain 1234
procwhy -e :8080

# Output structured JSON for automation or jq
procwhy --json :8080
procwhy --json 1234 | jq '.diagnostics'

# Show all items without truncation
procwhy -a 1234
procwhy --all node

# Disable automatic pager
procwhy --no-pager 1234
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
      "severity": "warning",
      "confidence": "confirmed",
      "category": "DELETED FILES",
      "observed": "Process holds 1 open file handle(s) to unlinked/deleted files (/tmp/cache.db (deleted)).",
      "inference": "Disk space will not be freed by the filesystem until descriptors close.",
      "recommendation": "Restart or signal the process to release deleted file handles and free disk space.",
      "evidence": ["Open deleted file count: 1", "Sample path: /tmp/cache.db (deleted)"]
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
