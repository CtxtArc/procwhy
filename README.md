<p align="center">
  <img src="assets/icon.svg" width="96" height="96" alt="procwhy logo">
</p>

# procwhy

**Turn raw OS telemetry into actionable process diagnoses.**

<p align="center">
  <img src="https://img.shields.io/badge/Release-v1.0.0-blue" alt="Release">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen" alt="Status">
  <img src="https://img.shields.io/badge/Tests-19_passing-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/License-MIT-blue" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux_%7C_macOS-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/Language-Rust-orange" alt="Language">
</p>

During an incident, raw metrics don't answer **why**:
- `CPU = 98%` doesn't tell you if the process is stuck in a spinlock or saturated with worker tasks.
- `Disk 100% full` doesn't tell you that a process is holding 4 GB of disk space hostage through deleted file handles.
- `kill -9` doing nothing doesn't explain that the process is stuck in uninterruptible kernel sleep (D-state) on a dead NFS mount.
- `netstat` dumps don't warn you that a dev service accidentally bound to `0.0.0.0` with 17 active external connections.

`procwhy` interrogates `/proc`, socket tables, and open file descriptors, evaluates heuristic diagnostic rules, and produces an actionable conclusion in **<500ms**.

<p align="center">
  <img src="assets/demo.svg" alt="procwhy terminal demo" width="100%">
</p>

## Diagnoses

Instead of dumping raw tables for you to piece together, `procwhy` analyzes the process state and surfaces actionable diagnostic findings:

- **Deleted File Leaks**: Detects unlinked files still held open by descriptors that prevent the filesystem from freeing disk space.
- **Uninterruptible D-State Hangs**: Reveals kernel wait channels (`wchan`) when a process is stuck waiting on storage I/O and cannot be killed.
- **Public Wildcard Binds**: Flags services listening on `0.0.0.0` or `[::]` with active external connections.
- **OOM Intervention Risk**: Calculates memory percentage against system RAM and warns before the Linux OOM-killer terminates the process.
- **Zombie / Defunct Processes**: Identifies terminated child processes whose parent has failed to call `waitpid()` to reap them.
- **Disk Thrashing**: Measures real-time read/write delta throughput and catches runaway logging or swap activity (>20 MB/s).
- **Lock Contention & CPU Pegging**: Distinguishes between futex lock waits and sustained busy loops.
- **Credential Masking**: Automatically masks API keys, bearer tokens, database passwords, and secrets in environment variables.

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

# Output structured JSON for automation or jq
procwhy --json :8080
procwhy --json 1234 | jq '.verdict'

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
  "pid": 545719,
  "name": "firefox",
  "status": "Sleep",
  "verdict": [
    {
      "severity": "warning",
      "category": "DELETED FILES",
      "message": "Process holds 5 open file handle(s) to unlinked/deleted files. Disk space remains allocated on the filesystem until closed.",
      "recommendation": "Restart or signal the process to release deleted file handles and reclaim disk space."
    }
  ],
  "stats": {
    "cpu_usage_percent": 0.0,
    "memory_mb": 1236.3,
    "memory_percent_system": 5.3,
    "disk_io_rate": { "read_bytes_per_sec": 0.0, "write_bytes_per_sec": 0.0 },
    "wchan": "poll_schedule_timeout.constprop.0"
  }
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


