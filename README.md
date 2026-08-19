# procwhy

**A lightweight diagnostic process inspector for Linux and macOS.**

<p align="center">
  <img src="https://img.shields.io/badge/Version-v1.0.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/Status-Production_Ready-success" alt="Status">
  <img src="https://img.shields.io/badge/Tests-19_passing-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/License-MIT_OR_Apache_2.0-blue" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux_%7C_macOS-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/Language-Rust-orange" alt="Language">
</p>

`procwhy` combines process telemetry, socket state, open file descriptors, and rule-based diagnostics into a single formatted snapshot in under 500 milliseconds.

<p align="center">
  <img src="assets/demo.svg" alt="procwhy terminal demo" width="100%">
</p>

## Features

- **Process Targeting**: Inspect by PID (`1234`), port (`:8080`, `-p 3000`), or process name (`firefox`, `node`).
- **Telemetry Snapshot**: CPU usage delta over a 200ms sampling window, resident memory, disk I/O throughput rate, and kernel wait channels (`wchan`).
- **Automated Diagnostics**:
  - Memory consumption thresholds (>20% and >50% system RAM)
  - Disk throughput and thrashing (>20 MB/s)
  - Uninterruptible Sleep (D-state) kernel hang detection
  - Wildcard network interface binding (`0.0.0.0`, `[::]`, `*`)
  - Outbound connection spikes (>10 active external TCP connections)
  - Defunct / zombie state detection
  - Deleted open file leaks (unlinked files holding disk space)
  - CPU pegging (>90%)
  - Privileged port identification (<1024)
  - File descriptor and child process count checks
- **Credential Masking**: Automatically masks API keys, bearer tokens, database passwords, and secrets in environment variables.
- **Deep I/O Inspection**:
  - Linux: Direct `/proc/[pid]/fd` and `/proc/[pid]/net/{tcp,udp,unix}` parsing with network namespace support.
  - macOS: Native `lsof` integration.
- **Pager Support**: Integrates with `$PAGER` (defaults to `less -FRX`) for long outputs, with `-a` / `--all` and `--no-pager` options.

## Installation

### Build from Source

```bash
# Clone the repository
git clone https://github.com/CtxtArc/procwhy.git
cd procwhy

# Install the binary locally
cargo install --path .
```

Or build the release binary:
```bash
cargo build --release
# Binary available at target/release/procwhy
```


## Usage

```bash
# Inspect by PID
procwhy 1234

# Inspect by port
procwhy :8080
procwhy --port 3000

# Inspect by process name
procwhy node
procwhy firefox

# Show all items without truncation
procwhy -a 1234
procwhy --all node

# Disable pager
procwhy --no-pager 1234
```

## License

MIT OR Apache-2.0
