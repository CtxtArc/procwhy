# procwhy

A lightweight diagnostic process inspector for Linux and macOS.

`procwhy` combines process telemetry, socket state, open file descriptors, and rule-based diagnostics into a single formatted snapshot in under 500 milliseconds.

```text
$ procwhy 545719

PID 545719  firefox

VERDICT
  WARN: [DELETED FILES] 5 open file handles point to deleted files (e.g. /home/user/.cache/app.log (deleted)). Disk space remains held until closed.
    Hint: Restart the process to release deleted file handles and free disk space.
  WARN: [HIGH CHILD COUNT] Process (PID 545719) has spawned 127 child processes.
    Hint: Ensure child processes are reaped to avoid process table exhaustion.
  INFO: [HIGH FD COUNT] Process has 115 open file descriptors and sockets.

STATS
  CPU        0.0%
  Memory     1236.3 MB (5.3% of 23.0 GB)
  Disk I/O   0 B/s
  Status     Sleep
  Wait Chan  poll_schedule_timeout.constprop.0

ENVIRONMENT (Top 5)
  PATH=/usr/local/bin:/usr/bin:...
  ...and 45 more

CHILDREN (Top 5)
  └─ Socket Thread 545741
  └─ Compositor 545794
  └─ Renderer 545780
  └─ TaskController 545763
  └─ IPC I/O Parent 545738
  ...and 122 more

NETWORK
  → TCP 192.168.1.83:53736 -> 34.107.243.93:443 (ESTABLISHED)
  → TCP [2a0d:3341:...]:43816 -> [2606:4700:...]:443 (ESTABLISHED)
  → UDP [::]:43319

UNIX SOCKETS (Top 5)
  → /run/user/1000/wayland-proxy-545719
  → [unnamed SEQPACKET socket (inode 1004626)]
  → [unnamed SEQPACKET socket (inode 1056766)]
  ...and 42 more

FILES (Top 5)
  /dev/dri/renderD128
  /dev/null
  /dev/tty1
  ...and 57 more
```

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

### Via Cargo
```bash
cargo install procwhy
```

### Via Homebrew
```bash
brew tap CtxtArc/procwhy
brew install procwhy
```

### Pre-built Binaries
Pre-built binaries for Linux (x86_64, aarch64) and macOS (x86_64, Apple Silicon arm64) are available on [GitHub Releases](https://github.com/CtxtArc/procwhy/releases).

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


