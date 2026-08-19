
## The Heart of the Project

The core philosophy of `procwhy` is **ergonomics over exhaustiveness**.

It is a *diagnostic snapshot*, not a continuous monitor. Tools like `htop` are for watching a system breathe; `procwhy` is for interrogating a specific suspect. If a user has to read a manual or pass five flags to get their answer, the tool has failed. It must deliver a human-readable, beautifully formatted verdict in under 500 milliseconds, taking the mental load of interpreting `lsof`, `ps`, and `/proc` off the developer's shoulders.

## Milestone 1: The OS Baseline (v0.1.0)

This phase proves the concept using safe, cross-platform Rust crates like `sysinfo`. The goal is to build the skeleton and get the layout looking beautiful on both Linux and macOS.

* Parse the PID cleanly with friendly error handling if the process doesn't exist.
* Display CPU percentage, memory usage, thread count, and the exact command used to launch it.
* Map the process tree to show immediate children and print a truncated list of interesting environment variables.

## Milestone 2: The I/O Layer (v0.2.0)

This is where the tool becomes genuinely useful. We need to track the physical footprint of the process.

* Implement the Linux backend by parsing the `/proc/[pid]/fd` and `/proc/[pid]/net` files.
* Implement the macOS fallback by shelling out to `lsof -p [pid]` and parsing the `stdout`.
* Format the output to clearly distinguish between local files, UNIX sockets, and external network connections.

## Milestone 3: The "Why" Engine (v1.0.0) ✓ COMPLETED

This milestone introduced the killer feature: the heuristics engine.

* Built the rule engine to flag anomalies: memory > 20%/50% of RAM, CPU > 90%, disk I/O > 20 MB/s.
* Detects D-STATE hangs, zombie processes, deleted file descriptor leaks.
* Flags suspicious network behavior: wildcard `0.0.0.0` listeners, > 10 external TCP connections.
* Detects privileged ports (< 1024), high file descriptor counts (≥ 100).
* Packaged for distribution via `cargo install` and GitHub Releases.
* Structured `--json` output for automation pipelines.
* Automatic credential masking for environment variables.
