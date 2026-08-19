use crate::io::{DiskIoRate, ProcessIo};
use serde::Serialize;
use sysinfo::ProcessStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Possible,
    Likely,
    Confirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Health {
    Ok,
    Info,
    Warning,
    Critical,
}

impl Health {
    pub fn from_findings(findings: &[Finding]) -> Self {
        if findings.iter().any(|f| f.severity == Severity::Critical) {
            Health::Critical
        } else if findings.iter().any(|f| f.severity == Severity::Warning) {
            Health::Warning
        } else if findings.iter().any(|f| f.severity == Severity::Info) {
            Health::Info
        } else {
            Health::Ok
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub category: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub observation: String,
    pub evidence: Vec<String>,
    pub interpretation: String,
    pub recommendation: String,
}

pub fn generate_summary(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "Operating within normal resource thresholds and operating baseline.".to_string();
    }

    let mut highlights = Vec::new();
    for f in findings {
        match f.category {
            "D-STATE HANG" => highlights.push("stuck in uninterruptible kernel sleep (D-state)"),
            "OOM KILLER RISK" => highlights.push("consuming critical memory (high OOM risk)"),
            "HIGH RAM" => highlights.push("consuming significant system RAM"),
            "CPU PEGGING" => highlights.push("consuming unusually high CPU"),
            "HIGH DISK I/O" => highlights.push("generating heavy disk throughput"),
            "DELETED FILES" => highlights.push("holding open file handles to deleted files"),
            "PUBLIC LISTENER" => highlights.push("publicly exposed on a wildcard interface"),
            "HIGH TCP CONNS" => highlights.push("holding a high number of external connections"),
            "HIGH FD COUNT" => highlights.push("maintaining a large number of open file descriptors"),
            "ZOMBIE PROCESS" => highlights.push("defunct and awaiting reaping by parent"),
            "HIGH CHILD COUNT" => highlights.push("spawning an unusually high number of children"),
            "PRIVILEGED PORT" => highlights.push("bound to a privileged system port (<1024)"),
            _ => highlights.push(f.category),
        }
    }

    highlights.dedup();
    if highlights.len() == 1 {
        format!("Process is {}.", highlights[0])
    } else if highlights.len() == 2 {
        format!("Process is {} and {}.", highlights[0], highlights[1])
    } else {
        format!(
            "Process is {}, {}, and {}.",
            highlights[0],
            highlights[1],
            highlights[2]
        )
    }
}

pub struct ProcessSnapshot<'a> {
    pub pid: u32,
    pub name: &'a str,
    pub cmd: &'a [String],
    pub cpu_usage: f32,
    pub memory_bytes: u64,
    pub total_system_memory_bytes: u64,
    pub status: ProcessStatus,
    pub parent_pid: Option<u32>,
    pub children_count: usize,
    pub io: &'a ProcessIo,
    pub disk_io_rate: Option<DiskIoRate>,
    pub wchan: Option<&'a str>,
}

pub fn analyze_snapshot(snapshot: &ProcessSnapshot) -> Vec<Finding> {
    let mut findings = Vec::new();

    check_zombie_state(snapshot, &mut findings);
    check_wchan_and_state(snapshot, &mut findings);
    check_memory_usage(snapshot, &mut findings);
    check_cpu_usage(snapshot, &mut findings);
    check_disk_io_rate(snapshot, &mut findings);
    check_wildcard_binds(snapshot, &mut findings);
    check_external_tcp_connections(snapshot, &mut findings);
    check_deleted_open_files(snapshot, &mut findings);
    check_privileged_ports(snapshot, &mut findings);
    check_high_fd_count(snapshot, &mut findings);
    check_child_processes(snapshot, &mut findings);

    findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    findings
}

fn check_wchan_and_state(snapshot: &ProcessSnapshot, findings: &mut Vec<Finding>) {
    let status_str = format!("{:?}", snapshot.status);
    let is_d_state = status_str.contains("Uninterruptible") || status_str.eq_ignore_ascii_case("D");

    if is_d_state {
        let wchan_info = snapshot.wchan.unwrap_or("disk/driver I/O");
        findings.push(Finding {
            category: "D-STATE HANG",
            severity: Severity::Critical,
            confidence: Confidence::Confirmed,
            observation: format!(
                "Process is in Uninterruptible Sleep (D-state) on kernel wait channel '{}'.",
                wchan_info
            ),
            evidence: vec![
                "Scheduler state: TASK_UNINTERRUPTIBLE (D)".to_string(),
                format!("Kernel wait channel (wchan): {}", wchan_info),
            ],
            interpretation: "Process is blocked in a kernel driver or storage I/O operation. POSIX signals (including SIGKILL / kill -9) are ignored until the kernel I/O request unblocks.".to_string(),
            recommendation: "Inspect storage subsystem, hung NFS mounts, or kernel dmesg logs for storage/driver timeouts.".to_string(),
        });
    } else if let Some(wchan) = snapshot.wchan {
        if wchan.contains("futex") && snapshot.cpu_usage == 0.0 {
            findings.push(Finding {
                category: "LOCK CONTENTION",
                severity: Severity::Info,
                confidence: Confidence::Likely,
                observation: format!("Threads are sleeping in kernel wait channel '{}' with 0.0% CPU.", wchan),
                evidence: vec![
                    format!("Kernel wait channel: {}", wchan),
                    "CPU utilization: 0.0%".to_string(),
                    format!("Scheduler state: {:?}", snapshot.status),
                ],
                interpretation: "Likely waiting on a user-space synchronization primitive (e.g. pthread mutex / futex).".to_string(),
                recommendation: "If the process is unresponsive, inspect thread stacks for deadlocks or lock starvation.".to_string(),
            });
        }
    }
}

fn check_disk_io_rate(snapshot: &ProcessSnapshot, findings: &mut Vec<Finding>) {
    if let Some(rate) = snapshot.disk_io_rate {
        let total_bytes_sec = rate.read_bytes_per_sec + rate.write_bytes_per_sec;
        let threshold_mb = 20.0 * 1024.0 * 1024.0; // 20 MB/s

        if total_bytes_sec >= threshold_mb {
            let total_mb_s = total_bytes_sec / (1024.0 * 1024.0);
            let read_mb_s = rate.read_bytes_per_sec / (1024.0 * 1024.0);
            let write_mb_s = rate.write_bytes_per_sec / (1024.0 * 1024.0);

            findings.push(Finding {
                category: "HIGH DISK I/O",
                severity: Severity::Warning,
                confidence: Confidence::Likely,
                observation: format!(
                    "High disk throughput: {:.1} MB/s total ({:.1} MB/s read, {:.1} MB/s write).",
                    total_mb_s, read_mb_s, write_mb_s
                ),
                evidence: vec![
                    format!("Read rate: {:.1} MB/s", read_mb_s),
                    format!("Write rate: {:.1} MB/s", write_mb_s),
                    "Sampling window: 200ms delta".to_string(),
                ],
                interpretation: "Heavy disk read/write bandwidth that may saturate storage queues and degrade system responsiveness.".to_string(),
                recommendation: "Check for unbuffered file logging, large core dumps, or swap thrashing.".to_string(),
            });
        }
    }
}

fn check_child_processes(snapshot: &ProcessSnapshot, findings: &mut Vec<Finding>) {
    if snapshot.children_count >= 50 {
        findings.push(Finding {
            category: "HIGH CHILD COUNT",
            severity: Severity::Warning,
            confidence: Confidence::Likely,
            observation: format!(
                "Process has spawned {} active child processes/workers (PID {}).",
                snapshot.children_count, snapshot.pid
            ),
            evidence: vec![format!("Direct child process count: {}", snapshot.children_count)],
            interpretation: "Elevated worker count that increases context switching overhead and process table consumption.".to_string(),
            recommendation: "Ensure child processes are properly reaped and pooled to avoid process table exhaustion.".to_string(),
        });
    }
}

fn check_zombie_state(snapshot: &ProcessSnapshot, findings: &mut Vec<Finding>) {
    let is_zombie_status = matches!(snapshot.status, ProcessStatus::Zombie | ProcessStatus::Dead);
    let is_defunct_name = snapshot.name.contains("<defunct>");
    let is_defunct_cmd = snapshot.cmd.iter().any(|arg| arg.contains("<defunct>"));

    if is_zombie_status || is_defunct_name || is_defunct_cmd {
        let parent_info = match snapshot.parent_pid {
            Some(ppid) => format!("parent PID {}", ppid),
            None => "unknown parent".to_string(),
        };
        findings.push(Finding {
            category: "ZOMBIE PROCESS",
            severity: Severity::Critical,
            confidence: Confidence::Confirmed,
            observation: format!(
                "Defunct process. It has terminated but {} has not reaped its exit status via waitpid().",
                parent_info
            ),
            evidence: vec![
                format!("Scheduler state: {:?}", snapshot.status),
                format!("Parent: {}", parent_info),
            ],
            interpretation: "The process descriptor remains allocated in the kernel process table until reaped by its parent.".to_string(),
            recommendation: format!("Signal {} or restart the parent to reap terminated child processes.", parent_info),
        });
    }
}

fn check_memory_usage(snapshot: &ProcessSnapshot, findings: &mut Vec<Finding>) {
    if snapshot.total_system_memory_bytes == 0 {
        return;
    }

    let mem_pct =
        (snapshot.memory_bytes as f64 / snapshot.total_system_memory_bytes as f64) * 100.0;
    let mem_mb = snapshot.memory_bytes as f64 / 1024.0 / 1024.0;
    let total_gb = snapshot.total_system_memory_bytes as f64 / 1024.0 / 1024.0 / 1024.0;

    if mem_pct >= 50.0 {
        findings.push(Finding {
            category: "OOM KILLER RISK",
            severity: Severity::Critical,
            confidence: Confidence::Likely,
            observation: format!(
                "Resident memory is {:.1} MB ({:.1}% of {:.1} GB system RAM).",
                mem_mb, mem_pct, total_gb
            ),
            evidence: vec![
                format!("Resident memory (RSS): {:.1} MB", mem_mb),
                format!("Host RAM share: {:.1}%", mem_pct),
                format!("Total host RAM: {:.1} GB", total_gb),
            ],
            interpretation: "High probability of Linux kernel OOM-killer termination under system memory pressure.".to_string(),
            recommendation: "Inspect memory growth profile, heap allocations, or configure container memory limits.".to_string(),
        });
    } else if mem_pct >= 20.0 {
        findings.push(Finding {
            category: "HIGH RAM",
            severity: Severity::Warning,
            confidence: Confidence::Likely,
            observation: format!(
                "Process consumes {:.1} MB ({:.1}% of {:.1} GB system RAM).",
                mem_mb, mem_pct, total_gb
            ),
            evidence: vec![
                format!("Resident memory (RSS): {:.1} MB", mem_mb),
                format!("Host RAM share: {:.1}%", mem_pct),
            ],
            interpretation: "Substantial physical memory footprint relative to total available system RAM.".to_string(),
            recommendation: "Verify memory growth profile or configure cgroup memory limits.".to_string(),
        });
    }
}

fn check_cpu_usage(snapshot: &ProcessSnapshot, findings: &mut Vec<Finding>) {
    if snapshot.cpu_usage >= 90.0 {
        findings.push(Finding {
            category: "CPU PEGGING",
            severity: Severity::Warning,
            confidence: Confidence::Likely,
            observation: format!("{:.1}% CPU utilization over the sampling window.", snapshot.cpu_usage),
            evidence: vec![
                format!("CPU utilization: {:.1}%", snapshot.cpu_usage),
                format!("Scheduler state: {:?}", snapshot.status),
                format!("Kernel wait channel: {}", snapshot.wchan.unwrap_or("-")),
                "Sample duration: 200ms".to_string(),
            ],
            interpretation: "Likely CPU-bound execution (busy-loop or unthrottled computation).".to_string(),
            recommendation: "Capture a stack profile (e.g. perf top / pstack) before terminating to identify the hot code path.".to_string(),
        });
    }
}

fn check_wildcard_binds(snapshot: &ProcessSnapshot, findings: &mut Vec<Finding>) {
    let mut wildcard_listeners = Vec::new();

    for conn in &snapshot.io.network_connections {
        if conn.contains("LISTEN") {
            let is_wildcard = conn.contains("0.0.0.0:")
                || conn.contains("[::]:")
                || conn.contains("*: ")
                || conn.contains("*:*")
                || conn.contains("TCP *:")
                || conn.starts_with("TCP 0.0.0.0:")
                || conn.starts_with("TCP [::]:");

            if is_wildcard {
                wildcard_listeners.push(conn.clone());
            }
        }
    }

    if !wildcard_listeners.is_empty() {
        let count = wildcard_listeners.len();
        let sample = wildcard_listeners[0].clone();
        let desc = if count == 1 {
            format!("Process is bound to wildcard interface: {}", sample)
        } else {
            format!(
                "Process is bound to {} wildcard interfaces ({})",
                count, sample
            )
        };

        findings.push(Finding {
            category: "PUBLIC LISTENER",
            severity: Severity::Warning,
            confidence: Confidence::Possible,
            observation: desc,
            evidence: vec![format!("Listener bind: {}", sample)],
            interpretation: "Socket accepts incoming traffic from all network interfaces on the host if unfirewalled.".to_string(),
            recommendation: "Verify whether the service should bind to all interfaces or 127.0.0.1.".to_string(),
        });
    }
}

fn check_external_tcp_connections(snapshot: &ProcessSnapshot, findings: &mut Vec<Finding>) {
    let mut external_count = 0;

    for conn in &snapshot.io.network_connections {
        if conn.starts_with("TCP") && !conn.contains("LISTEN") {
            let is_local = conn.contains("127.0.0.1")
                || conn.contains("[::1]")
                || conn.contains("localhost");

            if !is_local && (conn.contains("->") || conn.contains("ESTABLISHED")) {
                external_count += 1;
            }
        }
    }

    if external_count > 10 {
        findings.push(Finding {
            category: "HIGH TCP CONNS",
            severity: Severity::Warning,
            confidence: Confidence::Possible,
            observation: format!(
                "Process has {} active external TCP connections (threshold: 10).",
                external_count
            ),
            evidence: vec![format!("External connection count: {}", external_count)],
            interpretation: "Elevated outbound or inbound network traffic, or potential connection pool exhaustion.".to_string(),
            recommendation: "Check connection pool limits, HTTP keep-alive settings, or upstream service latency.".to_string(),
        });
    }
}

fn check_deleted_open_files(snapshot: &ProcessSnapshot, findings: &mut Vec<Finding>) {
    let mut deleted_items = snapshot.io.deleted_files.clone();

    if deleted_items.is_empty() {
        for f in &snapshot.io.open_files {
            if f.ends_with(" (deleted)") || f.contains(" (deleted)") {
                deleted_items.push(crate::io::DeletedFile {
                    path: f.clone(),
                    size_bytes: 0,
                });
            }
        }
    }

    if !deleted_items.is_empty() {
        let count = deleted_items.len();
        let total_bytes: u64 = deleted_items.iter().map(|d| d.size_bytes).sum();
        let largest = deleted_items.iter().max_by_key(|d| d.size_bytes);
        let sample_path = &deleted_items[0].path;

        let obs_text = if total_bytes > 0 {
            format!(
                "{} deleted file descriptor(s) held open ({} allocated on disk).",
                count,
                crate::io::format_bytes(total_bytes)
            )
        } else if count == 1 {
            format!("1 deleted file descriptor held open ({}).", sample_path)
        } else {
            format!(
                "{} deleted file descriptors held open (e.g. {}).",
                count, sample_path
            )
        };

        let mut evidence = vec![format!("{} deleted file descriptors", count)];
        if total_bytes > 0 {
            evidence.push(format!(
                "Total disk space held: {}",
                crate::io::format_bytes(total_bytes)
            ));
        }
        if let Some(l) = largest {
            if l.size_bytes > 0 && count > 1 {
                evidence.push(format!(
                    "Largest deleted file: {} ({})",
                    l.path,
                    crate::io::format_bytes(l.size_bytes)
                ));
            } else if l.size_bytes == 0 {
                evidence.push(format!("Sample unlinked path: {}", sample_path));
            }
        } else {
            evidence.push(format!("Sample unlinked path: {}", sample_path));
        }

        findings.push(Finding {
            category: "DELETED FILES",
            severity: Severity::Warning,
            confidence: Confidence::Confirmed,
            observation: obs_text,
            evidence,
            interpretation: "Filesystem space remains allocated and cannot be reclaimed until those descriptors close.".to_string(),
            recommendation: "Restart or signal the process to release deleted file handles and free disk space.".to_string(),
        });
    }
}


fn check_privileged_ports(snapshot: &ProcessSnapshot, findings: &mut Vec<Finding>) {
    let mut priv_ports = Vec::new();

    for conn in &snapshot.io.network_connections {
        if conn.contains("LISTEN") {
            if let Some(port) = extract_port(conn) {
                if port < 1024 {
                    priv_ports.push((port, conn.clone()));
                }
            }
        }
    }

    if !priv_ports.is_empty() {
        let sample = &priv_ports[0];
        findings.push(Finding {
            category: "PRIVILEGED PORT",
            severity: Severity::Info,
            confidence: Confidence::Confirmed,
            observation: format!("Bound to privileged system port {} ({}).", sample.0, sample.1),
            evidence: vec![format!("Privileged port: {}", sample.0)],
            interpretation: "Required CAP_NET_BIND_SERVICE or superuser capabilities at bind time.".to_string(),
            recommendation: "Ensure least-privilege principles are followed if running as a non-root service.".to_string(),
        });
    }
}

fn check_high_fd_count(snapshot: &ProcessSnapshot, findings: &mut Vec<Finding>) {
    let total_fds = snapshot.io.open_files.len()
        + snapshot.io.unix_sockets.len()
        + snapshot.io.network_connections.len();

    if total_fds >= 100 {
        findings.push(Finding {
            category: "HIGH FD COUNT",
            severity: Severity::Info,
            confidence: Confidence::Confirmed,
            observation: format!(
                "Process has {} open file descriptors and sockets.",
                total_fds
            ),
            evidence: vec![
                format!("Open files: {}", snapshot.io.open_files.len()),
                format!("Sockets: {}", snapshot.io.unix_sockets.len() + snapshot.io.network_connections.len()),
            ],
            interpretation: "Elevated descriptor usage approaching default process ulimit thresholds.".to_string(),
            recommendation: "Check file descriptor limits (ulimit -n) to prevent EMFILE exhaustion.".to_string(),
        });
    }
}

fn extract_port(conn: &str) -> Option<u16> {
    if let Some(pos) = conn.rfind(':') {
        let rest = &conn[pos + 1..];
        let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        num_str.parse::<u16>().ok()
    } else {
        None
    }
}

pub fn redact_env_var(env_str: &str) -> String {
    let sensitive_keys = [
        "KEY", "SECRET", "TOKEN", "PASS", "PASSWORD", "AUTH", "CREDENTIAL", "PRIVATE", "APIKEY",
        "DATABASE_URL", "CERT", "SIGNATURE",
    ];

    if let Some((k, v)) = env_str.split_once('=') {
        // Check for embedded URI credentials: e.g. http://user:pass@host
        if v.contains("://") && v.contains('@') {
            if let Some(at_idx) = v.rfind('@') {
                if let Some(colon_idx) = v[..at_idx].rfind(':') {
                    let proto_end = v.find("://").map(|i| i + 3).unwrap_or(0);
                    if colon_idx > proto_end {
                        return format!("{}={}:***{}", k, &v[..colon_idx], &v[at_idx..]);
                    }
                }
            }
            return format!("{}=*** [REDACTED]", k);
        }

        let upper_k = k.to_uppercase();
        let is_sensitive = sensitive_keys.iter().any(|&s| upper_k.contains(s));

        if is_sensitive {
            if v.len() > 8 && (v.starts_with("sk-") || v.starts_with("ghp_")) {
                let prefix: String = v.chars().take(3).collect();
                return format!("{}={}*** [REDACTED]", k, prefix);
            }

            return format!("{}=*** [REDACTED]", k);
        }
    }

    env_str.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_snapshot<'a>(io: &'a ProcessIo) -> ProcessSnapshot<'a> {
        ProcessSnapshot {
            pid: 1234,
            name: "test_process",
            cmd: &[],
            cpu_usage: 0.0,
            memory_bytes: 1024 * 1024 * 10,
            total_system_memory_bytes: 1024 * 1024 * 1024 * 16,
            status: ProcessStatus::Run,
            parent_pid: Some(1),
            children_count: 0,
            io,
            disk_io_rate: None,
            wchan: None,
        }
    }

    #[test]
    fn test_normal_process_baseline() {
        let io = ProcessIo::default();
        let snapshot = dummy_snapshot(&io);
        let findings = analyze_snapshot(&snapshot);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_memory_exceeding_50_percent() {
        let io = ProcessIo::default();
        let mut snapshot = dummy_snapshot(&io);
        snapshot.total_system_memory_bytes = 1000;
        snapshot.memory_bytes = 600;

        let findings = analyze_snapshot(&snapshot);
        assert!(findings.iter().any(|f| f.category == "OOM KILLER RISK"));
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].confidence, Confidence::Likely);
    }

    #[test]
    fn test_memory_exceeding_20_percent() {
        let io = ProcessIo::default();
        let mut snapshot = dummy_snapshot(&io);
        snapshot.total_system_memory_bytes = 1000;
        snapshot.memory_bytes = 250;

        let findings = analyze_snapshot(&snapshot);
        assert!(findings.iter().any(|f| f.category == "HIGH RAM"));
        assert_eq!(findings[0].severity, Severity::Warning);
        assert_eq!(findings[0].confidence, Confidence::Likely);
    }

    #[test]
    fn test_uninterruptible_d_state() {
        let io = ProcessIo::default();
        let mut snapshot = dummy_snapshot(&io);
        snapshot.status = ProcessStatus::UninterruptibleDiskSleep;
        snapshot.wchan = Some("io_schedule");

        let findings = analyze_snapshot(&snapshot);
        assert!(findings.iter().any(|f| f.category == "D-STATE HANG"));
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].confidence, Confidence::Confirmed);
    }

    #[test]
    fn test_disk_io_rate_heuristic() {
        let io = ProcessIo::default();
        let mut snapshot = dummy_snapshot(&io);
        snapshot.disk_io_rate = Some(DiskIoRate {
            read_bytes_per_sec: 15.0 * 1024.0 * 1024.0,
            write_bytes_per_sec: 10.0 * 1024.0 * 1024.0,
        });

        let findings = analyze_snapshot(&snapshot);
        assert!(findings.iter().any(|f| f.category == "HIGH DISK I/O"));
    }

    #[test]
    fn test_wildcard_listener() {
        let io = ProcessIo {
            open_files: vec![],
            deleted_files: vec![],
            unix_sockets: vec![],
            network_connections: vec![
                "TCP 0.0.0.0:8080 (LISTEN)".to_string(),
                "TCP 127.0.0.1:3000 (LISTEN)".to_string(),
            ],
        };
        let snapshot = dummy_snapshot(&io);
        let findings = analyze_snapshot(&snapshot);

        assert!(findings.iter().any(|f| f.category == "PUBLIC LISTENER"));
        assert_eq!(findings[0].confidence, Confidence::Possible);
    }

    #[test]
    fn test_more_than_10_external_tcp_connections() {
        let mut conns = Vec::new();
        for i in 1..=12 {
            conns.push(format!(
                "TCP 192.168.1.50:{} -> 93.184.216.{}:443 (ESTABLISHED)",
                50000 + i,
                i
            ));
        }
        let io = ProcessIo {
            open_files: vec![],
            deleted_files: vec![],
            unix_sockets: vec![],
            network_connections: conns,
        };
        let snapshot = dummy_snapshot(&io);
        let findings = analyze_snapshot(&snapshot);

        assert!(findings.iter().any(|f| f.category == "HIGH TCP CONNS"));
    }

    #[test]
    fn test_zombie_detection() {
        let io = ProcessIo::default();
        let mut snapshot = dummy_snapshot(&io);
        snapshot.status = ProcessStatus::Zombie;

        let findings = analyze_snapshot(&snapshot);
        assert!(findings.iter().any(|f| f.category == "ZOMBIE PROCESS"));
        assert_eq!(findings[0].confidence, Confidence::Confirmed);
    }

    #[test]
    fn test_deleted_files_detection() {
        let io = ProcessIo {
            open_files: vec![
                "/var/log/app.log (deleted)".to_string(),
                "/etc/hosts".to_string(),
            ],
            deleted_files: vec![crate::io::DeletedFile {
                path: "/var/log/app.log (deleted)".to_string(),
                size_bytes: 4 * 1024 * 1024 * 1024, // 4 GB
            }],
            unix_sockets: vec![],
            network_connections: vec![],
        };
        let snapshot = dummy_snapshot(&io);
        let findings = analyze_snapshot(&snapshot);

        assert!(findings.iter().any(|f| f.category == "DELETED FILES"));
        let deleted_finding = findings.iter().find(|f| f.category == "DELETED FILES").unwrap();
        assert_eq!(deleted_finding.confidence, Confidence::Confirmed);
        assert!(deleted_finding.evidence.iter().any(|e| e.contains("4.0 GB")));
    }

    #[test]
    fn test_privileged_port_detection() {
        let io = ProcessIo {
            open_files: vec![],
            deleted_files: vec![],
            unix_sockets: vec![],
            network_connections: vec!["TCP 127.0.0.1:80 (LISTEN)".to_string()],
        };
        let snapshot = dummy_snapshot(&io);
        let findings = analyze_snapshot(&snapshot);

        assert!(findings.iter().any(|f| f.category == "PRIVILEGED PORT"));
    }


    #[test]
    fn test_redact_sensitive_environment_variables() {
        assert_eq!(
            redact_env_var("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            "AWS_SECRET_ACCESS_KEY=*** [REDACTED]"
        );
        assert_eq!(
            redact_env_var("DATABASE_URL=postgres://postgres:mypassword@localhost:5432/mydb"),
            "DATABASE_URL=postgres://postgres:***@localhost:5432/mydb"
        );
        assert_eq!(
            redact_env_var("SERVICE_ENDPOINT=http://admin:secret123@api.internal:8080/v1"),
            "SERVICE_ENDPOINT=http://admin:***@api.internal:8080/v1"
        );
        assert_eq!(
            redact_env_var("OPENAI_API_KEY=sk-proj-1234567890"),
            "OPENAI_API_KEY=sk-*** [REDACTED]"
        );
        assert_eq!(
            redact_env_var("PATH=/usr/local/bin:/usr/bin"),
            "PATH=/usr/local/bin:/usr/bin"
        );
    }

    #[test]
    fn test_health_levels_from_findings() {
        assert_eq!(Health::from_findings(&[]), Health::Ok);

        let info_finding = vec![Finding {
            category: "LOCK CONTENTION",
            severity: Severity::Info,
            confidence: Confidence::Confirmed,
            observation: "Waiting on futex".to_string(),
            evidence: vec![],
            interpretation: "Thread lock wait".to_string(),
            recommendation: "Inspect deadlock".to_string(),
        }];
        assert_eq!(Health::from_findings(&info_finding), Health::Info);

        let warn_finding = vec![Finding {
            category: "CPU PEGGING",
            severity: Severity::Warning,
            confidence: Confidence::Likely,
            observation: "CPU 95%".to_string(),
            evidence: vec![],
            interpretation: "Busy loop".to_string(),
            recommendation: "Profile stack".to_string(),
        }];
        assert_eq!(Health::from_findings(&warn_finding), Health::Warning);

        let critical_finding = vec![
            Finding {
                category: "CPU PEGGING",
                severity: Severity::Warning,
                confidence: Confidence::Likely,
                observation: "CPU 95%".to_string(),
                evidence: vec![],
                interpretation: "Busy loop".to_string(),
                recommendation: "Profile stack".to_string(),
            },
            Finding {
                category: "D-STATE HANG",
                severity: Severity::Critical,
                confidence: Confidence::Confirmed,
                observation: "Stuck in D-state".to_string(),
                evidence: vec![],
                interpretation: "Kernel I/O hang".to_string(),
                recommendation: "Check storage".to_string(),
            },
        ];
        assert_eq!(Health::from_findings(&critical_finding), Health::Critical);
    }

    #[test]
    fn test_generate_summary_outputs() {
        assert_eq!(
            generate_summary(&[]),
            "Operating within normal resource thresholds and operating baseline."
        );

        let one_finding = vec![Finding {
            category: "DELETED FILES",
            severity: Severity::Warning,
            confidence: Confidence::Confirmed,
            observation: "Deleted files held".to_string(),
            evidence: vec![],
            interpretation: "Blocks held".to_string(),
            recommendation: "Restart".to_string(),
        }];
        assert_eq!(
            generate_summary(&one_finding),
            "Process is holding open file handles to deleted files."
        );

        let two_findings = vec![
            Finding {
                category: "CPU PEGGING",
                severity: Severity::Warning,
                confidence: Confidence::Likely,
                observation: "CPU 95%".to_string(),
                evidence: vec![],
                interpretation: "Busy loop".to_string(),
                recommendation: "Profile stack".to_string(),
            },
            Finding {
                category: "DELETED FILES",
                severity: Severity::Warning,
                confidence: Confidence::Confirmed,
                observation: "Deleted files held".to_string(),
                evidence: vec![],
                interpretation: "Blocks held".to_string(),
                recommendation: "Restart".to_string(),
            },
        ];
        assert_eq!(
            generate_summary(&two_findings),
            "Process is consuming unusually high CPU and holding open file handles to deleted files."
        );
    }
}
