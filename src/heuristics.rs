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
    pub severity: Severity,
    pub confidence: Confidence,
    pub category: &'static str,
    pub observed: String,
    pub inference: String,
    pub recommendation: String,
    pub evidence: Vec<String>,
    pub explanation: Option<String>,
}

pub fn generate_summary(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "Operating within normal resource thresholds and operating baseline.".to_string();
    }

    let mut highlights = Vec::new();
    for f in findings {
        match f.category {
            "D-STATE HANG" => highlights.push("stuck in uninterruptible kernel sleep (D-state)"),
            "CRITICAL RAM" => highlights.push("consuming critical memory (high OOM risk)"),
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
            severity: Severity::Critical,
            confidence: Confidence::Confirmed,
            category: "D-STATE HANG",
            observed: format!(
                "Process is stuck in Uninterruptible Sleep (D-state) on kernel wait channel '{}'.",
                wchan_info
            ),
            inference: "The process is blocked inside a kernel driver/storage operation. Signals (including SIGKILL / kill -9) are deferred until the kernel I/O request finishes.".to_string(),
            recommendation: "Inspect storage subsystem, slow/hanging NFS mounts, or kernel dmesg logs for driver timeouts.".to_string(),
            evidence: vec![
                "Process state: Uninterruptible Sleep (D)".to_string(),
                format!("Kernel wait channel: {}", wchan_info),
            ],
            explanation: Some("D-state (TASK_UNINTERRUPTIBLE) is used when a task is waiting on hardware or filesystem I/O that cannot be safely aborted without risking corruption.".to_string()),
        });
    } else if let Some(wchan) = snapshot.wchan {
        if wchan.contains("futex") && snapshot.cpu_usage == 0.0 {
            findings.push(Finding {
                severity: Severity::Info,
                confidence: Confidence::Likely,
                category: "LOCK CONTENTION",
                observed: format!("Threads are sleeping in kernel wait channel '{}' with 0% CPU.", wchan),
                inference: "Process threads are blocked on a user-space synchronization primitive (e.g. pthread mutex / futex lock).".to_string(),
                recommendation: "If the process is unresponsive, inspect thread stacks for deadlocks or lock starvation.".to_string(),
                evidence: vec![
                    format!("Kernel wait channel: {}", wchan),
                    "CPU utilization: 0.0%".to_string(),
                ],
                explanation: Some("A futex wait indicates threads are waiting for another thread to release a lock or signal a condition variable.".to_string()),
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
                severity: Severity::Warning,
                confidence: Confidence::Likely,
                category: "HIGH DISK I/O",
                observed: format!(
                    "High disk throughput: {:.1} MB/s ({:.1} MB/s read, {:.1} MB/s write).",
                    total_mb_s, read_mb_s, write_mb_s
                ),
                inference: "Heavy disk read/write bandwidth that may saturate I/O queues or degrade overall system responsiveness.".to_string(),
                recommendation: "Check for unbuffered file logging, large core dumps, or swap thrashing.".to_string(),
                evidence: vec![
                    format!("Read rate: {:.1} MB/s", read_mb_s),
                    format!("Write rate: {:.1} MB/s", write_mb_s),
                ],
                explanation: Some("High disk I/O measured as delta over 200ms window from /proc/[pid]/io.".to_string()),
            });
        }
    }
}

fn check_child_processes(snapshot: &ProcessSnapshot, findings: &mut Vec<Finding>) {
    if snapshot.children_count >= 50 {
        findings.push(Finding {
            severity: Severity::Warning,
            confidence: Confidence::Likely,
            category: "HIGH CHILD COUNT",
            observed: format!(
                "Process has spawned {} active child processes/workers (PID {}).",
                snapshot.children_count, snapshot.pid
            ),
            inference: "Elevated worker or sub-process count that may increase context switching and process table load.".to_string(),
            recommendation: "Ensure child processes are reaped to avoid process table exhaustion.".to_string(),
            evidence: vec![format!("Direct child process count: {}", snapshot.children_count)],
            explanation: Some("Process hierarchy was traversed to identify all active child processes whose parent PID matches this process.".to_string()),
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
            severity: Severity::Critical,
            confidence: Confidence::Confirmed,
            category: "ZOMBIE PROCESS",
            observed: format!(
                "Defunct process. It has terminated but {} has not collected its exit code via waitpid().",
                parent_info
            ),
            inference: "The process entry remains allocated in the kernel process table until reaped by its parent.".to_string(),
            recommendation: format!("Signal {} or restart the parent to reap terminated child processes.", parent_info),
            evidence: vec![
                format!("Status: {:?}", snapshot.status),
                format!("Parent: {}", parent_info),
            ],
            explanation: Some("When a process exits, its descriptor remains in the OS table as a zombie until the parent reads its exit status with wait() / waitpid().".to_string()),
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
            severity: Severity::Critical,
            confidence: Confidence::Likely,
            category: "OOM KILLER RISK",
            observed: format!(
                "Consuming {:.1} MB ({:.1}% of {:.1} GB system RAM).",
                mem_mb, mem_pct, total_gb
            ),
            inference: "High probability of Linux kernel OOM-killer termination under system memory pressure.".to_string(),
            recommendation: "Check for memory leaks or configure container memory limits.".to_string(),
            evidence: vec![
                format!("Resident memory: {:.1} MB", mem_mb),
                format!("System memory share: {:.1}%", mem_pct),
            ],
            explanation: Some("When system memory is exhausted, the Linux Out-Of-Memory (OOM) killer selects high-memory processes to terminate with SIGKILL.".to_string()),
        });
    } else if mem_pct >= 20.0 {
        findings.push(Finding {
            severity: Severity::Warning,
            confidence: Confidence::Likely,
            category: "HIGH RAM",
            observed: format!(
                "Process consumes {:.1} MB ({:.1}% of {:.1} GB system RAM).",
                mem_mb, mem_pct, total_gb
            ),
            inference: "Substantial resident memory footprint relative to total available host RAM.".to_string(),
            recommendation: "Verify memory growth profile or configure cgroup memory limits.".to_string(),
            evidence: vec![
                format!("Resident memory: {:.1} MB", mem_mb),
                format!("System memory share: {:.1}%", mem_pct),
            ],
            explanation: Some("Resident Set Size (RSS) represents physical memory currently mapped to the process address space.".to_string()),
        });
    }
}

fn check_cpu_usage(snapshot: &ProcessSnapshot, findings: &mut Vec<Finding>) {
    if snapshot.cpu_usage >= 90.0 {
        findings.push(Finding {
            severity: Severity::Warning,
            confidence: Confidence::Likely,
            category: "CPU PEGGING",
            observed: format!(
                "Process is consuming {:.1}% CPU over the sampling window.",
                snapshot.cpu_usage
            ),
            inference: "Sustained CPU-bound execution (tight loop or heavy compute workload).".to_string(),
            recommendation: "Profile active threads with perf/pstack before terminating to capture call stacks.".to_string(),
            evidence: vec![
                format!("Sampled CPU: {:.1}%", snapshot.cpu_usage),
                format!("Scheduler state: {:?}", snapshot.status),
            ],
            explanation: Some("High CPU utilization in state 'Running' without I/O wait indicates thread execution in user or kernel space.".to_string()),
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
            format!("Publicly listening on wildcard interface: {}", sample)
        } else {
            format!(
                "Publicly listening on {} wildcard interfaces ({})",
                count, sample
            )
        };

        findings.push(Finding {
            severity: Severity::Warning,
            confidence: Confidence::Possible,
            category: "PUBLIC LISTENER",
            observed: desc,
            inference: "The socket is exposed to all network interfaces on the host (including public/external networks if unfirewalled).".to_string(),
            recommendation: "Bind to 127.0.0.1 or a specific interface if public external access is unintended.".to_string(),
            evidence: vec![format!("Listener bind: {}", sample)],
            explanation: Some("Binding to INADDR_ANY (0.0.0.0) or IN6ADDR_ANY ([::]) accepts incoming traffic on every host network interface.".to_string()),
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
            severity: Severity::Warning,
            confidence: Confidence::Possible,
            category: "HIGH TCP CONNS",
            observed: format!(
                "Process has {} active external TCP connections (threshold: 10).",
                external_count
            ),
            inference: "Elevated outbound or inbound external network traffic, or potential connection pool exhaustion.".to_string(),
            recommendation: "Check for connection pool leaks, unclosed HTTP clients, or high external traffic.".to_string(),
            evidence: vec![format!("Active external connections: {}", external_count)],
            explanation: Some("Connections to non-loopback IPs in ESTABLISHED state parsed from socket tables.".to_string()),
        });
    }
}

fn check_deleted_open_files(snapshot: &ProcessSnapshot, findings: &mut Vec<Finding>) {
    let deleted_files: Vec<_> = snapshot
        .io
        .open_files
        .iter()
        .filter(|f| f.ends_with(" (deleted)") || f.contains(" (deleted)"))
        .cloned()
        .collect();

    if !deleted_files.is_empty() {
        let count = deleted_files.len();
        let sample = &deleted_files[0];
        findings.push(Finding {
            severity: Severity::Warning,
            confidence: Confidence::Confirmed,
            category: "DELETED FILES",
            observed: format!(
                "Process holds {} open file handle(s) to unlinked/deleted files on disk (e.g. {}).",
                count, sample
            ),
            inference: "Disk space will not be freed by the filesystem until the process closes the descriptors or terminates.".to_string(),
            recommendation: "Restart or signal the process to release deleted file handles and reclaim disk space.".to_string(),
            evidence: vec![
                format!("Open deleted file count: {}", count),
                format!("Sample unlinked path: {}", sample),
            ],
            explanation: Some("When a file is unlinked while open, its directory entry is removed but inode data blocks remain allocated until the last descriptor closes.".to_string()),
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
            severity: Severity::Info,
            confidence: Confidence::Confirmed,
            category: "PRIVILEGED PORT",
            observed: format!("Bound to privileged system port {} ({}).", sample.0, sample.1),
            inference: "Process required CAP_NET_BIND_SERVICE or root privileges at bind time.".to_string(),
            recommendation: "Ensure least-privilege principles are followed if running as a non-root service.".to_string(),
            evidence: vec![format!("Privileged port: {}", sample.0)],
            explanation: Some("Ports below 1024 are reserved by POSIX systems and require elevated capabilities to bind.".to_string()),
        });
    }
}

fn check_high_fd_count(snapshot: &ProcessSnapshot, findings: &mut Vec<Finding>) {
    let total_fds = snapshot.io.open_files.len()
        + snapshot.io.unix_sockets.len()
        + snapshot.io.network_connections.len();

    if total_fds >= 100 {
        findings.push(Finding {
            severity: Severity::Info,
            confidence: Confidence::Confirmed,
            category: "HIGH FD COUNT",
            observed: format!(
                "Process has {} open file descriptors and sockets.",
                total_fds
            ),
            inference: "Elevated file descriptor usage relative to default process expectations.".to_string(),
            recommendation: "Check file descriptor limits (ulimit -n) to prevent EMFILE errors.".to_string(),
            evidence: vec![
                format!("Open files: {}", snapshot.io.open_files.len()),
                format!("Sockets: {}", snapshot.io.unix_sockets.len() + snapshot.io.network_connections.len()),
            ],
            explanation: Some("Aggregated from /proc/[pid]/fd or lsof output.".to_string()),
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
            unix_sockets: vec![],
            network_connections: vec![],
        };
        let snapshot = dummy_snapshot(&io);
        let findings = analyze_snapshot(&snapshot);

        assert!(findings.iter().any(|f| f.category == "DELETED FILES"));
        assert_eq!(findings[0].confidence, Confidence::Confirmed);
    }

    #[test]
    fn test_privileged_port_detection() {
        let io = ProcessIo {
            open_files: vec![],
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
            severity: Severity::Info,
            confidence: Confidence::Confirmed,
            category: "LOCK CONTENTION",
            observed: "Waiting on futex".to_string(),
            inference: "Thread lock wait".to_string(),
            recommendation: "Inspect deadlock".to_string(),
            evidence: vec![],
            explanation: None,
        }];
        assert_eq!(Health::from_findings(&info_finding), Health::Info);

        let warn_finding = vec![Finding {
            severity: Severity::Warning,
            confidence: Confidence::Likely,
            category: "CPU PEGGING",
            observed: "CPU 95%".to_string(),
            inference: "Busy loop".to_string(),
            recommendation: "Profile stack".to_string(),
            evidence: vec![],
            explanation: None,
        }];
        assert_eq!(Health::from_findings(&warn_finding), Health::Warning);

        let critical_finding = vec![
            Finding {
                severity: Severity::Warning,
                confidence: Confidence::Likely,
                category: "CPU PEGGING",
                observed: "CPU 95%".to_string(),
                inference: "Busy loop".to_string(),
                recommendation: "Profile stack".to_string(),
                evidence: vec![],
                explanation: None,
            },
            Finding {
                severity: Severity::Critical,
                confidence: Confidence::Confirmed,
                category: "D-STATE HANG",
                observed: "Stuck in D-state".to_string(),
                inference: "Kernel I/O hang".to_string(),
                recommendation: "Check storage".to_string(),
                evidence: vec![],
                explanation: None,
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
            severity: Severity::Warning,
            confidence: Confidence::Confirmed,
            category: "DELETED FILES",
            observed: "Deleted files held".to_string(),
            inference: "Blocks held".to_string(),
            recommendation: "Restart".to_string(),
            evidence: vec![],
            explanation: None,
        }];
        assert_eq!(
            generate_summary(&one_finding),
            "Process is holding open file handles to deleted files."
        );

        let two_findings = vec![
            Finding {
                severity: Severity::Warning,
                confidence: Confidence::Likely,
                category: "CPU PEGGING",
                observed: "CPU 95%".to_string(),
                inference: "Busy loop".to_string(),
                recommendation: "Profile stack".to_string(),
                evidence: vec![],
                explanation: None,
            },
            Finding {
                severity: Severity::Warning,
                confidence: Confidence::Confirmed,
                category: "DELETED FILES",
                observed: "Deleted files held".to_string(),
                inference: "Blocks held".to_string(),
                recommendation: "Restart".to_string(),
                evidence: vec![],
                explanation: None,
            },
        ];
        assert_eq!(
            generate_summary(&two_findings),
            "Process is consuming unusually high CPU and holding open file handles to deleted files."
        );
    }
}
