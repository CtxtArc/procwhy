use crate::io::{DiskIoRate, ProcessIo};
use sysinfo::ProcessStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub category: &'static str,
    pub message: String,
    pub recommendation: Option<String>,
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
            category: "D-STATE HANG",
            message: format!(
                "Process is in uninterruptible sleep (D-state) on kernel '{}'. It cannot be killed until I/O unblocks.",
                wchan_info
            ),
            recommendation: Some(
                "Check storage devices, slow NFS mounts, or device driver status.".to_string(),
            ),
        });
    } else if let Some(wchan) = snapshot.wchan {
        if wchan.contains("futex") && snapshot.cpu_usage == 0.0 {
            findings.push(Finding {
                severity: Severity::Info,
                category: "LOCK WAIT",
                message: format!("Process is waiting in kernel wait channel '{}' (futex lock).", wchan),
                recommendation: None,
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
                category: "HIGH DISK I/O",
                message: format!(
                    "High disk throughput: {:.1} MB/s ({:.1} MB/s read, {:.1} MB/s write).",
                    total_mb_s, read_mb_s, write_mb_s
                ),
                recommendation: Some(
                    "Check for excessive file flushing, unbuffered logging, or swap activity.".to_string(),
                ),
            });
        }
    }
}

fn check_child_processes(snapshot: &ProcessSnapshot, findings: &mut Vec<Finding>) {
    if snapshot.children_count >= 50 {
        findings.push(Finding {
            severity: Severity::Warning,
            category: "HIGH CHILD COUNT",
            message: format!(
                "Process (PID {}) has spawned {} child processes.",
                snapshot.pid, snapshot.children_count
            ),
            recommendation: Some(
                "Ensure child processes are reaped to avoid process table exhaustion.".to_string(),
            ),
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
            category: "ZOMBIE PROCESS",
            message: format!(
                "Defunct process. Terminated but not reaped by {}.",
                parent_info
            ),
            recommendation: Some(format!(
                "Signal {} to reap terminated children.",
                parent_info
            )),
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
            category: "CRITICAL RAM",
            message: format!(
                "Process uses {:.1} MB ({:.1}% of {:.1} GB system RAM).",
                mem_mb, mem_pct, total_gb
            ),
            recommendation: Some(
                "High risk of OOM-killer termination. Check for memory leaks.".to_string(),
            ),
        });
    } else if mem_pct >= 20.0 {
        findings.push(Finding {
            severity: Severity::Warning,
            category: "HIGH RAM",
            message: format!(
                "Process uses {:.1} MB ({:.1}% of {:.1} GB system RAM).",
                mem_mb, mem_pct, total_gb
            ),
            recommendation: Some(
                "Verify memory growth or configure cgroup memory limits.".to_string(),
            ),
        });
    }
}

fn check_cpu_usage(snapshot: &ProcessSnapshot, findings: &mut Vec<Finding>) {
    if snapshot.cpu_usage >= 90.0 {
        findings.push(Finding {
            severity: Severity::Warning,
            category: "HIGH CPU",
            message: format!(
                "Process is at {:.1}% CPU usage.",
                snapshot.cpu_usage
            ),
            recommendation: Some(
                "Profile threads for tight loops or lock contention.".to_string(),
            ),
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
            format!("Listening on wildcard interface: {}", sample)
        } else {
            format!(
                "Listening on {} wildcard interfaces ({})",
                count, sample
            )
        };

        findings.push(Finding {
            severity: Severity::Warning,
            category: "WILDCARD BIND",
            message: format!("{}, exposed on all network interfaces.", desc),
            recommendation: Some(
                "Bind to 127.0.0.1 if public external access is unintended.".to_string(),
            ),
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
            category: "HIGH TCP CONNS",
            message: format!(
                "{} active external TCP connections (threshold: 10).",
                external_count
            ),
            recommendation: Some(
                "Inspect connection pooling or HTTP keep-alive settings.".to_string(),
            ),
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
            category: "DELETED FILES",
            message: format!(
                "{} open file handles point to deleted files (e.g. {}). Disk space remains held until closed.",
                count, sample
            ),
            recommendation: Some(
                "Restart the process to release deleted file handles and free disk space.".to_string(),
            ),
        });
    }
}

fn check_privileged_ports(snapshot: &ProcessSnapshot, findings: &mut Vec<Finding>) {
    let mut priv_ports = Vec::new();

    for conn in &snapshot.io.network_connections {
        if conn.contains("LISTEN") {
            if let Some(port) = extract_port(conn) {
                if port > 0 && port < 1024 {
                    priv_ports.push(port);
                }
            }
        }
    }

    priv_ports.sort();
    priv_ports.dedup();

    if !priv_ports.is_empty() {
        let ports_str = priv_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(Finding {
            severity: Severity::Info,
            category: "PRIVILEGED PORT",
            message: format!("Bound to privileged port(s): {}.", ports_str),
            recommendation: Some(
                "Ensure root or CAP_NET_BIND_SERVICE capabilities are intended.".to_string(),
            ),
        });
    }
}

fn check_high_fd_count(snapshot: &ProcessSnapshot, findings: &mut Vec<Finding>) {
    let total_fds = snapshot.io.open_files.len()
        + snapshot.io.unix_sockets.len()
        + snapshot.io.network_connections.len();

    if total_fds >= 500 {
        findings.push(Finding {
            severity: Severity::Warning,
            category: "HIGH FD COUNT",
            message: format!(
                "Process has {} open file descriptors and sockets.",
                total_fds
            ),
            recommendation: Some(
                "Check for file descriptor leaks and verify ulimit -n.".to_string(),
            ),
        });
    } else if total_fds >= 100 {
        findings.push(Finding {
            severity: Severity::Info,
            category: "HIGH FD COUNT",
            message: format!(
                "Process has {} open file descriptors and sockets.",
                total_fds
            ),
            recommendation: None,
        });
    }
}


fn extract_port(conn_str: &str) -> Option<u16> {
    let parts: Vec<&str> = conn_str.split_whitespace().collect();
    for part in parts {
        if let Some(colon_idx) = part.rfind(':') {
            let port_part = &part[colon_idx + 1..];
            let clean_port: String = port_part.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(port) = clean_port.parse::<u16>() {
                return Some(port);
            }
        }
    }
    None
}

/// Redacts sensitive environment variables like tokens, passwords, and API keys.
pub fn redact_env_var(env_str: &str) -> String {
    if let Some((key, val)) = env_str.split_once('=') {
        let key_upper = key.to_uppercase();
        let is_sensitive_key = key_upper.contains("SECRET")
            || key_upper.contains("PASS")
            || key_upper.contains("TOKEN")
            || key_upper.contains("AUTH")
            || key_upper.contains("KEY")
            || key_upper.contains("CREDENTIAL")
            || key_upper.contains("DATABASE_URL")
            || key_upper.contains("DB_URI")
            || key_upper.contains("PRIVATE");

        if is_sensitive_key {
            if val.is_empty() {
                return format!("{}=", key);
            }
            if val.starts_with("sk-") {
                return format!("{}=sk-*** [REDACTED]", key);
            }
            return format!("{}=*** [REDACTED]", key);
        }

        // Check for value patterns (e.g. tokens in values)
        if val.starts_with("Bearer ")
            || val.starts_with("ghp_")
            || val.starts_with("gho_")
            || val.starts_with("glpat-")
            || val.starts_with("xoxb-")
        {
            return format!("{}=*** [REDACTED]", key);
        }

        // Redact passwords inside URLs (e.g. OTHER_URL=postgres://user:password@host/db)
        if val.contains("://") && val.contains('@') {
            if let Some(scheme_end) = val.find("://") {
                let scheme = &val[..scheme_end];
                let after_scheme = &val[scheme_end + 3..];
                if let Some(at_idx) = after_scheme.find('@') {
                    let auth_part = &after_scheme[..at_idx];
                    if let Some(colon_idx) = auth_part.find(':') {
                        let user = &auth_part[..colon_idx];
                        let rest = &after_scheme[at_idx..];
                        return format!("{}={}://{}:***{}", key, scheme, user, rest);
                    }
                }
            }
        }

        return format!("{}={}", key, val);
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
            cpu_usage: 5.0,
            memory_bytes: 100 * 1024 * 1024,                  // 100 MB
            total_system_memory_bytes: 1024 * 1024 * 1024 * 8, // 8 GB
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
        assert!(findings.is_empty(), "Expected no findings for baseline process");
    }

    #[test]
    fn test_disk_io_rate_heuristic() {
        let io = ProcessIo::default();
        let mut snapshot = dummy_snapshot(&io);
        snapshot.disk_io_rate = Some(DiskIoRate {
            read_bytes_per_sec: 25.0 * 1024.0 * 1024.0, // 25 MB/s
            write_bytes_per_sec: 5.0 * 1024.0 * 1024.0,  // 5 MB/s
        });

        let findings = analyze_snapshot(&snapshot);
        assert!(findings.iter().any(|f| f.category == "HIGH DISK I/O"));
    }

    #[test]
    fn test_uninterruptible_d_state() {
        let io = ProcessIo::default();
        let mut snapshot = dummy_snapshot(&io);
        snapshot.status = ProcessStatus::UninterruptibleDiskSleep;
        snapshot.wchan = Some("io_schedule");

        let findings = analyze_snapshot(&snapshot);
        assert!(findings.iter().any(|f| f.category == "D-STATE HANG"));
    }


    #[test]
    fn test_memory_exceeding_20_percent() {
        let io = ProcessIo::default();
        let mut snapshot = dummy_snapshot(&io);
        snapshot.memory_bytes = 2 * 1024 * 1024 * 1024;

        let findings = analyze_snapshot(&snapshot);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "HIGH RAM");
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn test_memory_exceeding_50_percent() {
        let io = ProcessIo::default();
        let mut snapshot = dummy_snapshot(&io);
        snapshot.memory_bytes = (4.8 * 1024.0 * 1024.0 * 1024.0) as u64;

        let findings = analyze_snapshot(&snapshot);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "CRITICAL RAM");
        assert_eq!(findings[0].severity, Severity::Critical);
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

        assert!(findings.iter().any(|f| f.category == "WILDCARD BIND"));
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
            "DATABASE_URL=*** [REDACTED]"
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
}

