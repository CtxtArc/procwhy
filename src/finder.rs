use anyhow::{bail, Result};
use sysinfo::{Pid, System};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetQuery {
    Pid(u32),
    Port(u16),
    Name(String),
}

pub fn parse_target_query(target_arg: Option<&str>, port_flag: Option<u16>) -> Result<TargetQuery> {
    if let Some(port) = port_flag {
        return Ok(TargetQuery::Port(port));
    }

    let target = match target_arg {
        Some(t) if !t.trim().is_empty() => t.trim(),
        _ => bail!("No target specified. Provide a PID, process name (e.g. 'node'), or port (e.g. ':8080')."),
    };

    // Case 1: ':8080' or 'port:8080'
    if let Some(port_str) = target.strip_prefix(':').or_else(|| target.strip_prefix("port:")) {
        if let Ok(port) = port_str.parse::<u16>() {
            return Ok(TargetQuery::Port(port));
        }
    }

    // Case 2: Pure integer (e.g. '1234')
    if let Ok(pid) = target.parse::<u32>() {
        return Ok(TargetQuery::Pid(pid));
    }

    // Case 3: Process name (e.g. 'firefox', 'node')
    Ok(TargetQuery::Name(target.to_string()))
}

/// Resolves a TargetQuery to a single PID, with friendly error handling.
pub fn resolve_pid(query: &TargetQuery, sys: &System) -> Result<u32> {
    match query {
        TargetQuery::Pid(pid) => {
            let sys_pid = Pid::from_u32(*pid);
            if sys.process(sys_pid).is_some() {
                Ok(*pid)
            } else {
                // Check if this integer happened to be an active listening port
                if *pid <= 65535 {
                    if let Ok(resolved) = resolve_pid_by_port(*pid as u16, sys) {
                        return Ok(resolved);
                    }
                }
                bail!("PID {} not found. Are you sure the process is running?", pid);
            }
        }
        TargetQuery::Port(port) => resolve_pid_by_port(*port, sys),
        TargetQuery::Name(name) => resolve_pid_by_name(name, sys),
    }
}

pub fn resolve_pid_by_name(name: &str, sys: &System) -> Result<u32> {
    let search_lower = name.to_lowercase();
    let mut matches = Vec::new();

    for (pid, process) in sys.processes() {
        let proc_name = process.name().to_lowercase();
        let cmd = process.cmd().join(" ").to_lowercase();

        let is_match = proc_name == search_lower
            || proc_name.starts_with(&search_lower)
            || cmd.split_whitespace().any(|tok| {
                tok == search_lower
                    || tok.ends_with(&format!("/{}", search_lower))
                    || tok.ends_with(&format!("\\{}", search_lower))
            });

        if is_match {
            matches.push((pid.as_u32(), process));
        }
    }

    if matches.is_empty() {
        bail!("No running process found matching '{}'.", name);
    }

    if matches.len() == 1 {
        return Ok(matches[0].0);
    }

    // Multiple matches: if there is an exact name match, filter to exact matches first
    let exact_matches: Vec<_> = matches
        .iter()
        .filter(|(_, p)| p.name().to_lowercase() == search_lower)
        .copied()
        .collect();

    let candidate_list = if !exact_matches.is_empty() && exact_matches.len() < matches.len() {
        if exact_matches.len() == 1 {
            return Ok(exact_matches[0].0);
        }
        exact_matches
    } else {
        matches
    };

    // Sort by CPU usage descending to show most active first
    let mut sorted = candidate_list;
    sorted.sort_by(|a, b| {
        b.1.cpu_usage()
            .partial_cmp(&a.1.cpu_usage())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut msg = format!("Multiple processes found matching '{}':\n", name);
    for (pid, proc) in sorted.iter().take(5) {
        let cmd = proc.cmd().join(" ");
        let display_cmd = if cmd.is_empty() { proc.name() } else { &cmd };
        let mem_mb = proc.memory() as f64 / 1024.0 / 1024.0;
        msg.push_str(&format!(
            "  PID {:<6}  {:<16} (CPU: {:>4.1}%, Mem: {:>5.1} MB)  {}\n",
            pid,
            proc.name(),
            proc.cpu_usage(),
            mem_mb,
            display_cmd
        ));
    }
    if sorted.len() > 5 {
        msg.push_str(&format!("  ...and {} more\n", sorted.len() - 5));
    }
    msg.push_str("\nSpecify a PID: procwhy <PID>");

    bail!(msg);
}

#[cfg(target_os = "linux")]
pub fn resolve_pid_by_port(port: u16, _sys: &System) -> Result<u32> {
    use std::collections::HashMap;
    use std::fs;

    // Find socket inodes on this port across TCP and UDP tables
    let mut matching_inodes = HashMap::new();

    if let Ok(tcp_entries) = procfs::net::tcp() {
        for entry in tcp_entries {
            if entry.local_address.port() == port {
                matching_inodes.insert(entry.inode, entry.state == procfs::net::TcpState::Listen);
            }
        }
    }
    if let Ok(tcp6_entries) = procfs::net::tcp6() {
        for entry in tcp6_entries {
            if entry.local_address.port() == port {
                matching_inodes.insert(entry.inode, entry.state == procfs::net::TcpState::Listen);
            }
        }
    }
    if let Ok(udp_entries) = procfs::net::udp() {
        for entry in udp_entries {
            if entry.local_address.port() == port {
                matching_inodes.insert(entry.inode, true);
            }
        }
    }
    if let Ok(udp6_entries) = procfs::net::udp6() {
        for entry in udp6_entries {
            if entry.local_address.port() == port {
                matching_inodes.insert(entry.inode, true);
            }
        }
    }

    if matching_inodes.is_empty() {
        bail!("No active process found on port {}.", port);
    }

    // Scan process file descriptors for matching socket inodes
    let mut candidate_pids = Vec::new();

    if let Ok(proc_entries) = fs::read_dir("/proc") {
        for p_entry in proc_entries.flatten() {
            let file_name = p_entry.file_name();
            let name_str = file_name.to_string_lossy();
            if let Ok(pid) = name_str.parse::<u32>() {
                let fd_dir = format!("/proc/{}/fd", pid);
                if let Ok(fds) = fs::read_dir(&fd_dir) {
                    for fd in fds.flatten() {
                        if let Ok(target) = fs::read_link(fd.path()) {
                            let target_str = target.to_string_lossy();
                            if let Some(inode_str) = target_str
                                .strip_prefix("socket:[")
                                .and_then(|s| s.strip_suffix(']'))
                            {
                                if let Ok(inode) = inode_str.parse::<u64>() {
                                    if let Some(&is_listen) = matching_inodes.get(&inode) {
                                        candidate_pids.push((pid, is_listen));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if candidate_pids.is_empty() {
        bail!(
            "Port {} is active, but permissions prevent inspecting owning process handles (try running with sudo).",
            port
        );
    }

    // Prioritize listening socket
    if let Some((pid, _)) = candidate_pids.iter().find(|(_, is_listen)| *is_listen) {
        return Ok(*pid);
    }

    Ok(candidate_pids[0].0)
}


#[cfg(target_os = "macos")]
pub fn resolve_pid_by_port(port: u16, _sys: &System) -> Result<u32> {
    use std::process::Command;

    let output = Command::new("lsof")
        .arg("-n")
        .arg("-P")
        .arg("-i")
        .arg(format!(":{}", port))
        .arg("-F")
        .arg("p")
        .output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if let Some(pid_str) = line.strip_prefix('p') {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    return Ok(pid);
                }
            }
        }
    }

    bail!("No active process found using port {}.", port);
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn resolve_pid_by_port(port: u16, _sys: &System) -> Result<u32> {
    bail!("Port resolution is not supported on this platform.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_target_query_pid() {
        let q = parse_target_query(Some("1234"), None).unwrap();
        assert_eq!(q, TargetQuery::Pid(1234));
    }

    #[test]
    fn test_parse_target_query_port_colon() {
        let q = parse_target_query(Some(":8080"), None).unwrap();
        assert_eq!(q, TargetQuery::Port(8080));

        let q2 = parse_target_query(Some("port:3000"), None).unwrap();
        assert_eq!(q2, TargetQuery::Port(3000));
    }

    #[test]
    fn test_parse_target_query_port_flag() {
        let q = parse_target_query(None, Some(5432)).unwrap();
        assert_eq!(q, TargetQuery::Port(5432));
    }

    #[test]
    fn test_parse_target_query_name() {
        let q = parse_target_query(Some("firefox"), None).unwrap();
        assert_eq!(q, TargetQuery::Name("firefox".to_string()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_resolve_live_port() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let current_pid = std::process::id();

        let mut sys = System::new();
        sys.refresh_processes();

        let resolved = resolve_pid_by_port(port, &sys).unwrap();
        assert_eq!(resolved, current_pid);
    }

    // ── parse_target_query — error paths ──────────────────────────────────

    #[test]
    fn test_parse_target_query_no_target_errors() {
        let result = parse_target_query(None, None);
        assert!(result.is_err(), "No target and no port flag must return an error");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("No target specified"), "Error must mention 'No target specified'");
    }

    #[test]
    fn test_parse_target_query_empty_string_errors() {
        let result = parse_target_query(Some(""), None);
        assert!(result.is_err(), "Empty string target must return an error");
    }

    #[test]
    fn test_parse_target_query_whitespace_only_errors() {
        let result = parse_target_query(Some("   "), None);
        assert!(result.is_err(), "Whitespace-only target must return an error");
    }

    #[test]
    fn test_parse_target_query_port_flag_takes_precedence_over_positional() {
        // Even if a positional target is also given, --port flag wins
        let q = parse_target_query(Some("node"), Some(8080)).unwrap();
        assert_eq!(q, TargetQuery::Port(8080),
            "--port flag must take precedence over positional target");
    }

    #[test]
    fn test_parse_target_query_port_prefix_out_of_u16_range_is_name() {
        // ":99999" — port_str "99999" is > u16::MAX, parse fails → treated as Name
        let q = parse_target_query(Some(":99999"), None).unwrap();
        assert_eq!(q, TargetQuery::Name(":99999".to_string()),
            "Port value exceeding u16::MAX must fall through to Name");
    }

    #[test]
    fn test_parse_target_query_port_colon_prefix_with_name() {
        // "port:myservice" — not a number → treated as Name
        let q = parse_target_query(Some("port:myservice"), None).unwrap();
        assert_eq!(q, TargetQuery::Name("port:myservice".to_string()),
            "Non-numeric port:X target must be treated as a Name");
    }

    #[test]
    fn test_parse_target_query_large_pid_is_pid() {
        let q = parse_target_query(Some("65535"), None).unwrap();
        assert_eq!(q, TargetQuery::Pid(65535));
    }
}
