use serde::Serialize;
#[cfg(target_os = "linux")]
use std::collections::HashSet;
#[cfg(target_os = "linux")]
use std::fs;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeletedFile {
    pub path: String,
    pub size_bytes: u64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessIo {
    pub open_files: Vec<String>,
    pub deleted_files: Vec<DeletedFile>,
    pub unix_sockets: Vec<String>,
    pub network_connections: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct DiskIoStats {
    pub read_bytes: u64,
    pub write_bytes: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
pub struct DiskIoRate {
    pub read_bytes_per_sec: f64,
    pub write_bytes_per_sec: f64,
}

impl DiskIoRate {
    pub fn calculate(start: Option<DiskIoStats>, end: Option<DiskIoStats>, duration_secs: f64) -> Option<Self> {
        if duration_secs <= 0.0 {
            return None;
        }
        let (s, e) = (start?, end?);
        let read_rate = (e.read_bytes.saturating_sub(s.read_bytes)) as f64 / duration_secs;
        let write_rate = (e.write_bytes.saturating_sub(s.write_bytes)) as f64 / duration_secs;
        Some(DiskIoRate {
            read_bytes_per_sec: read_rate,
            write_bytes_per_sec: write_rate,
        })
    }
}

pub fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

pub fn format_bytes_rate(bytes_per_sec: f64) -> String {
    if bytes_per_sec >= 1024.0 * 1024.0 * 1024.0 {
        format!("{:.2} GB/s", bytes_per_sec / (1024.0 * 1024.0 * 1024.0))
    } else if bytes_per_sec >= 1024.0 * 1024.0 {
        format!("{:.1} MB/s", bytes_per_sec / (1024.0 * 1024.0))
    } else if bytes_per_sec >= 1024.0 {
        format!("{:.1} KB/s", bytes_per_sec / 1024.0)
    } else {
        format!("{:.0} B/s", bytes_per_sec)
    }
}

#[cfg(target_os = "linux")]
pub fn get_disk_io(pid: u32) -> Option<DiskIoStats> {
    let io_file = format!("/proc/{}/io", pid);
    let content = fs::read_to_string(io_file).ok()?;
    let mut stats = DiskIoStats::default();

    for line in content.lines() {
        if let Some(val) = line.strip_prefix("read_bytes:") {
            stats.read_bytes = val.trim().parse::<u64>().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("write_bytes:") {
            stats.write_bytes = val.trim().parse::<u64>().unwrap_or(0);
        }
    }

    Some(stats)
}

#[cfg(not(target_os = "linux"))]
pub fn get_disk_io(_pid: u32) -> Option<DiskIoStats> {
    None
}

#[cfg(target_os = "linux")]
pub fn get_wchan(pid: u32) -> Option<String> {
    let path = format!("/proc/{}/wchan", pid);
    let content = fs::read_to_string(path).ok()?;
    let trimmed = content.trim();
    if trimmed.is_empty() || trimmed == "0" {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn get_wchan(_pid: u32) -> Option<String> {
    None
}

#[cfg(target_os = "linux")]
pub fn get_process_io(pid: u32) -> ProcessIo {
    let mut io = ProcessIo::default();
    let mut socket_inodes: HashSet<u64> = HashSet::new();

    // Scan process file descriptor links
    let fd_dir = format!("/proc/{}/fd", pid);
    if let Ok(entries) = fs::read_dir(&fd_dir) {
        for entry in entries.flatten() {
            if let Ok(target) = fs::read_link(entry.path()) {
                let target_str = target.to_string_lossy().to_string();

                if let Some(inode_str) = target_str
                    .strip_prefix("socket:[")
                    .and_then(|s| s.strip_suffix(']'))
                {
                    if let Ok(inode) = inode_str.parse::<u64>() {
                        socket_inodes.insert(inode);
                    }
                } else if let Some(inode_str) = target_str.strip_prefix("[0000]:") {
                    if let Ok(inode) = inode_str.parse::<u64>() {
                        socket_inodes.insert(inode);
                    }
                } else if target_str.starts_with('/') {
                    // Exclude internal /proc/[pid]/fd directory references
                    let proc_prefix = format!("/proc/{}", pid);
                    if !target_str.starts_with(&proc_prefix) || !target_str.ends_with("/fd") {
                        if target_str.ends_with(" (deleted)") || target_str.contains(" (deleted)") {
                            let size = fs::metadata(entry.path()).map(|m| m.len()).unwrap_or(0);
                            io.deleted_files.push(DeletedFile {
                                path: target_str.clone(),
                                size_bytes: size,
                            });
                        }
                        io.open_files.push(target_str);
                    }
                }
            }
        }
    }

    if socket_inodes.is_empty() {
        io.open_files.sort();
        io.open_files.dedup();
        return io;
    }

    // Read TCP, UDP, and UNIX socket tables
    let proc_res = procfs::process::Process::new(pid as i32);

    // Collect TCP sockets
    let mut tcp_entries = Vec::new();
    if let Ok(ref proc) = proc_res {
        if let Ok(tcp) = proc.tcp() {
            tcp_entries.extend(tcp);
        }
        if let Ok(tcp6) = proc.tcp6() {
            tcp_entries.extend(tcp6);
        }
    }
    if tcp_entries.is_empty() {
        if let Ok(tcp) = procfs::net::tcp() {
            tcp_entries.extend(tcp);
        }
        if let Ok(tcp6) = procfs::net::tcp6() {
            tcp_entries.extend(tcp6);
        }
    }

    // Collect UDP sockets
    let mut udp_entries = Vec::new();
    if let Ok(ref proc) = proc_res {
        if let Ok(udp) = proc.udp() {
            udp_entries.extend(udp);
        }
        if let Ok(udp6) = proc.udp6() {
            udp_entries.extend(udp6);
        }
    }
    if udp_entries.is_empty() {
        if let Ok(udp) = procfs::net::udp() {
            udp_entries.extend(udp);
        }
        if let Ok(udp6) = procfs::net::udp6() {
            udp_entries.extend(udp6);
        }
    }

    // Collect UNIX sockets
    let mut unix_entries = Vec::new();
    if let Ok(ref proc) = proc_res {
        if let Ok(unix) = proc.unix() {
            unix_entries.extend(unix);
        }
    }
    if unix_entries.is_empty() {
        if let Ok(unix) = procfs::net::unix() {
            unix_entries.extend(unix);
        }
    }

    // Match socket inodes
    let mut resolved_inodes = HashSet::new();

    for entry in tcp_entries {
        if socket_inodes.contains(&entry.inode) {
            resolved_inodes.insert(entry.inode);
            let conn_str = if entry.state == procfs::net::TcpState::Listen {
                format!("TCP {} (LISTEN)", entry.local_address)
            } else {
                let state_str = format_tcp_state(entry.state);
                format!(
                    "TCP {} -> {} ({})",
                    entry.local_address, entry.remote_address, state_str
                )
            };
            io.network_connections.push(conn_str);
        }
    }

    for entry in udp_entries {
        if socket_inodes.contains(&entry.inode) {
            resolved_inodes.insert(entry.inode);
            let conn_str = if entry.remote_address.port() == 0
                || entry.remote_address.ip().is_unspecified()
            {
                format!("UDP {}", entry.local_address)
            } else {
                format!("UDP {} -> {}", entry.local_address, entry.remote_address)
            };
            io.network_connections.push(conn_str);
        }
    }

    for entry in unix_entries {
        if socket_inodes.contains(&entry.inode) {
            resolved_inodes.insert(entry.inode);
            let sock_str = if let Some(ref path) = entry.path {
                if !path.as_os_str().is_empty() {
                    path.to_string_lossy().to_string()
                } else {
                    format!(
                        "[unnamed {} socket (inode {})]",
                        format_unix_socket_type(entry.socket_type),
                        entry.inode
                    )
                }
            } else {
                format!(
                    "[unnamed {} socket (inode {})]",
                    format_unix_socket_type(entry.socket_type),
                    entry.inode
                )
            };
            io.unix_sockets.push(sock_str);
        }
    }

    // If any socket inode wasn't resolved in tcp/udp/unix tables
    for inode in socket_inodes {
        if !resolved_inodes.contains(&inode) {
            io.unix_sockets.push(format!("[socket: {}]", inode));
        }
    }

    io.open_files.sort();
    io.open_files.dedup();
    io.unix_sockets.sort();
    io.unix_sockets.dedup();
    io.network_connections.sort();
    io.network_connections.dedup();

    io
}

#[cfg(not(target_os = "linux"))]
pub fn get_process_io(pid: u32) -> ProcessIo {
    let output = std::process::Command::new("lsof")
        .args(["-p", &pid.to_string(), "-F", "pftPTn"])
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            return parse_lsof_output(&stdout);
        }
    }

    // Fallback to tabular lsof
    let output_tabular = std::process::Command::new("lsof")
        .args(["-p", &pid.to_string()])
        .output();

    if let Ok(out) = output_tabular {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            return parse_lsof_output(&stdout);
        }
    }

    ProcessIo::default()
}

#[cfg(target_os = "linux")]
fn format_tcp_state(state: procfs::net::TcpState) -> &'static str {
    match state {
        procfs::net::TcpState::Established => "ESTABLISHED",
        procfs::net::TcpState::SynSent => "SYN_SENT",
        procfs::net::TcpState::SynRecv => "SYN_RECV",
        procfs::net::TcpState::FinWait1 => "FIN_WAIT1",
        procfs::net::TcpState::FinWait2 => "FIN_WAIT2",
        procfs::net::TcpState::TimeWait => "TIME_WAIT",
        procfs::net::TcpState::Close => "CLOSE",
        procfs::net::TcpState::CloseWait => "CLOSE_WAIT",
        procfs::net::TcpState::LastAck => "LAST_ACK",
        procfs::net::TcpState::Listen => "LISTEN",
        procfs::net::TcpState::Closing => "CLOSING",
        procfs::net::TcpState::NewSynRecv => "NEW_SYN_RECV",
    }
}

#[cfg(target_os = "linux")]
fn format_unix_socket_type(st: u16) -> &'static str {
    match st {
        1 => "STREAM",
        2 => "DGRAM",
        3 => "RAW",
        4 => "RDM",
        5 => "SEQPACKET",
        6 => "DCCP",
        _ => "UNIX",
    }
}

#[allow(dead_code)]
#[derive(Default)]
struct LsofFdRecord {
    fd_type: Option<String>,
    protocol: Option<String>,
    tcp_state: Option<String>,
    name: Option<String>,
}

#[allow(dead_code)]
pub fn parse_lsof_output(stdout: &str) -> ProcessIo {
    let mut io = ProcessIo::default();
    let mut current = LsofFdRecord::default();

    let commit_record = |rec: &mut LsofFdRecord, io: &mut ProcessIo| {
        let name = match rec.name.take() {
            Some(n) if !n.trim().is_empty() => n.trim().to_string(),
            _ => return,
        };

        let fd_type = rec.fd_type.take().unwrap_or_default();
        let protocol = rec.protocol.take().unwrap_or_default();
        let tcp_state = rec.tcp_state.take();

        let type_upper = fd_type.to_uppercase();
        let proto_upper = protocol.to_uppercase();

        let is_unix = type_upper == "UNIX"
            || name.starts_with('/') && (name.contains(".sock") || name.contains("/run/"))
            || name.contains("->0x");

        let is_network = type_upper == "IPV4"
            || type_upper == "IPV6"
            || type_upper == "INET"
            || type_upper == "INET6"
            || proto_upper == "TCP"
            || proto_upper == "UDP"
            || (name.contains("->") && (name.contains(':') || name.contains('.')))
            || (name.starts_with('*') && name.contains(':'))
            || (name.contains(':') && !name.starts_with('/'));

        if is_network {
            let proto_prefix = if !proto_upper.is_empty() {
                proto_upper
            } else if name.contains("UDP") || type_upper.contains("UDP") {
                "UDP".to_string()
            } else {
                "TCP".to_string()
            };

            let state_suffix = if let Some(state) = tcp_state {
                let clean = state
                    .strip_prefix("TST=")
                    .or_else(|| state.strip_prefix("ST="))
                    .unwrap_or(&state);
                format!(" ({})", clean)
            } else if !name.contains('(') && proto_prefix == "TCP" {
                if name.starts_with("*:") || name.contains(":*") || name.ends_with("(LISTEN)") {
                    " (LISTEN)".to_string()
                } else {
                    String::new()
                }
            } else {
                String::new()
            };

            let formatted = if name.starts_with("TCP ") || name.starts_with("UDP ") {
                format!("{}{}", name, state_suffix)
            } else {
                format!("{} {}{}", proto_prefix, name, state_suffix)
            };

            io.network_connections.push(formatted);
        } else if is_unix {
            io.unix_sockets.push(name);
        } else if name.starts_with('/') {
            if name.ends_with(" (deleted)") || name.contains(" (deleted)") {
                io.deleted_files.push(DeletedFile {
                    path: name.clone(),
                    size_bytes: 0,
                });
            }
            io.open_files.push(name);
        }
    };

    let mut is_field_format = false;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let first_char = trimmed.chars().next().unwrap_or_default();
        if matches!(first_char, 'p' | 'f' | 't' | 'P' | 'T' | 'n') && !trimmed.contains("  ") {
            is_field_format = true;
            let tag = first_char;
            let val = &trimmed[1..];
            match tag {
                'p' => {
                    commit_record(&mut current, &mut io);
                }
                'f' => {
                    commit_record(&mut current, &mut io);
                }
                't' => current.fd_type = Some(val.to_string()),
                'P' => current.protocol = Some(val.to_string()),
                'T' => {
                    if val.starts_with("ST=") || val.starts_with("TST=") {
                        current.tcp_state = Some(val.to_string());
                    }
                }
                'n' => current.name = Some(val.to_string()),
                _ => {}
            }
        } else if !is_field_format {
            // Tabular format parsing: e.g. "proc 123 user 3u IPv4 0x123 0t0 TCP *:8080 (LISTEN)"
            // Skip header line
            if trimmed.starts_with("COMMAND") && trimmed.contains("PID") {
                continue;
            }
            let cols: Vec<&str> = trimmed.split_whitespace().collect();
            if cols.len() >= 5 {
                let mut rec = LsofFdRecord::default();
                for &col in &cols {
                    let col_upper = col.to_uppercase();
                    if col_upper == "IPV4"
                        || col_upper == "IPV6"
                        || col_upper == "INET"
                        || col_upper == "INET6"
                        || col_upper == "UNIX"
                        || col_upper == "REG"
                        || col_upper == "DIR"
                        || col_upper == "CHR"
                    {
                        rec.fd_type = Some(col.to_string());
                    }
                    if col_upper == "TCP" || col_upper == "UDP" {
                        rec.protocol = Some(col.to_string());
                    }
                }

                if let Some(type_idx) = cols.iter().position(|&c| {
                    let u = c.to_uppercase();
                    u == "IPV4"
                        || u == "IPV6"
                        || u == "INET"
                        || u == "INET6"
                        || u == "UNIX"
                        || u == "REG"
                        || u == "DIR"
                        || u == "CHR"
                }) {
                    let remaining = &cols[type_idx + 1..];
                    if let Some(start_idx) = remaining.iter().position(|&tok| {
                        tok.starts_with('/')
                            || tok.starts_with("->")
                            || tok.starts_with('*')
                            || tok.starts_with('[')
                            || tok.eq_ignore_ascii_case("TCP")
                            || tok.eq_ignore_ascii_case("UDP")
                            || (tok.contains(':') && !tok.starts_with("0x"))
                    }) {
                        let full_name = remaining[start_idx..].join(" ");
                        rec.name = Some(full_name);
                        commit_record(&mut rec, &mut io);
                    } else if let Some(&last) = remaining.last() {
                        rec.name = Some(last.to_string());
                        commit_record(&mut rec, &mut io);
                    }
                }
            }
        }
    }
    commit_record(&mut current, &mut io);

    io.open_files.sort();
    io.open_files.dedup();
    io.unix_sockets.sort();
    io.unix_sockets.dedup();
    io.network_connections.sort();
    io.network_connections.dedup();

    io
}

#[cfg(target_os = "linux")]
pub fn get_fd_count(pid: u32) -> usize {
    std::fs::read_dir(format!("/proc/{}/fd", pid))
        .map(|entries| entries.count())
        .unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
pub fn get_fd_count(_pid: u32) -> usize {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_lsof_field_format() {
        let sample = "\
p1234
f3
tIPv4
PTCP
TST=LISTEN
n*:8080
f4
tIPv4
PTCP
TST=ESTABLISHED
n192.168.1.50:50000->93.184.216.34:443
f5
tunix
n/run/user/1000/systemd/private
f6
tREG
n/var/log/syslog
";
        let io = parse_lsof_output(sample);
        assert_eq!(io.network_connections.len(), 2);
        assert!(io.network_connections.iter().any(|c| c.contains("LISTEN") && c.contains("8080")));
        assert!(io.network_connections.iter().any(|c| c.contains("ESTABLISHED")));
        assert_eq!(io.unix_sockets.len(), 1);
        assert_eq!(io.unix_sockets[0], "/run/user/1000/systemd/private");
        assert_eq!(io.open_files.len(), 1);
        assert_eq!(io.open_files[0], "/var/log/syslog");
    }

    #[test]
    fn test_parse_lsof_tabular_format() {
        let sample = "\
COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
node     1234  app    3u  IPv4  0x123      0t0  TCP *:3000 (LISTEN)
node     1234  app    4u  unix  0x456      0t0      /tmp/node.sock
node     1234  app    5r   REG    8,1     1024  123 /srv/app/index.js
";
        let io = parse_lsof_output(sample);
        assert_eq!(io.network_connections.len(), 1);
        assert!(io.network_connections[0].contains("3000"));
        assert_eq!(io.unix_sockets.len(), 1);
        assert_eq!(io.unix_sockets[0], "/tmp/node.sock");
        assert_eq!(io.open_files.len(), 1);
        assert_eq!(io.open_files[0], "/srv/app/index.js");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_linux_live_socket_and_file_detection() {
        let self_pid = std::process::id();
        let io = get_process_io(self_pid);
        // The test process itself has stdin/stdout/stderr open at minimum
        assert!(
            !io.open_files.is_empty() || !io.unix_sockets.is_empty() || !io.network_connections.is_empty(),
            "Self-process must have at least one open file descriptor visible"
        );
    }

    // ── format_bytes ──────────────────────────────────────────────────────

    #[test]
    fn test_format_bytes_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1023), "1023 B");
    }

    #[test]
    fn test_format_bytes_kilobytes() {
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
    }

    #[test]
    fn test_format_bytes_megabytes() {
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_bytes(10 * 1024 * 1024), "10.0 MB");
    }

    #[test]
    fn test_format_bytes_gigabytes() {
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GB");
        assert_eq!(format_bytes(4 * 1024 * 1024 * 1024), "4.0 GB");
    }

    // ── format_bytes_rate ─────────────────────────────────────────────────

    #[test]
    fn test_format_bytes_rate_zero() {
        assert_eq!(format_bytes_rate(0.0), "0 B/s");
    }

    #[test]
    fn test_format_bytes_rate_kilobytes() {
        assert_eq!(format_bytes_rate(2048.0), "2.0 KB/s");
    }

    #[test]
    fn test_format_bytes_rate_megabytes() {
        assert_eq!(format_bytes_rate(5.0 * 1024.0 * 1024.0), "5.0 MB/s");
    }

    #[test]
    fn test_format_bytes_rate_gigabytes() {
        assert_eq!(format_bytes_rate(2.0 * 1024.0 * 1024.0 * 1024.0), "2.00 GB/s");
    }

    // ── DiskIoRate::calculate ─────────────────────────────────────────────

    #[test]
    fn test_disk_io_rate_calculate_normal_delta() {
        let start = Some(DiskIoStats { read_bytes: 0, write_bytes: 0 });
        let end = Some(DiskIoStats { read_bytes: 1024, write_bytes: 512 });
        let rate = DiskIoRate::calculate(start, end, 1.0).unwrap();
        assert!((rate.read_bytes_per_sec - 1024.0).abs() < 0.01);
        assert!((rate.write_bytes_per_sec - 512.0).abs() < 0.01);
    }

    #[test]
    fn test_disk_io_rate_calculate_zero_duration_returns_none() {
        let start = Some(DiskIoStats { read_bytes: 0, write_bytes: 0 });
        let end = Some(DiskIoStats { read_bytes: 1024, write_bytes: 0 });
        assert!(DiskIoRate::calculate(start, end, 0.0).is_none(),
            "Zero duration must return None to avoid divide-by-zero");
    }

    #[test]
    fn test_disk_io_rate_calculate_saturating_sub_on_counter_wrap() {
        // If end < start (counter reset / wraparound), saturating_sub gives 0
        let start = Some(DiskIoStats { read_bytes: 1000, write_bytes: 500 });
        let end = Some(DiskIoStats { read_bytes: 100, write_bytes: 50 });
        let rate = DiskIoRate::calculate(start, end, 1.0).unwrap();
        assert_eq!(rate.read_bytes_per_sec, 0.0, "Counter wrap must produce 0 read rate");
        assert_eq!(rate.write_bytes_per_sec, 0.0, "Counter wrap must produce 0 write rate");
    }

    #[test]
    fn test_disk_io_rate_calculate_none_start_returns_none() {
        let end = Some(DiskIoStats { read_bytes: 1024, write_bytes: 0 });
        assert!(DiskIoRate::calculate(None, end, 1.0).is_none());
    }

    #[test]
    fn test_disk_io_rate_calculate_none_end_returns_none() {
        let start = Some(DiskIoStats { read_bytes: 0, write_bytes: 0 });
        assert!(DiskIoRate::calculate(start, None, 1.0).is_none());
    }

    // ── parse_lsof_output — edge cases ───────────────────────────────────

    #[test]
    fn test_parse_lsof_deleted_file_is_classified() {
        let sample = "\
p1234
f5
tREG
n/var/log/app.log (deleted)
";
        let io = parse_lsof_output(sample);
        assert!(io.open_files.iter().any(|f| f.contains("deleted")),
            "Deleted file must appear in open_files");
        assert!(io.deleted_files.iter().any(|d| d.path.contains("deleted")),
            "Deleted file must appear in deleted_files");
    }

    #[test]
    fn test_parse_lsof_udp_socket() {
        let sample = "\
p1234
f3
tIPv4
PUDP
n0.0.0.0:53
";
        let io = parse_lsof_output(sample);
        assert!(io.network_connections.iter().any(|c| c.contains("UDP") && c.contains("53")),
            "UDP socket must be classified as a network connection: {:?}", io.network_connections);
    }

    #[test]
    fn test_parse_lsof_empty_input() {
        let io = parse_lsof_output("");
        assert!(io.open_files.is_empty());
        assert!(io.unix_sockets.is_empty());
        assert!(io.network_connections.is_empty());
    }

    #[test]
    fn test_parse_lsof_deduplicates_entries() {
        // Same file appearing under multiple fds must be deduplicated
        let sample = "\
p1234
f3
tREG
n/etc/hosts
f4
tREG
n/etc/hosts
";
        let io = parse_lsof_output(sample);
        assert_eq!(io.open_files.iter().filter(|f| f.as_str() == "/etc/hosts").count(), 1,
            "Duplicate open file entries must be deduplicated");
    }
}
