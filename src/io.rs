use serde::Serialize;
use std::collections::HashSet;
use std::fs;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessIo {
    pub open_files: Vec<String>,
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

#[cfg(target_os = "linux")]
fn format_unix_socket_type(socket_type: u16) -> &'static str {
    match socket_type {
        1 => "STREAM",
        2 => "DGRAM",
        3 => "RAW",
        4 => "RDM",
        5 => "SEQPACKET",
        _ => "UNIX",
    }
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

#[cfg(target_os = "macos")]
pub fn get_process_io(pid: u32) -> ProcessIo {
    use std::process::Command;

    let output = Command::new("lsof")
        .arg("-n")
        .arg("-P")
        .arg("-p")
        .arg(pid.to_string())
        .arg("-F")
        .arg("ftTnpP")
        .output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_lsof_output(&stdout)
    } else {
        ProcessIo::default()
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn get_process_io(_pid: u32) -> ProcessIo {
    ProcessIo::default()
}

#[allow(dead_code)]
#[derive(Default, Debug)]
struct LsofFdRecord {
    fd_type: Option<String>,
    protocol: Option<String>,
    tcp_state: Option<String>,
    name: Option<String>,
}

/// Parses machine-readable (`lsof -F`) or standard tabular output from `lsof`.
#[allow(dead_code)]
pub fn parse_lsof_output(stdout: &str) -> ProcessIo {

    let mut io = ProcessIo::default();
    let mut current = LsofFdRecord::default();

    let commit_record = |record: &mut LsofFdRecord, io: &mut ProcessIo| {
        let name = match record.name.take() {
            Some(n) if !n.trim().is_empty() => n.trim().to_string(),
            _ => return,
        };
        let fd_type = record.fd_type.take().unwrap_or_default();
        let protocol = record.protocol.take().unwrap_or_default();
        let tcp_state = record.tcp_state.take();

        let type_upper = fd_type.to_uppercase();
        let proto_upper = protocol.to_uppercase();

        let is_unix = type_upper == "UNIX"
            || name.starts_with("->0x")
            || (name.starts_with('/') && type_upper == "UNIX");

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_lsof_field_format() {
        let sample = r#"
p1234
f0
tCHR
n/dev/null
f1
tREG
n/Users/alice/app.log
f3
tIPv4
PTCP
TST=LISTEN
n*:8080
f4
tIPv4
PTCP
TST=ESTABLISHED
n192.168.1.50:54321->93.184.216.34:443
f5
tIPv6
PUDP
n*:5353
f6
tunix
n/var/run/mDNSResponder
f7
tunix
n->0x1234abcd
"#;

        let io = parse_lsof_output(sample);

        assert_eq!(
            io.open_files,
            vec!["/Users/alice/app.log".to_string(), "/dev/null".to_string()]
        );
        assert_eq!(
            io.unix_sockets,
            vec!["->0x1234abcd".to_string(), "/var/run/mDNSResponder".to_string()]
        );
        assert_eq!(
            io.network_connections,
            vec![
                "TCP *:8080 (LISTEN)".to_string(),
                "TCP 192.168.1.50:54321->93.184.216.34:443 (ESTABLISHED)".to_string(),
                "UDP *:5353".to_string(),
            ]
        );

    }

    #[test]
    fn test_parse_lsof_tabular_format() {
        let sample = r#"
COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
app      1234 user  cwd    DIR    1,4      128  100 /Users/user/project
app      1234 user  txt    REG    1,4    45678  101 /usr/local/bin/app
app      1234 user    0r   CHR    3,2      0t0  102 /dev/null
app      1234 user    3u  IPv4 0x1000      0t0  TCP *:8080 (LISTEN)
app      1234 user    4u  IPv4 0x2000      0t0  TCP 192.168.1.50:54321->93.184.216.34:443 (ESTABLISHED)
app      1234 user    5u  IPv6 0x3000      0t0  UDP *:5353
app      1234 user    6u  unix 0x4000      0t0      /var/run/usbmuxd
app      1234 user    7u  unix 0x5000      0t0      ->0x6000
"#;

        let io = parse_lsof_output(sample);

        assert!(io.open_files.contains(&"/dev/null".to_string()));
        assert!(io.open_files.contains(&"/Users/user/project".to_string()));
        assert!(io.open_files.contains(&"/usr/local/bin/app".to_string()));
        assert!(io.unix_sockets.contains(&"/var/run/usbmuxd".to_string()));
        assert!(io.unix_sockets.contains(&"->0x6000".to_string()));
        assert!(io.network_connections.iter().any(|c| c.contains("8080")));
        assert!(io.network_connections.iter().any(|c| c.contains("54321")));
        assert!(io.network_connections.iter().any(|c| c.contains("5353")));
    }


    #[cfg(target_os = "linux")]
    #[test]
    fn test_linux_live_socket_and_file_detection() {
        use std::io::Write;
        use std::net::{TcpListener, UdpSocket};
        use std::os::unix::net::UnixListener;

        let temp_path = std::env::temp_dir().join(format!("procwhy_io_test_{}.tmp", std::process::id()));
        let mut file = fs::File::create(&temp_path).unwrap();
        writeln!(file, "hello procwhy").unwrap();

        let tcp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp_port = tcp_listener.local_addr().unwrap().port();

        let udp_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_port = udp_socket.local_addr().unwrap().port();

        let unix_path = format!("/tmp/procwhy_unix_test_{}.sock", std::process::id());
        let _ = fs::remove_file(&unix_path);
        let _unix_listener = UnixListener::bind(&unix_path).unwrap();

        let pid = std::process::id();
        let io = get_process_io(pid);

        // Verify open files contain the temp file
        let temp_path_str = temp_path.to_string_lossy().to_string();
        assert!(
            io.open_files.contains(&temp_path_str),
            "Expected open files {:?} to contain {:?}",
            io.open_files,
            temp_path_str
        );

        // Verify TCP listener was detected
        assert!(
            io.network_connections
                .iter()
                .any(|c| c.contains(&format!(":{}", tcp_port)) && c.contains("LISTEN")),
            "Expected network connections {:?} to contain TCP port {}",
            io.network_connections,
            tcp_port
        );

        // Verify UDP socket was detected
        assert!(
            io.network_connections
                .iter()
                .any(|c| c.contains(&format!(":{}", udp_port)) && c.starts_with("UDP")),
            "Expected network connections {:?} to contain UDP port {}",
            io.network_connections,
            udp_port
        );

        // Verify UNIX socket was detected
        assert!(
            io.unix_sockets.contains(&unix_path),
            "Expected unix sockets {:?} to contain {:?}",
            io.unix_sockets,
            unix_path
        );

        let _ = fs::remove_file(&unix_path);
        let _ = fs::remove_file(&temp_path);
    }
}
