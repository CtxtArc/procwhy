mod finder;
mod heuristics;
mod io;

use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use finder::{parse_target_query, resolve_pid, TargetQuery};
use heuristics::{analyze_snapshot, generate_summary, redact_env_var, Health, ProcessSnapshot, Severity};
use io::{format_bytes_rate, get_disk_io, get_process_io, get_wchan, DiskIoRate};
use serde::Serialize;
use std::collections::HashSet;
use std::fmt::Write as _;
use std::io::IsTerminal;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use sysinfo::{Pid, System, Users};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(author, version, about = "Turn raw process telemetry into actionable process diagnoses")]
struct Cli {
    /// PID, process name (e.g. 'node'), or port (e.g. ':8080') to inspect
    #[arg(value_name = "TARGET")]
    target: Option<String>,

    /// Look up process by listening/connected port
    #[arg(short, long, value_name = "PORT")]
    port: Option<u16>,

    /// Show all files, sockets, children, and environment variables without truncation
    #[arg(short, long)]
    all: bool,

    /// Output full diagnostic report in structured JSON format
    #[arg(short, long)]
    json: bool,

    /// Do not pipe output into a pager (e.g. less)
    #[arg(long)]
    no_pager: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct JsonReport {
    pub procwhy_version: &'static str,
    pub pid: u32,
    pub name: String,
    pub cmd: Vec<String>,
    pub status: String,
    pub health: Health,
    pub summary: String,
    pub identity: JsonIdentity,
    pub ancestry: Vec<JsonAncestryNode>,
    pub diagnostics: Vec<heuristics::Finding>,
    pub resources: JsonResources,
    pub network: JsonNetwork,
    pub unix_sockets: Vec<String>,
    pub open_files: Vec<String>,
    pub children: Vec<JsonChild>,
    pub environment: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct JsonIdentity {
    pub binary: String,
    pub user: String,
    pub cwd: String,
    pub uptime_seconds: u64,
    pub uptime_human: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct JsonAncestryNode {
    pub pid: u32,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct JsonResources {
    pub cpu_usage_percent: f32,
    pub memory_bytes: u64,
    pub memory_mb: f64,
    pub memory_percent_system: Option<f64>,
    pub total_system_memory_bytes: u64,
    pub disk_io_rate: Option<DiskIoRate>,
    pub wchan: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct JsonNetwork {
    pub total_connections: usize,
    pub listeners: Vec<String>,
    pub outbound: Vec<String>,
    pub all_connections: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct JsonChild {
    pub pid: u32,
    pub name: String,
}

pub fn format_uptime_from_now(start_time_secs: u64, now_secs: u64) -> (u64, String) {
    if start_time_secs == 0 || now_secs < start_time_secs {
        return (0, "unknown".to_string());
    }

    let elapsed = now_secs - start_time_secs;
    let days = elapsed / 86400;
    let hours = (elapsed % 86400) / 3600;
    let mins = (elapsed % 3600) / 60;
    let secs = elapsed % 60;

    let human = if days > 0 {
        format!("{}d {}h {}m", days, hours, mins)
    } else if hours > 0 {
        format!("{}h {}m", hours, mins)
    } else if mins > 0 {
        format!("{}m {}s", mins, secs)
    } else {
        format!("{}s", secs)
    };

    (elapsed, human)
}

pub fn format_uptime(start_time_secs: u64) -> (u64, String) {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_uptime_from_now(start_time_secs, now_secs)
}

pub fn build_process_ancestry(pid: Pid, sys: &System) -> Vec<JsonAncestryNode> {
    let mut lineage = Vec::new();
    let mut current_pid = Some(pid);
    let mut visited = HashSet::new();

    while let Some(p) = current_pid {
        if !visited.insert(p) {
            break;
        }
        if let Some(proc) = sys.process(p) {
            lineage.push(JsonAncestryNode {
                pid: p.as_u32(),
                name: proc.name().to_string(),
            });
            current_pid = proc.parent();
        } else {
            break;
        }
    }

    lineage.reverse();
    lineage
}

pub fn get_process_cwd(pid: u32, proc_cwd: Option<&std::path::Path>) -> String {
    if let Some(cwd) = proc_cwd {
        let s = cwd.to_string_lossy().to_string();
        if !s.is_empty() {
            return s;
        }
    }
    #[cfg(target_os = "linux")]
    if let Ok(link) = std::fs::read_link(format!("/proc/{}/cwd", pid)) {
        return link.to_string_lossy().to_string();
    }
    "unknown".to_string()
}

pub fn get_process_user(pid: u32, proc_uid: Option<&sysinfo::Uid>, users: &Users) -> String {
    let mut uid_num = proc_uid.and_then(|u| u.to_string().parse::<u32>().ok());

    #[cfg(target_os = "linux")]
    if uid_num.is_none() {
        if let Ok(status) = std::fs::read_to_string(format!("/proc/{}/status", pid)) {
            for line in status.lines() {
                if line.starts_with("Uid:") {
                    if let Some(u) = line.split_whitespace().nth(1).and_then(|s| s.parse::<u32>().ok()) {
                        uid_num = Some(u);
                        break;
                    }
                }
            }
        }
    }

    if let Some(uid) = uid_num {
        if let Some(user) = users.iter().find(|u| u.id().to_string() == uid.to_string()) {
            return format!("{} (UID {})", user.name(), uid);
        }
        if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
            for line in passwd.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 3 && parts[2] == uid.to_string() {
                    return format!("{} (UID {})", parts[0], uid);
                }
            }
        }
        return format!("UID {}", uid);
    }

    "unknown".to_string()
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let query = parse_target_query(cli.target.as_deref(), cli.port)?;

    let mut sys = System::new();
    sys.refresh_processes();
    sys.refresh_memory();

    let target_pid = resolve_pid(&query, &sys)?;
    let pid = Pid::from_u32(target_pid);

    // Initial snapshot for CPU & disk I/O delta
    let disk_t0 = get_disk_io(target_pid);
    let time_t0 = Instant::now();

    // Sample delta over 200ms window
    thread::sleep(Duration::from_millis(200));
    sys.refresh_processes();

    let disk_t1 = get_disk_io(target_pid);
    let time_t1 = Instant::now();
    let delta_secs = time_t1.duration_since(time_t0).as_secs_f64();
    let disk_rate = DiskIoRate::calculate(disk_t0, disk_t1, delta_secs);

    let process = sys
        .process(pid)
        .context("PID not found or terminated during inspection.")?;

    let cmd_vec = process.cmd().to_vec();
    let cmd = cmd_vec.join(" ");
    let display_cmd = if cmd.is_empty() {
        process.name().to_string()
    } else {
        cmd
    };

    let io = get_process_io(target_pid);
    let wchan = get_wchan(target_pid);

    let children: Vec<_> = sys
        .processes()
        .values()
        .filter(|p| p.parent() == Some(pid))
        .collect();

    let total_memory = sys.total_memory();
    let snapshot = ProcessSnapshot {
        pid: target_pid,
        name: process.name(),
        cmd: &cmd_vec,
        cpu_usage: process.cpu_usage(),
        memory_bytes: process.memory(),
        total_system_memory_bytes: total_memory,
        status: process.status(),
        parent_pid: process.parent().map(|p| p.as_u32()),
        children_count: children.len(),
        io: &io,
        disk_io_rate: disk_rate,
        wchan: wchan.as_deref(),
    };
    let findings = analyze_snapshot(&snapshot);
    let health = Health::from_findings(&findings);
    let summary = generate_summary(&findings);

    // Identity metadata
    let users = Users::new_with_refreshed_list();
    let user_str = get_process_user(target_pid, process.user_id(), &users);
    let cwd_str = get_process_cwd(target_pid, process.cwd());
    let exe_str = process
        .exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| display_cmd.clone());

    let (uptime_secs, uptime_human) = format_uptime(process.start_time());
    let ancestry = build_process_ancestry(pid, &sys);

    // Categorize network connections
    let mut listeners = Vec::new();
    let mut outbound = Vec::new();
    for conn in &io.network_connections {
        if conn.contains("LISTEN") {
            listeners.push(conn.clone());
        } else {
            outbound.push(conn.clone());
        }
    }

    // JSON Output Mode
    if cli.json {
        let env_redacted: Vec<String> = process
            .environ()
            .iter()
            .map(|e| redact_env_var(e))
            .collect();

        let children_json: Vec<JsonChild> = children
            .iter()
            .map(|c| JsonChild {
                pid: c.pid().as_u32(),
                name: c.name().to_string(),
            })
            .collect();

        let memory_mb = process.memory() as f64 / 1024.0 / 1024.0;
        let mem_pct = if total_memory > 0 {
            Some((process.memory() as f64 / total_memory as f64) * 100.0)
        } else {
            None
        };

        let report = JsonReport {
            procwhy_version: VERSION,
            pid: target_pid,
            name: process.name().to_string(),
            cmd: cmd_vec,
            status: format!("{:?}", process.status()),
            health,
            summary,
            identity: JsonIdentity {
                binary: exe_str,
                user: user_str,
                cwd: cwd_str,
                uptime_seconds: uptime_secs,
                uptime_human,
            },
            ancestry,
            diagnostics: findings,
            resources: JsonResources {
                cpu_usage_percent: process.cpu_usage(),
                memory_bytes: process.memory(),
                memory_mb,
                memory_percent_system: mem_pct,
                total_system_memory_bytes: total_memory,
                disk_io_rate: disk_rate,
                wchan,
            },
            network: JsonNetwork {
                total_connections: io.network_connections.len(),
                listeners,
                outbound,
                all_connections: io.network_connections,
            },
            unix_sockets: io.unix_sockets,
            open_files: io.open_files,
            children: children_json,
            environment: env_redacted,
        };

        let json_str = serde_json::to_string_pretty(&report)?;
        println!("{}", json_str);
        return Ok(());
    }

    let mut out = String::new();

    let header_suffix = match &query {
        TargetQuery::Port(p) => format!(" {}", format!("(port :{})", p).dimmed()),
        TargetQuery::Name(n) if n != process.name() => {
            format!(" {}", format!("(matched '{}')", n).dimmed())
        }
        _ => String::new(),
    };

    writeln!(out, "\n{} {}", "procwhy".bold().dimmed(), VERSION.dimmed())?;
    writeln!(
        out,
        "\n{} {}{}  {}",
        process.name().bold().green(),
        format!("(PID {})", target_pid).dimmed(),
        header_suffix,
        display_cmd.dimmed()
    )?;
    writeln!(out, "{}", "────────────────────────────────────────────────────────────".dimmed())?;

    // --- HEALTH ---
    let health_str = match health {
        Health::Critical => "CRITICAL".red().bold(),
        Health::Warning => "WARN".yellow().bold(),
        Health::Info => "INFO".cyan().bold(),
        Health::Ok => "OK".green().bold(),
    };
    writeln!(out, "\n{:<12} {}", "HEALTH".bold().blue(), health_str)?;

    // --- IDENTITY ---
    writeln!(out, "\n{}", "IDENTITY".bold().blue())?;
    writeln!(out, "  Binary     {}", exe_str)?;
    writeln!(out, "  User       {}", user_str)?;
    writeln!(out, "  CWD        {}", cwd_str)?;
    writeln!(out, "  Uptime     {}", uptime_human)?;

    // --- ANCESTRY ---
    if !ancestry.is_empty() {
        writeln!(out, "\n{}", "ANCESTRY".bold().blue())?;
        let tree_str = ancestry
            .iter()
            .map(|node| {
                if node.pid == target_pid {
                    format!("{} ({})", node.name.green().bold(), node.pid.to_string().bold())
                } else {
                    format!("{} ({})", node.name.dimmed(), node.pid.to_string().dimmed())
                }
            })
            .collect::<Vec<_>>()
            .join(" ─> ");
        writeln!(out, "  {}", tree_str)?;
    }

    // --- RESOURCES ---
    writeln!(out, "\n{}", "RESOURCES".bold().blue())?;
    writeln!(out, "  CPU        {:.1}%", process.cpu_usage())?;

    let memory_mb = process.memory() as f64 / 1024.0 / 1024.0;
    if total_memory > 0 {
        let mem_pct = (process.memory() as f64 / total_memory as f64) * 100.0;
        let total_gb = total_memory as f64 / 1024.0 / 1024.0 / 1024.0;
        writeln!(
            out,
            "  Memory     {:.1} MB ({:.1}% of {:.1} GB)",
            memory_mb, mem_pct, total_gb
        )?;
    } else {
        writeln!(out, "  Memory     {:.1} MB", memory_mb)?;
    }

    if let Some(rate) = disk_rate {
        let read_str = format_bytes_rate(rate.read_bytes_per_sec);
        let write_str = format_bytes_rate(rate.write_bytes_per_sec);
        if rate.read_bytes_per_sec == 0.0 && rate.write_bytes_per_sec == 0.0 {
            writeln!(out, "  Disk I/O   0 B/s")?;
        } else {
            writeln!(out, "  Disk I/O   {} Read, {} Write", read_str, write_str)?;
        }
    }

    writeln!(out, "  Status     {:?}", process.status())?;
    if let Some(ref chan) = wchan {
        writeln!(out, "  Wait Chan  {}", chan.dimmed())?;
    }

    // --- DIAGNOSTICS ---
    writeln!(out, "\n{}", "DIAGNOSTICS".bold().blue())?;
    if findings.is_empty() {
        writeln!(
            out,
            "  {}",
            "No anomalies detected.".green()
        )?;
    } else {
        for finding in &findings {
            match finding.severity {
                Severity::Critical => {
                    writeln!(
                        out,
                        "  {} [{}] {}",
                        "CRITICAL:".red().bold(),
                        finding.category.red().bold(),
                        finding.message.bold()
                    )?;
                }
                Severity::Warning => {
                    writeln!(
                        out,
                        "  {} [{}] {}",
                        "WARN:".yellow().bold(),
                        finding.category.yellow().bold(),
                        finding.message
                    )?;
                }
                Severity::Info => {
                    writeln!(
                        out,
                        "  {} [{}] {}",
                        "INFO:".cyan().bold(),
                        finding.category.cyan().bold(),
                        finding.message
                    )?;
                }
            }
            if let Some(ref rec) = finding.recommendation {
                writeln!(out, "    {}", format!("Hint: {}", rec).dimmed())?;
            }
        }
    }

    // --- SUMMARY ---
    writeln!(out, "\n{}", "SUMMARY".bold().blue())?;
    writeln!(out, "  {}", summary)?;

    // --- NETWORK ---
    let net_title = if cli.all && io.network_connections.len() > 10 {
        format!("NETWORK (All {})", io.network_connections.len())
    } else {
        "NETWORK".to_string()
    };
    writeln!(out, "\n{}", net_title.bold().blue())?;

    if io.network_connections.is_empty() {
        writeln!(out, "  {}", "None".dimmed())?;
    } else {
        if !listeners.is_empty() {
            for lis in &listeners {
                writeln!(out, "  LISTEN     {}", lis.yellow())?;
            }
        }
        if !outbound.is_empty() {
            let ext_count = outbound.iter().filter(|c| !c.contains("127.0.0.1") && !c.contains("[::1]")).count();
            writeln!(out, "  OUTBOUND   {} connections ({} external)", outbound.len(), ext_count)?;
        }
        if cli.all {
            for net in &io.network_connections {
                writeln!(out, "  → {}", net.yellow())?;
            }
        } else {
            for net in io.network_connections.iter().take(5) {
                writeln!(out, "  → {}", net.yellow())?;
            }
            if io.network_connections.len() > 5 {
                writeln!(
                    out,
                    "  {}",
                    format!("...and {} more", io.network_connections.len() - 5).dimmed()
                )?;
            }
        }
    }

    // --- UNIX SOCKETS ---
    let sock_title = if cli.all && io.unix_sockets.len() > 5 {
        format!("UNIX SOCKETS (All {})", io.unix_sockets.len())
    } else if io.unix_sockets.len() > 5 {
        "UNIX SOCKETS (Top 5)".to_string()
    } else {
        "UNIX SOCKETS".to_string()
    };
    writeln!(out, "\n{}", sock_title.bold().blue())?;

    if io.unix_sockets.is_empty() {
        writeln!(out, "  {}", "None".dimmed())?;
    } else if cli.all {
        for sock in &io.unix_sockets {
            writeln!(out, "  → {}", sock.cyan())?;
        }
    } else {
        for sock in io.unix_sockets.iter().take(5) {
            writeln!(out, "  → {}", sock.cyan())?;
        }
        if io.unix_sockets.len() > 5 {
            writeln!(
                out,
                "  {}",
                format!("...and {} more", io.unix_sockets.len() - 5).dimmed()
            )?;
        }
    }

    // --- FILES ---
    let file_title = if cli.all && io.open_files.len() > 5 {
        format!("FILES (All {})", io.open_files.len())
    } else if io.open_files.len() > 5 {
        "FILES (Top 5)".to_string()
    } else {
        "FILES".to_string()
    };
    writeln!(out, "\n{}", file_title.bold().blue())?;

    if io.open_files.is_empty() {
        writeln!(out, "  {}", "None (or permission denied)".dimmed())?;
    } else if cli.all {
        for file in &io.open_files {
            writeln!(out, "  {}", file)?;
        }
    } else {
        for file in io.open_files.iter().take(5) {
            writeln!(out, "  {}", file)?;
        }
        if io.open_files.len() > 5 {
            writeln!(
                out,
                "  {}",
                format!("...and {} more", io.open_files.len() - 5).dimmed()
            )?;
        }
    }

    // --- CHILDREN ---
    if !children.is_empty() {
        let child_title = if cli.all && children.len() > 5 {
            format!("CHILDREN (All {})", children.len())
        } else if children.len() > 5 {
            "CHILDREN (Top 5)".to_string()
        } else {
            "CHILDREN".to_string()
        };
        writeln!(out, "\n{}", child_title.bold().blue())?;

        if cli.all {
            for child in &children {
                writeln!(
                    out,
                    "  └─ {} {}",
                    child.name().dimmed(),
                    child.pid().to_string().bold()
                )?;
            }
        } else {
            for child in children.iter().take(5) {
                writeln!(
                    out,
                    "  └─ {} {}",
                    child.name().dimmed(),
                    child.pid().to_string().bold()
                )?;
            }
            if children.len() > 5 {
                writeln!(
                    out,
                    "  {}",
                    format!("...and {} more", children.len() - 5).dimmed()
                )?;
            }
        }
    }

    writeln!(out)?;

    // --- OUTPUT / PAGER DISPATCH ---
    print_output(&out, cli.no_pager)?;

    Ok(())
}

fn should_use_pager(no_pager: bool) -> bool {
    if no_pager {
        return false;
    }
    if std::env::var("PROCWY_NO_PAGER").is_ok() {
        return false;
    }
    if let Ok(pager) = std::env::var("PAGER") {
        if pager == "cat" || pager.trim().is_empty() {
            return false;
        }
    }
    if let Ok(term) = std::env::var("TERM") {
        if term == "dumb" {
            return false;
        }
    }
    std::io::stdout().is_terminal()
}

fn print_output(content: &str, no_pager: bool) -> Result<()> {
    if should_use_pager(no_pager) {
        let pager_cmd = std::env::var("PROCWY_PAGER")
            .or_else(|_| std::env::var("PAGER"))
            .unwrap_or_else(|_| "less".to_string());

        let mut cmd = if pager_cmd == "less" {
            let mut c = std::process::Command::new("less");
            c.arg("-FRX");
            c
        } else {
            let parts: Vec<&str> = pager_cmd.split_whitespace().collect();
            if parts.is_empty() {
                let mut c = std::process::Command::new("less");
                c.arg("-FRX");
                c
            } else {
                let mut c = std::process::Command::new(parts[0]);
                if parts.len() > 1 {
                    c.args(&parts[1..]);
                }
                c
            }
        };

        cmd.stdin(std::process::Stdio::piped());

        if let Ok(mut child) = cmd.spawn() {
            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write;
                let _ = stdin.write_all(content.as_bytes());
            }
            let _ = child.wait();
            return Ok(());
        }
    }

    use std::io::Write;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let _ = handle.write_all(content.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_uptime_seconds() {
        let (elapsed, human) = format_uptime_from_now(1000, 1045);
        assert_eq!(elapsed, 45);
        assert_eq!(human, "45s");
    }

    #[test]
    fn test_format_uptime_minutes() {
        let (elapsed, human) = format_uptime_from_now(1000, 1000 + 135);
        assert_eq!(elapsed, 135);
        assert_eq!(human, "2m 15s");
    }

    #[test]
    fn test_format_uptime_hours() {
        let (_elapsed, human) = format_uptime_from_now(1000, 1000 + 3600 * 3 + 1200);
        assert_eq!(human, "3h 20m");
    }

    #[test]
    fn test_format_uptime_days() {
        let (_elapsed, human) = format_uptime_from_now(1000, 1000 + 86400 * 2 + 3600 * 5 + 600);
        assert_eq!(human, "2d 5h 10m");
    }

    #[test]
    fn test_format_uptime_unknown_or_future() {
        let (_elapsed, human) = format_uptime_from_now(0, 1000);
        assert_eq!(human, "unknown");

        let (_, human_future) = format_uptime_from_now(2000, 1000);
        assert_eq!(human_future, "unknown");
    }


    #[test]
    fn test_json_report_serialization() {
        let report = JsonReport {
            procwhy_version: "1.0.0",
            pid: 1234,
            name: "test-service".to_string(),
            cmd: vec!["node".to_string(), "server.js".to_string()],
            status: "Running".to_string(),
            health: Health::Warning,
            summary: "Process is holding open file handles to deleted files.".to_string(),
            identity: JsonIdentity {
                binary: "/usr/bin/node".to_string(),
                user: "app (UID 1000)".to_string(),
                cwd: "/srv/app".to_string(),
                uptime_seconds: 7200,
                uptime_human: "2h 0m".to_string(),
            },
            ancestry: vec![
                JsonAncestryNode {
                    pid: 1,
                    name: "systemd".to_string(),
                },
                JsonAncestryNode {
                    pid: 1234,
                    name: "node".to_string(),
                },
            ],
            diagnostics: vec![heuristics::Finding {
                severity: Severity::Warning,
                category: "DELETED FILES",
                message: "1 open file handle points to deleted file".to_string(),
                recommendation: Some("Restart process".to_string()),
            }],
            resources: JsonResources {
                cpu_usage_percent: 15.5,
                memory_bytes: 104857600,
                memory_mb: 100.0,
                memory_percent_system: Some(2.5),
                total_system_memory_bytes: 4194304000,
                disk_io_rate: None,
                wchan: None,
            },
            network: JsonNetwork {
                total_connections: 1,
                listeners: vec!["TCP 0.0.0.0:8080".to_string()],
                outbound: vec![],
                all_connections: vec!["TCP 0.0.0.0:8080 (LISTEN)".to_string()],
            },
            unix_sockets: vec![],
            open_files: vec!["/srv/app/server.js".to_string()],
            children: vec![],
            environment: vec!["NODE_ENV=production".to_string()],
        };

        let json = serde_json::to_string_pretty(&report).expect("Serialization failed");
        assert!(json.contains("\"health\": \"warning\""));
        assert!(json.contains("\"name\": \"test-service\""));
        assert!(json.contains("\"binary\": \"/usr/bin/node\""));
    }
}
