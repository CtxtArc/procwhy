mod finder;
mod heuristics;
mod io;

use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use finder::{parse_target_query, resolve_pid, TargetQuery};
use heuristics::{analyze_snapshot, redact_env_var, ProcessSnapshot, Severity};
use io::{format_bytes_rate, get_disk_io, get_process_io, get_wchan, DiskIoRate};
use std::fmt::Write as _;
use std::io::IsTerminal;
use std::thread;
use std::time::{Duration, Instant};
use sysinfo::{Pid, System};

#[derive(Parser)]
#[command(author, version, about = "Why is my process doing this?")]
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

    /// Do not pipe output into a pager (e.g. less)
    #[arg(long)]
    no_pager: bool,
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

    let mut out = String::new();

    let header_suffix = match &query {
        TargetQuery::Port(p) => format!(" {}", format!("(port :{})", p).dimmed()),
        TargetQuery::Name(n) if n != process.name() => {
            format!(" {}", format!("(matched '{}')", n).dimmed())
        }
        _ => String::new(),
    };

    writeln!(
        out,
        "\n{} {}{}  {}",
        "PID".bold(),
        target_pid,
        header_suffix,
        display_cmd.green()
    )?;

    // Verdict section
    writeln!(out, "\n{}", "VERDICT".bold().blue())?;
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
                        finding.category.red(),
                        finding.message.bold()
                    )?;
                }
                Severity::Warning => {
                    writeln!(
                        out,
                        "  {} [{}] {}",
                        "WARN:".yellow().bold(),
                        finding.category.yellow(),
                        finding.message
                    )?;
                }
                Severity::Info => {
                    writeln!(
                        out,
                        "  {} [{}] {}",
                        "INFO:".cyan().bold(),
                        finding.category.cyan(),
                        finding.message
                    )?;
                }
            }
            if let Some(ref rec) = finding.recommendation {
                writeln!(out, "    {}", format!("Hint: {}", rec).dimmed())?;
            }
        }
    }

    // Stats section
    writeln!(out, "\n{}", "STATS".bold().blue())?;
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

    // --- ENVIRONMENT ---
    let env_vars = process.environ();
    let env_title = if cli.all && env_vars.len() > 5 {
        format!("ENVIRONMENT (All {})", env_vars.len())
    } else if env_vars.len() > 5 {
        "ENVIRONMENT (Top 5)".to_string()
    } else {
        "ENVIRONMENT".to_string()
    };
    writeln!(out, "\n{}", env_title.bold().blue())?;

    if env_vars.is_empty() {
        writeln!(out, "  {}", "None detected (or permission denied)".dimmed())?;
    } else if cli.all {
        for env in env_vars {
            let redacted = redact_env_var(env);
            writeln!(out, "  {}", redacted.dimmed())?;
        }
    } else {
        for env in env_vars.iter().take(5) {
            let redacted = redact_env_var(env);
            writeln!(out, "  {}", redacted.dimmed())?;
        }
        if env_vars.len() > 5 {
            writeln!(
                out,
                "  {}",
                format!("...and {} more", env_vars.len() - 5).dimmed()
            )?;
        }
    }

    // --- CHILDREN ---
    let child_title = if cli.all && children.len() > 5 {
        format!("CHILDREN (All {})", children.len())
    } else if children.len() > 5 {
        "CHILDREN (Top 5)".to_string()
    } else {
        "CHILDREN".to_string()
    };
    writeln!(out, "\n{}", child_title.bold().blue())?;

    if children.is_empty() {
        writeln!(out, "  {}", "None".dimmed())?;
    } else if cli.all {
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

    // --- NETWORK ---
    let net_title = if cli.all && io.network_connections.len() > 10 {
        format!("NETWORK (All {})", io.network_connections.len())
    } else {
        "NETWORK".to_string()
    };
    writeln!(out, "\n{}", net_title.bold().blue())?;

    if io.network_connections.is_empty() {
        writeln!(out, "  {}", "None".dimmed())?;
    } else if cli.all {
        for net in &io.network_connections {
            writeln!(out, "  → {}", net.yellow())?;
        }
    } else {
        for net in io.network_connections.iter().take(10) {
            writeln!(out, "  → {}", net.yellow())?;
        }
        if io.network_connections.len() > 10 {
            writeln!(
                out,
                "  {}",
                format!("...and {} more", io.network_connections.len() - 10).dimmed()
            )?;
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




