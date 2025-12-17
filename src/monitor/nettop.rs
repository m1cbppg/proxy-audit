use anyhow::{Context, Result};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::Instant;

/// 流量数据快照
#[derive(Debug, Clone)]
pub struct TrafficSnapshot {
    pub timestamp: Instant,
    pub processes: HashMap<i32, ProcessTraffic>,
}

/// 单个进程的流量数据
#[derive(Debug, Clone)]
pub struct ProcessTraffic {
    pub pid: i32,
    pub name: String,
    pub interface: String,
    pub state: String,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
}

/// Nettop 收集器
pub struct NettopCollector {
    // 能够控制子进程，例如杀死它
    child: Option<std::process::Child>,
}

impl NettopCollector {
    pub fn new() -> Self {
        Self { child: None }
    }

    /// 启动 nettop 进程并返回一个迭代器，该迭代器会不断产生 TrafficSnapshot
    pub fn start(&mut self) -> Result<impl Iterator<Item = Result<String>>> {
        // 命令: sudo nettop -L 0 -P -x
        // 移除 -J 参数，因为会导致 exit status 64
        let child = Command::new("script")
            .args([
                "-q",
                "/dev/null",
                "nettop",
                "-L",
                "0",  // Line buffered / Continuous
                "-P", // Collapse rows by process
                "-x", // Extended format
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null()) // Ignore stderr
            .spawn()
            .context("Failed to spawn nettop")?;

        self.child = Some(child);
        let stdout = self
            .child
            .as_mut()
            .unwrap()
            .stdout
            .take()
            .context("Failed to open stdout")?;
        let reader = BufReader::new(stdout);

        Ok(NettopIterator { reader })
    }
}

impl Drop for NettopCollector {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// 迭代器：逐块解析 nettop 输出
pub struct NettopIterator<R> {
    reader: BufReader<R>,
}

impl<R: std::io::Read> Iterator for NettopIterator<R> {
    type Item = Result<String>; // 临时返回行字符串，待解析逻辑完善

    fn next(&mut self) -> Option<Self::Item> {
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => None, // EOF
            Ok(_) => {
                let trimmed = line.trim().to_string();
                if trimmed.is_empty() {
                    return self.next();
                }
                Some(Ok(trimmed))
            }
            Err(e) => Some(Err(anyhow::anyhow!(e))),
        }
    }
}

pub fn parse_nettop_csv_line(line: &str) -> Option<ProcessTraffic> {
    // 实际 macOS 12+ nettop -L 0 -P -x 输出格式:
    // time,,interface,state,bytes_in,bytes_out,...
    // 17:52:31.561358,syslogd.342,,,0,715,...

    // 忽略 Header
    if line.starts_with("time,") {
        return None;
    }

    let parts: Vec<&str> = line.split(',').collect();
    if parts.len() < 6 {
        return None;
    }

    // Col 1: name.pid (e.g., "syslogd.342", "Google Chrome H.97817")
    let name_pid_raw = parts[1];
    if name_pid_raw.is_empty() {
        return None;
    }

    // 解析 "name.pid"，注意 name 中可能包含 "."，所以取最后一个 "." 分隔
    let (name, pid) = match name_pid_raw.rsplit_once('.') {
        Some((n, p)) => {
            let pid_val = p.parse().unwrap_or(0);
            (n.to_string(), pid_val)
        }
        None => (name_pid_raw.to_string(), 0),
    };

    if pid == 0 {
        return None;
    }

    // Col 2: interface (可能为空)
    let interface = parts[2].to_string();

    // Col 3: state (可能为空)
    let state = parts[3].to_string();

    // Helper to parse u64
    let parse_bytes = |s: &str| -> u64 { s.parse().unwrap_or(0) };

    // Col 4: bytes_in
    let total_bytes_in = parse_bytes(parts[4]);

    // Col 5: bytes_out
    let total_bytes_out = parse_bytes(parts[5]);

    Some(ProcessTraffic {
        pid,
        name,
        interface,
        state,
        total_bytes_in,
        total_bytes_out,
    })
}
