use super::nettop::ProcessTraffic;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ProcessStats {
    pub pid: i32,
    pub name: String,
    pub interface: String,
    pub state: String,

    // Total bytes (accumulated from nettop)
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,

    // Calculated rates (Bytes per second)
    pub rate_in: f64,
    pub rate_out: f64,

    // Internal state for rate calculation
    last_updated: Instant,
    last_bytes_in: u64,
    last_bytes_out: u64,
}

impl ProcessStats {
    fn new(traffic: &ProcessTraffic, now: Instant) -> Self {
        Self {
            pid: traffic.pid,
            name: traffic.name.clone(),
            interface: traffic.interface.clone(),
            state: traffic.state.clone(),
            total_bytes_in: traffic.total_bytes_in,
            total_bytes_out: traffic.total_bytes_out,
            rate_in: 0.0,
            rate_out: 0.0,
            last_updated: now,
            last_bytes_in: traffic.total_bytes_in,
            last_bytes_out: traffic.total_bytes_out,
        }
    }

    fn update(&mut self, traffic: &ProcessTraffic, now: Instant) {
        // 更新基本信息 (Interface 可能会变)
        self.interface = traffic.interface.clone();
        self.state = traffic.state.clone();

        // 只有当流量增加时才计算速率
        // 注意：nettop 输出的是 total bytes，所以我们始终用新值减旧值
        // 但是 nettop 可能对同一个 PID 输出多行 (不同 socket)，调用者应该先聚合好了再传进来？
        // 或者 Tracker 负责聚合？
        // 如果 Tracker 负责聚合，那么 ProcessTraffic 应该是聚合后的结果。

        self.total_bytes_in = traffic.total_bytes_in;
        self.total_bytes_out = traffic.total_bytes_out;

        let duration = now.duration_since(self.last_updated);
        let secs = duration.as_secs_f64();

        if secs > 0.0 {
            // 防止 wrap around (虽然 u64 很难溢出)
            let delta_in = self.total_bytes_in.saturating_sub(self.last_bytes_in);
            let delta_out = self.total_bytes_out.saturating_sub(self.last_bytes_out);

            self.rate_in = delta_in as f64 / secs;
            self.rate_out = delta_out as f64 / secs;

            // 更新 checkpoints
            self.last_bytes_in = self.total_bytes_in;
            self.last_bytes_out = self.total_bytes_out;
            self.last_updated = now;
        }
    }
}

pub struct TrafficTracker {
    // PID -> Stats
    stats: HashMap<i32, ProcessStats>,
}

impl TrafficTracker {
    pub fn new() -> Self {
        Self {
            stats: HashMap::new(),
        }
    }

    /// Update tracker with a batch of aggregated process traffic
    pub fn update(&mut self, traffic_list: &[ProcessTraffic]) {
        let now = Instant::now();

        // Mark checked pids to handle removal of dead processes?
        // 简单处理：我们保留所有历史记录，或者 TTL？
        // 既然是 top，如果进程没了，应该从列表移除。
        let mut present_pids = Vec::new();

        for t in traffic_list {
            present_pids.push(t.pid);

            self.stats
                .entry(t.pid)
                .and_modify(|s| s.update(t, now))
                .or_insert_with(|| ProcessStats::new(t, now));
        }

        // 可选：清理不再出现的 PIDs (如果 nettop 确实覆盖了所有流量进程)
        // 注意：nettop 可能只输出有流量的？不，-L 0 好像会输出所有？
        // 暂不清理，避免闪烁。或者设置一个 TTL。
    }

    pub fn get_all_stats(&self) -> Vec<&ProcessStats> {
        self.stats.values().collect()
    }
}
