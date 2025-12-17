use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{prelude::*, widgets::*};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use super::nettop::{parse_nettop_csv_line, NettopCollector, ProcessTraffic};
use super::tracker::TrafficTracker;

enum AppEvent {
    Input(event::KeyEvent),
    Tick,
    TrafficUpdate(Vec<ProcessTraffic>),
}

pub fn run_tui() -> Result<()> {
    // 1. Setup Terminal
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // 2. Setup Data Collection in background thread
    let (tx, rx) = mpsc::channel();
    let tx_traffic = tx.clone();

    // Traffic Collector Thread
    thread::spawn(move || {
        let mut collector = NettopCollector::new();
        // 简单聚合逻辑：每次读取一批 line，聚合后发送
        // 由于 nettop 输出是流式的，我们尝试每秒聚合一次？
        // 或者简便起见：读取到一行就解析，积累在一个 buffer 里，每隔 500ms 发送一次 buffer

        let iter = match collector.start() {
            Ok(iter) => iter,
            Err(_) => return, // Handle error?
        };

        let mut batch = Vec::new();
        let mut last_send = Instant::now();

        for line_res in iter {
            if let Ok(line) = line_res {
                if let Some(traffic) = parse_nettop_csv_line(&line) {
                    batch.push(traffic);
                }
            }

            // check time to flush
            if last_send.elapsed() >= Duration::from_millis(500) {
                if !batch.is_empty() {
                    // Aggregate by PID within the batch immediately?
                    // nettop output might contain duplicate PIDs (multiple sockets)
                    // We consolidate them here before sending to UI thread
                    let mut aggregated: std::collections::HashMap<i32, ProcessTraffic> =
                        std::collections::HashMap::new();

                    for t in batch.drain(..) {
                        aggregated
                            .entry(t.pid)
                            .and_modify(|existing| {
                                existing.total_bytes_in += t.total_bytes_in;
                                existing.total_bytes_out += t.total_bytes_out;
                                // Interface might differ, keep last one or logic to prioritize utun?
                                if t.interface.starts_with("utun") {
                                    existing.interface = t.interface.clone();
                                }
                            })
                            .or_insert(t);
                    }

                    let params: Vec<ProcessTraffic> = aggregated.into_values().collect();
                    let _ = tx_traffic.send(AppEvent::TrafficUpdate(params));
                }
                last_send = Instant::now();
            }
        }
    });

    // Input Thread (or use poll in main loop)
    // Using crossterm event::poll is easier in main loop usually

    // 3. Main Loop
    let mut tracker = TrafficTracker::new();
    let mut sort_by = SortBy::RateDown;
    let _filter_pid: Option<i32> = None; // TODO: Support CLI arg

    loop {
        // Draw
        terminal.draw(|f| ui(f, &tracker, sort_by))?;

        // Handle Events
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('s') => {
                        // Cycle sort
                        sort_by = match sort_by {
                            SortBy::RateDown => SortBy::RateUp,
                            SortBy::RateUp => SortBy::Pid,
                            SortBy::Pid => SortBy::RateDown,
                        };
                    }
                    _ => {}
                }
            }
        }

        // Handle Data Updates (Non-blocking check)
        while let Ok(event) = rx.try_recv() {
            match event {
                AppEvent::TrafficUpdate(data) => {
                    tracker.update(&data);
                }
                _ => {}
            }
        }
    }

    // 4. Restore Terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}

#[derive(Clone, Copy)]
enum SortBy {
    RateDown,
    RateUp,
    Pid,
}

fn ui(f: &mut Frame, tracker: &TrafficTracker, sort_by: SortBy) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(0),    // Table
            Constraint::Length(3), // Footer
        ])
        .split(f.area());

    // Title
    let title = Paragraph::new("Proxy Audit - Traffic Monitor")
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    // Data preparation
    let mut stats: Vec<_> = tracker.get_all_stats().into_iter().collect();

    // Filtering (Show only active or all?)
    // stats.retain(|s| s.rate_in > 0.0 || s.rate_out > 0.0);

    // Sorting
    stats.sort_by(|a, b| match sort_by {
        SortBy::RateDown => b.rate_in.partial_cmp(&a.rate_in).unwrap(),
        SortBy::RateUp => b.rate_out.partial_cmp(&a.rate_out).unwrap(),
        SortBy::Pid => a.pid.cmp(&b.pid),
    });

    // Formatting Rows
    let rows: Vec<Row> = stats
        .iter()
        .map(|s| {
            let name = if s.name.len() > 20 {
                &s.name[..20]
            } else {
                &s.name
            };

            // Highlight proxy
            let iface_style = if s.interface.starts_with("utun") {
                Style::default().fg(Color::Green)
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(s.pid.to_string()),
                Cell::from(name.to_string()),
                Cell::from(format_speed(s.rate_out)),
                Cell::from(format_speed(s.rate_in)),
                Cell::from(format_bytes(s.total_bytes_out)),
                Cell::from(format_bytes(s.total_bytes_in)),
                Cell::from(s.interface.clone()).style(iface_style),
            ])
        })
        .collect();

    // Table
    let table = Table::new(
        rows,
        [
            Constraint::Length(8),  // PID
            Constraint::Length(22), // Name
            Constraint::Length(12), // Up Speed
            Constraint::Length(12), // Down Speed
            Constraint::Length(12), // Total Up
            Constraint::Length(12), // Total Down
            Constraint::Length(8),  // Interface
        ],
    )
    .header(
        Row::new(vec![
            "PID", "NAME", "UP/s", "DOWN/s", "TOT UP", "TOT DOWN", "IFACE",
        ])
        .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().borders(Borders::ALL).title("Processes"));

    f.render_widget(table, chunks[1]);

    // Footer
    let sort_str = match sort_by {
        SortBy::RateDown => "DOWN Speed",
        SortBy::RateUp => "UP Speed",
        SortBy::Pid => "PID",
    };
    let footer_text = format!("Sort: {} (s) | Quit (q)", sort_str);
    let footer = Paragraph::new(footer_text).block(Block::default().borders(Borders::ALL));
    f.render_widget(footer, chunks[2]);
}

fn format_speed(bytes_per_sec: f64) -> String {
    if bytes_per_sec < 1024.0 {
        format!("{:.1} B/s", bytes_per_sec)
    } else if bytes_per_sec < 1024.0 * 1024.0 {
        format!("{:.1} KB/s", bytes_per_sec / 1024.0)
    } else {
        format!("{:.1} MB/s", bytes_per_sec / 1024.0 / 1024.0)
    }
}

fn format_bytes(bytes: u64) -> String {
    let b = bytes as f64;
    if b < 1024.0 {
        format!("{:.0} B", b)
    } else if b < 1024.0 * 1024.0 {
        format!("{:.1} KB", b / 1024.0)
    } else if b < 1024.0 * 1024.0 * 1024.0 {
        format!("{:.1} MB", b / 1024.0 / 1024.0)
    } else {
        format!("{:.1} GB", b / 1024.0 / 1024.0 / 1024.0)
    }
}
