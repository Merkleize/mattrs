use std::io::{self, BufRead, BufReader};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::ExecutableCommand;
use mattrs::inspector::{InstanceSnapshot, ManagerSnapshot};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState};

#[derive(Parser)]
#[command(name = "mattrs-inspector", about = "Real-time TUI for mattrs manager state")]
struct Args {
    /// Host to connect to
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    /// Port to connect to
    #[arg(long, default_value_t = 34443)]
    port: u16,
}

#[derive(Clone)]
struct AppState {
    snapshot: Option<ManagerSnapshot>,
    connected: bool,
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    let state = Arc::new(Mutex::new(AppState {
        snapshot: None,
        connected: false,
    }));

    // Network thread
    let net_state = Arc::clone(&state);
    let host = args.host.clone();
    let port = args.port;
    std::thread::spawn(move || loop {
        match TcpStream::connect(format!("{}:{}", host, port)) {
            Ok(stream) => {
                {
                    let mut s = net_state.lock().unwrap();
                    s.connected = true;
                }
                let reader = BufReader::new(stream);
                for line in reader.lines() {
                    match line {
                        Ok(line) => {
                            if let Ok(snap) = serde_json::from_str::<ManagerSnapshot>(&line) {
                                let mut s = net_state.lock().unwrap();
                                s.snapshot = Some(snap);
                            }
                        }
                        Err(_) => break,
                    }
                }
                {
                    let mut s = net_state.lock().unwrap();
                    s.connected = false;
                }
            }
            Err(_) => {}
        }
        std::thread::sleep(Duration::from_secs(2));
    });

    // Terminal setup
    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;

    let mut table_state = TableState::default();

    loop {
        let app = state.lock().unwrap().clone();

        terminal.draw(|f| {
            ui(f, &app, &mut table_state);
        })?;

        if event::poll(Duration::from_millis(16))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Up | KeyCode::Char('k') => {
                        let i = table_state.selected().unwrap_or(0);
                        table_state.select(Some(i.saturating_sub(1)));
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        let count = app
                            .snapshot
                            .as_ref()
                            .map(|s| s.instances.len())
                            .unwrap_or(0);
                        let i = table_state.selected().unwrap_or(0);
                        if count > 0 {
                            table_state.select(Some((i + 1).min(count - 1)));
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}

fn status_color(status: &str) -> Color {
    match status {
        "Abstract" => Color::Yellow,
        "Funded" => Color::Green,
        "Spent" => Color::DarkGray,
        _ => Color::White,
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}

fn ui(f: &mut Frame, app: &AppState, table_state: &mut TableState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),  // header
            Constraint::Min(5),    // table
            Constraint::Length(10), // detail
        ])
        .split(f.area());

    // Header
    let conn_status = if app.connected { "Connected" } else { "Disconnected" };
    let conn_color = if app.connected { Color::Green } else { Color::Red };
    let instance_count = app.snapshot.as_ref().map(|s| s.instances.len()).unwrap_or(0);

    let header = Line::from(vec![
        Span::styled("mattrs inspector", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw("    "),
        Span::styled(conn_status, Style::default().fg(conn_color)),
        Span::raw(format!("    {} instances", instance_count)),
    ]);
    f.render_widget(Paragraph::new(header), chunks[0]);

    // Table
    let header_row = Row::new(vec![
        Cell::from("#"),
        Cell::from("Contract"),
        Cell::from("Status"),
        Cell::from("Outpoint"),
        Cell::from("Amount"),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD))
    .bottom_margin(0);

    let rows: Vec<Row> = app
        .snapshot
        .as_ref()
        .map(|s| {
            s.instances
                .iter()
                .map(|inst| {
                    let color = status_color(&inst.status);
                    Row::new(vec![
                        Cell::from(inst.index.to_string()),
                        Cell::from(inst.contract_name.clone()),
                        Cell::from(inst.status.clone()).style(Style::default().fg(color)),
                        Cell::from(
                            inst.outpoint
                                .as_deref()
                                .unwrap_or_default()
                                .to_string(),
                        ),
                        Cell::from(
                            inst.funding_amount_sat
                                .map(|a| a.to_string())
                                .unwrap_or_default(),
                        ),
                    ])
                })
                .collect()
        })
        .unwrap_or_default();

    let table = Table::new(
        rows,
        [
            Constraint::Length(4),
            Constraint::Length(14),
            Constraint::Length(10),
            Constraint::Min(18),
            Constraint::Length(12),
        ],
    )
    .header(header_row)
    .block(Block::default().borders(Borders::ALL))
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_stateful_widget(table, chunks[1], table_state);

    // Detail panel
    let detail = if let Some(snap) = &app.snapshot {
        let sel = table_state.selected().unwrap_or(0);
        if let Some(inst) = snap.instances.get(sel) {
            format_detail(inst)
        } else {
            "No instances".to_string()
        }
    } else {
        "Waiting for data...".to_string()
    };

    let detail_widget = Paragraph::new(detail)
        .block(Block::default().borders(Borders::ALL).title("Detail"));
    f.render_widget(detail_widget, chunks[2]);
}

fn format_detail(inst: &InstanceSnapshot) -> String {
    let mut lines = vec![
        format!("Instance #{}", inst.index),
        format!("  Contract: {}", inst.contract_name),
        format!("  Status: {}", inst.status),
        format!("  Address: {}", inst.address),
        format!(
            "  State data: {} ({} bytes)",
            truncate(&inst.data_hex, 32),
            inst.data_hex.len() / 2
        ),
    ];

    if let Some(op) = &inst.outpoint {
        lines.push(format!("  Outpoint: {}", op));
    }
    if let Some(txid) = &inst.funding_txid {
        lines.push(format!("  Funding txid: {}", txid));
    }
    if let Some(amt) = inst.funding_amount_sat {
        lines.push(format!("  Amount: {} sat", amt));
    }
    if let Some(clause) = &inst.spending_clause {
        lines.push(format!("  Spent via: {}", clause));
    }

    lines.join("\n")
}
