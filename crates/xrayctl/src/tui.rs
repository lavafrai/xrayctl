use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use std::io::{self, Stdout};
use std::sync::Arc;
use std::time::Duration;
use xray_manager_core::ManagerService;
use xray_manager_core::application::{Operation, OperationOptions, Query};
use xray_manager_core::events::ManagerEvent;

#[derive(Debug, Clone, PartialEq)]
pub enum ProbeState {
    Pending,
    Running,
    Succeeded(u64),
    Failed(String),
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct NodeRow {
    pub id: String,
    pub subscription: String,
    pub protocol: String,
    pub name: String,
    pub unsupported: bool,
    pub state: ProbeState,
}

#[derive(Debug, Default)]
pub struct TuiModel {
    pub nodes: Vec<NodeRow>,
    pub selected: usize,
    pub filter: String,
}

impl TuiModel {
    pub fn apply(&mut self, event: &ManagerEvent) {
        let (id, state) = match event {
            ManagerEvent::NodeProbeStarted { node_id } => (node_id, ProbeState::Running),
            ManagerEvent::NodeProbeSucceeded {
                node_id,
                latency_ms,
            } => (node_id, ProbeState::Succeeded(*latency_ms)),
            ManagerEvent::NodeProbeFailed { node_id, error } => {
                (node_id, ProbeState::Failed(error.clone()))
            }
            ManagerEvent::NodeProbeCancelled { node_id } => (node_id, ProbeState::Cancelled),
            _ => return,
        };
        if let Some(row) = self.nodes.iter_mut().find(|row| &row.id == id) {
            row.state = state;
        }
    }

    pub fn sort_by_latency(&mut self) {
        let selected_id = self.nodes.get(self.selected).map(|row| row.id.clone());
        self.nodes.sort_by_key(|row| match row.state {
            ProbeState::Succeeded(latency) => latency,
            _ => u64::MAX,
        });
        if let Some(id) = selected_id {
            self.selected = self.nodes.iter().position(|row| row.id == id).unwrap_or(0);
        }
    }

    fn visible_indices(&self) -> Vec<usize> {
        let filter = self.filter.to_lowercase();
        self.nodes
            .iter()
            .enumerate()
            .filter(|(_, row)| {
                filter.is_empty()
                    || row.name.to_lowercase().contains(&filter)
                    || row.subscription.to_lowercase().contains(&filter)
                    || row.protocol.to_lowercase().contains(&filter)
            })
            .map(|(index, _)| index)
            .collect()
    }

    fn move_selection(&mut self, direction: isize) {
        let visible = self.visible_indices();
        if visible.is_empty() {
            return;
        }
        let current = visible
            .iter()
            .position(|index| *index == self.selected)
            .unwrap_or(0);
        let next = (current as isize + direction).clamp(0, visible.len().saturating_sub(1) as isize)
            as usize;
        self.selected = visible[next];
    }
}

pub async fn run(service: ManagerService) -> anyhow::Result<()> {
    let service = Arc::new(service);
    let rows = rows_from_query(&service.query(Query::Nodes).await?);
    let status = service.query(Query::Status).await?;
    let menu_settings = service.query(Query::MenuSettings).await?;
    let active_node = status
        .get("selected_node")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let result = event_loop(
        &mut terminal,
        rows,
        active_node,
        service,
        menu_settings
            .get("probe_on_open")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true),
        menu_settings
            .get("latency_green_ms")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(200),
        menu_settings
            .get("latency_yellow_ms")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(500),
    )
    .await;
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

async fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    rows: Vec<NodeRow>,
    mut active_node: Option<String>,
    service: Arc<ManagerService>,
    probe_on_open: bool,
    latency_green_ms: u64,
    latency_yellow_ms: u64,
) -> anyhow::Result<()> {
    let mut model = TuiModel {
        nodes: if rows.is_empty() {
            vec![NodeRow {
                id: String::new(),
                subscription: "-".into(),
                protocol: "-".into(),
                name: "No nodes loaded".into(),
                unsupported: false,
                state: ProbeState::Pending,
            }]
        } else {
            rows
        },
        ..TuiModel::default()
    };
    let mut filter_mode = false;
    let mut notice: Option<(Color, String)> = None;
    if probe_on_open {
        for row in &mut model.nodes {
            if !row.id.is_empty() {
                row.state = ProbeState::Running;
            }
        }
    }
    let mut probe_session = if probe_on_open {
        match service.start_node_probes().await {
            Ok(session) => Some(session),
            Err(error) => {
                notice = Some((
                    Color::Red,
                    format!(
                        "Could not start probes: {}",
                        compact_error(&error.to_string())
                    ),
                ));
                None
            }
        }
    } else {
        None
    };
    loop {
        if let Some(session) = &mut probe_session {
            while let Ok(outcome) = session.receiver.try_recv() {
                apply_probe_result(&mut model, outcome);
            }
            if session.receiver.is_closed() && session.receiver.is_empty() {
                probe_session = None;
            }
        }
        terminal.draw(|frame| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(7), Constraint::Min(3)])
                .split(frame.area());
            let notice_line = notice.as_ref().map_or_else(
                || Line::from("Ready"),
                |(color, message)| Line::from(Span::styled(message, Style::default().fg(*color))),
            );
            frame.render_widget(
                Paragraph::new(vec![
                    Line::from(Span::styled(
                        "xray-manager",
                        Style::default().fg(Color::Cyan),
                    )),
                    Line::from(format!(
                        "Active node: {}",
                        active_node.as_deref().unwrap_or("none")
                    )),
                    Line::from("Enter: select  r: probe  /: filter  s: sort  q: quit"),
                    Line::from(format!("Manager log: {}", manager_log_hint())),
                    notice_line,
                ])
                .block(Block::default().borders(Borders::ALL).title("Status")),
                chunks[0],
            );
            let visible = model.visible_indices();
            let rows: Vec<ListItem> = visible
                .iter()
                .map(|index| {
                    let row = &model.nodes[*index];
                    let is_active = active_node.as_ref().is_some_and(|active| {
                        active.starts_with(&row.id) || row.id.starts_with(active)
                    });
                    let color = if is_active {
                        Color::Cyan
                    } else if row.unsupported {
                        Color::DarkGray
                    } else {
                        match row.state {
                            ProbeState::Pending => Color::Gray,
                            ProbeState::Running => Color::Blue,
                            ProbeState::Succeeded(ms) if ms <= latency_green_ms => Color::Green,
                            ProbeState::Succeeded(ms) if ms <= latency_yellow_ms => Color::Yellow,
                            ProbeState::Succeeded(_) | ProbeState::Failed(_) => Color::Red,
                            ProbeState::Cancelled => Color::DarkGray,
                        }
                    };
                    ListItem::new(format!(
                        "{}  {}  {}  {}",
                        row.subscription,
                        row.protocol,
                        row.name,
                        probe_label(&row.state)
                    ))
                    .style(Style::default().fg(color))
                })
                .collect();
            let title = if model.filter.is_empty() {
                "Nodes".to_owned()
            } else {
                format!("Nodes — filter: {}", model.filter)
            };
            let selected_visible = visible
                .iter()
                .position(|index| *index == model.selected)
                .unwrap_or(0);
            let mut list_state = ListState::default().with_selected(Some(selected_visible));
            frame.render_stateful_widget(
                List::new(rows)
                    .highlight_symbol("▶ ")
                    .highlight_style(Style::default().bg(Color::DarkGray))
                    .block(Block::default().borders(Borders::ALL).title(title)),
                chunks[1],
                &mut list_state,
            );
        })?;
        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
        {
            if filter_mode {
                match key.code {
                    KeyCode::Enter | KeyCode::Esc => filter_mode = false,
                    KeyCode::Backspace => {
                        model.filter.pop();
                        model.selected = model.visible_indices().first().copied().unwrap_or(0);
                    }
                    KeyCode::Char(character) => {
                        model.filter.push(character);
                        model.selected = model.visible_indices().first().copied().unwrap_or(0);
                    }
                    _ => {}
                }
                continue;
            }
            match key.code {
                KeyCode::Char('q') => break,
                KeyCode::Esc => {
                    if let Some(session) = probe_session.take() {
                        session.cancel();
                        for row in &mut model.nodes {
                            if matches!(row.state, ProbeState::Pending | ProbeState::Running) {
                                row.state = ProbeState::Cancelled;
                            }
                        }
                    }
                }
                KeyCode::Char('s') => model.sort_by_latency(),
                KeyCode::Char('/') => {
                    filter_mode = true;
                    notice = Some((
                        Color::Blue,
                        "Filter mode: type text, Enter to finish".into(),
                    ));
                }
                KeyCode::Char('r') => {
                    if let Some(session) = probe_session.take() {
                        session.cancel();
                    }
                    for row in &mut model.nodes {
                        if !row.id.is_empty() {
                            row.state = ProbeState::Running;
                        }
                    }
                    match service.start_node_probes().await {
                        Ok(session) => {
                            probe_session = Some(session);
                            notice = Some((Color::Blue, "Probing nodes…".into()));
                        }
                        Err(error) => {
                            for row in &mut model.nodes {
                                if matches!(row.state, ProbeState::Running) {
                                    row.state = ProbeState::Failed("probe unavailable".into());
                                }
                            }
                            notice = Some((
                                Color::Red,
                                format!(
                                    "Could not start probes: {}",
                                    compact_error(&error.to_string())
                                ),
                            ));
                        }
                    }
                }
                KeyCode::Enter => {
                    if let Some(row) = model.nodes.get(model.selected) {
                        let id = row.id.clone();
                        let name = row.name.clone();
                        let unsupported = row.unsupported;
                        if id.is_empty() {
                            notice = Some((Color::Yellow, "No node is available to select".into()));
                        } else if unsupported {
                            notice = Some((
                                Color::Yellow,
                                format!("{name} is not supported by the current Xray adapter"),
                            ));
                        } else {
                            match service
                                .execute(
                                    Operation::NodeSelect { id: id.clone() },
                                    OperationOptions::default(),
                                )
                                .await
                            {
                                Ok(_) => {
                                    active_node = Some(id);
                                    notice = Some((
                                        Color::Green,
                                        format!("Activated {name} successfully"),
                                    ));
                                }
                                Err(error) => {
                                    notice = Some((
                                        Color::Red,
                                        format!(
                                            "Activation failed: {}",
                                            compact_error(&error.to_string())
                                        ),
                                    ));
                                }
                            }
                        }
                    }
                }
                KeyCode::Down => model.move_selection(1),
                KeyCode::Up => model.move_selection(-1),
                _ => {}
            }
        }
    }
    if let Some(session) = probe_session {
        session.cancel();
    }
    Ok(())
}

fn manager_log_hint() -> &'static str {
    if cfg!(target_os = "linux") {
        "/var/log/xray-manager/xrayctl.log"
    } else {
        ".xray-manager/logs/xrayctl.log"
    }
}

fn probe_label(state: &ProbeState) -> String {
    match state {
        ProbeState::Pending => "not probed".into(),
        ProbeState::Running => "probing…".into(),
        ProbeState::Succeeded(latency) => format!("{latency} ms"),
        ProbeState::Failed(_) => "failed".into(),
        ProbeState::Cancelled => "cancelled".into(),
    }
}

fn compact_error(error: &str) -> String {
    const MAX_CHARS: usize = 160;
    let mut compact = error.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.chars().count() > MAX_CHARS {
        compact = compact.chars().take(MAX_CHARS - 1).collect();
        compact.push('…');
    }
    compact
}

fn apply_probe_result(model: &mut TuiModel, outcome: xray_manager_core::probe::NodeProbeOutcome) {
    let event = if let Some(latency) = outcome.result.latency_ms {
        ManagerEvent::NodeProbeSucceeded {
            node_id: outcome.node_id,
            latency_ms: latency,
        }
    } else if outcome.result.error.as_deref() == Some("cancelled") {
        ManagerEvent::NodeProbeCancelled {
            node_id: outcome.node_id,
        }
    } else {
        ManagerEvent::NodeProbeFailed {
            node_id: outcome.node_id,
            error: outcome
                .result
                .error
                .unwrap_or_else(|| "probe failed".into()),
        }
    };
    model.apply(&event);
}

fn rows_from_query(value: &serde_json::Value) -> Vec<NodeRow> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|node| {
            Some(NodeRow {
                id: node.get("id")?.as_str()?.into(),
                subscription: node.get("subscription")?.as_str()?.into(),
                protocol: node.get("protocol")?.as_str()?.into(),
                name: node.get("name")?.as_str()?.into(),
                unsupported: node.get("support").and_then(serde_json::Value::as_str)
                    == Some("unsupported"),
                state: ProbeState::Pending,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn async_results_update_rows_without_moving_cursor() {
        let mut model = TuiModel {
            nodes: vec![NodeRow {
                id: "abc".into(),
                subscription: "main".into(),
                protocol: "VLESS".into(),
                name: "Frankfurt".into(),
                unsupported: false,
                state: ProbeState::Pending,
            }],
            selected: 0,
            filter: String::new(),
        };
        model.apply(&ManagerEvent::NodeProbeSucceeded {
            node_id: "abc".into(),
            latency_ms: 84,
        });
        assert_eq!(model.nodes[0].state, ProbeState::Succeeded(84));
        assert_eq!(model.selected, 0);
    }

    #[test]
    fn manual_sort_preserves_selected_node() {
        let row = |id: &str, latency| NodeRow {
            id: id.into(),
            subscription: "main".into(),
            protocol: "VLESS".into(),
            name: id.into(),
            unsupported: false,
            state: ProbeState::Succeeded(latency),
        };
        let mut model = TuiModel {
            nodes: vec![row("slow", 500), row("fast", 20)],
            selected: 0,
            filter: String::new(),
        };
        model.sort_by_latency();
        assert_eq!(model.nodes[model.selected].id, "slow");
    }

    #[test]
    fn filtering_does_not_reorder_rows() {
        let mut model = TuiModel {
            nodes: vec![
                NodeRow {
                    id: "one".into(),
                    subscription: "main".into(),
                    protocol: "VLESS".into(),
                    name: "Berlin".into(),
                    unsupported: false,
                    state: ProbeState::Pending,
                },
                NodeRow {
                    id: "two".into(),
                    subscription: "main".into(),
                    protocol: "Trojan".into(),
                    name: "Tokyo".into(),
                    unsupported: false,
                    state: ProbeState::Pending,
                },
            ],
            selected: 0,
            filter: "tok".into(),
        };
        assert_eq!(model.visible_indices(), vec![1]);
        model.move_selection(1);
        assert_eq!(model.selected, 1);
        assert_eq!(model.nodes[0].id, "one");
    }
}
