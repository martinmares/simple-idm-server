use crate::protocol::{Control, Resize};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{self, ClearType},
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{self, IsTerminal, Write},
    time::Duration,
};
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};
use url::Url;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, Deserialize)]
struct Config {
    bastions: BTreeMap<String, Profile>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Profile {
    pub(crate) url: String,
    issuer: String,
    client_id: String,
    tenant: Option<String>,
    #[serde(default = "default_scopes")]
    scopes: Vec<String>,
}

fn default_scopes() -> Vec<String> {
    ["openid", "profile", "email", "groups", "bastion:connect"]
        .map(str::to_owned)
        .to_vec()
}

pub(crate) fn secure_url(value: &str) -> Result<Url> {
    let url = Url::parse(value)?;
    let loopback = match url.host() {
        Some(url::Host::Domain("localhost")) => true,
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    if !(url.scheme() == "https" || url.scheme() == "http" && loopback)
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("Use HTTPS (HTTP is permitted only for explicit localhost/loopback fixtures), without credentials, query or fragment".into());
    }
    Ok(url)
}

fn profile_from(content: &str, hostname: &str) -> Result<Profile> {
    let mut config: Config = toml::from_str(content)?;
    let mut profile = config.bastions.remove(hostname).ok_or_else(|| format!(
        "Unknown bastion '{hostname}'. Add [bastions.\"{hostname}\"] with url, issuer and client_id to bastions.toml in the OS configuration directory for simple-idm-ssh-login"))?;
    secure_url(&profile.url)?;
    secure_url(&profile.issuer)?;
    if profile.client_id.trim().is_empty() || profile.scopes.iter().any(|s| s.trim().is_empty()) {
        return Err("Bastion client_id and scope names must not be empty".into());
    }
    // OIDC nonce validation requires openid; the bastion requires connect.
    for required in ["openid", "bastion:connect"] {
        if !profile.scopes.iter().any(|s| s == required) {
            profile.scopes.push(required.to_owned());
        }
    }
    Ok(profile)
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Catalog {
    #[serde(default)]
    identity: Option<Identity>,
    #[serde(default)]
    bastion: Option<BastionInfo>,
    #[serde(skip)]
    peer_ip: Option<std::net::IpAddr>,
    pub(crate) hosts: Vec<Host>,
}
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Identity {
    username: String,
    subject: String,
    tenant: Option<String>,
}
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct BastionInfo {
    id: String,
}
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Host {
    #[serde(default)]
    pub(crate) address: String,
    #[serde(default)]
    pub(crate) port: u16,
    #[serde(default)]
    pub(crate) resolved_ips: Vec<String>,
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) environment: String,
    pub(crate) description: String,
    pub(crate) logins: Vec<String>,
}

fn matches(host: &Host, query: &str) -> bool {
    let fields = format!(
        "{} {} {} {} {} {} {}",
        host.id,
        host.name,
        host.environment,
        host.description,
        host.logins.join(" "),
        host.address,
        host.resolved_ips.join(" ")
    )
    .to_lowercase();
    query
        .split_whitespace()
        .all(|word| fields.contains(&word.to_lowercase()))
}

// Server-supplied labels must never inject terminal escape/control sequences.
pub(crate) fn label(value: &str) -> String {
    value.chars().filter(|c| !c.is_control()).collect()
}

pub(crate) struct TerminalGuard;
pub fn install_panic_hook() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if terminal::is_raw_mode_enabled().unwrap_or(false) {
                restore_terminal();
            }
            previous(info);
        }));
    });
}

fn restore_terminal() {
    let _ = terminal::disable_raw_mode();
    let _ = execute!(
        io::stdout(),
        event::DisableMouseCapture,
        event::DisableBracketedPaste,
        crossterm::style::ResetColor,
        cursor::Show,
        terminal::LeaveAlternateScreen
    );
}

impl TerminalGuard {
    pub(crate) fn enter() -> Result<Self> {
        terminal::enable_raw_mode()?;
        let guard = Self;
        execute!(io::stdout(), terminal::EnterAlternateScreen, cursor::Hide)?;
        Ok(guard)
    }
}
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if terminal::is_raw_mode_enabled().unwrap_or(false) {
            restore_terminal();
        }
    }
}

pub(crate) fn load_profile(hostname: &str) -> Result<Profile> {
    let path = dirs::config_dir()
        .ok_or("Cannot determine config directory")?
        .join("simple-idm-ssh-login")
        .join("bastions.toml");
    let content = std::fs::read_to_string(&path).map_err(|e| {
        format!(
            "Cannot read {}: {e}. See the bastions.toml example.",
            path.display()
        )
    })?;
    profile_from(&content, hostname)
}

pub async fn run(hostname: &str, device: bool) -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate())?;
        let mut hangup = signal(SignalKind::hangup())?;
        tokio::select! {
            result = run_inner(hostname, device) => result,
            _ = terminate.recv() => Ok(()),
            _ = hangup.recv() => Ok(()),
            _ = tokio::signal::ctrl_c() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    run_inner(hostname, device).await
}

async fn run_inner(hostname: &str, device: bool) -> Result<()> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("Bastion requires an interactive terminal".into());
    }
    #[cfg(not(unix))]
    return Err("V1 raw bastion transport currently requires Unix (Linux/macOS)".into());
    #[cfg(unix)]
    {
        let profile = load_profile(hostname)?;
        let base = secure_url(&profile.url)?;
        let mut token = authenticate(&profile, device).await?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()?;
        let mut catalog = match load_catalog(&client, &base, &token).await {
            Err(error) if unauthorized(error.as_ref()) => {
                token = authenticate(&profile, device).await?;
                load_catalog(&client, &base, &token).await?
            }
            result => result?,
        };
        let mut terminal = Some(TerminalGuard::enter()?);
        let mut notice = String::new();
        let mut host_picker = PickerState::default();
        loop {
            let rows = catalog
                .hosts
                .iter()
                .map(|h| {
                    vec![
                        label(&h.name),
                        label(&if h.port == 0 || h.port == 22 {
                            h.address.clone()
                        } else {
                            format!("{}:{}", h.address, h.port)
                        }),
                        label(&h.resolved_ips.join(", ")),
                        label(&h.logins.join(", ")),
                        label(&h.environment),
                    ]
                })
                .collect::<Vec<_>>();
            let context = catalog.context(&base);
            let Some(index) = table_picker(
                "Hosts",
                &rows,
                &["Name", "Hostname", "IP address", "Account", "Environment"],
                |i, q| matches(&catalog.hosts[i], q),
                &notice,
                &context,
                &mut host_picker,
            )
            .await?
            else {
                break;
            };
            let host = &catalog.hosts[index];
            let login = match host.logins.as_slice() {
                [] => {
                    notice = "This host has no permitted Linux accounts".into();
                    continue;
                }
                [login] => login,
                logins => {
                    let Some(index) = picker(
                        "Linux account",
                        logins,
                        |i, q| logins[i].to_lowercase().contains(&q.to_lowercase()),
                        "q / Esc: back to hosts",
                    )
                    .await?
                    else {
                        continue;
                    };
                    &logins[index]
                }
            };
            let result = if host_picker.files {
                crate::files::run(&base, &token, &host.id, &host.name, login, &context).await
            } else {
                terminal_session(&base, &token, &host.id, login).await
            };
            notice = match result {
                Ok(message) => message,
                Err(error) if unauthorized(error.as_ref()) => {
                    // Restore the local terminal before printing browser instructions.
                    drop(terminal.take());
                    token = authenticate(&profile, device).await?;
                    catalog = load_catalog(&client, &base, &token).await?;
                    terminal = Some(TerminalGuard::enter()?);
                    "Authentication renewed; choose a host to reconnect".into()
                }
                Err(error) => format!("Connection failed: {error}"),
            };
        }
        Ok(())
    }
}

pub(crate) async fn authenticate(profile: &Profile, device: bool) -> Result<String> {
    authenticate_with_browser(profile, device, None).await
}

pub(crate) async fn authenticate_with_browser(
    profile: &Profile,
    device: bool,
    browser: Option<&str>,
) -> Result<String> {
    let token = if device {
        simple_idm_core::ssh_login::oidc_device::device_access_token_flow(
            &profile.issuer,
            &profile.client_id,
            profile.tenant.as_deref(),
            &profile.scopes,
        )
        .await?
    } else {
        simple_idm_core::ssh_login::oidc_browser::browser_access_token_flow_with_browser(
            &profile.issuer,
            &profile.client_id,
            profile.tenant.as_deref(),
            &profile.scopes,
            browser,
        )
        .await?
    };
    Ok(token)
}

pub(crate) async fn load_catalog(
    client: &reqwest::Client,
    base: &Url,
    token: &str,
) -> Result<Catalog> {
    let response = client
        .get(base.join("/api/v1/hosts")?)
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?;
    let peer_ip = response.remote_addr().map(|address| address.ip());
    let mut catalog: Catalog = response.json().await?;
    catalog.peer_ip = peer_ip;
    Ok(catalog)
}

fn unauthorized(error: &(dyn std::error::Error + 'static)) -> bool {
    if let Some(error) = error.downcast_ref::<reqwest::Error>() {
        return error.status() == Some(reqwest::StatusCode::UNAUTHORIZED);
    }
    matches!(error.downcast_ref::<tokio_tungstenite::tungstenite::Error>(),
        Some(tokio_tungstenite::tungstenite::Error::Http(response)) if response.status().as_u16() == 401)
}

impl Catalog {
    pub(crate) fn context(&self, base: &Url) -> Vec<String> {
        let mut lines = vec!["Welcome to Bastion!".into()];
        if let Some(identity) = &self.identity {
            lines.push(format!(
                "Signed in as: {} | Subject: {}",
                identity.username, identity.subject
            ));
            if let Some(tenant) = &identity.tenant {
                lines.push(format!("Tenant: {tenant}"));
            }
        } else {
            lines.push("User identity unavailable (update bastion server to 0.1.1)".into());
        }
        lines.push(format!(
            "Bastion: {}",
            self.bastion
                .as_ref()
                .map(|info| info.id.as_str())
                .unwrap_or("unknown")
        ));
        lines.push(format!("Endpoint: {}", base.as_str()));
        lines.push(format!(
            "Connected IP: {} (TLS endpoint)",
            self.peer_ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "unknown".into())
        ));

        lines
    }
}

async fn picker(
    title: &str,
    items: &[String],
    filter: impl Fn(usize, &str) -> bool,
    notice: &str,
) -> Result<Option<usize>> {
    let rows = items
        .iter()
        .map(|item| vec![label(item)])
        .collect::<Vec<_>>();
    table_picker(
        title,
        &rows,
        &["Account"],
        filter,
        notice,
        &[],
        &mut PickerState::default(),
    )
    .await
}

#[derive(Default)]
struct PickerState {
    query: String,
    selected: usize,
    table: ratatui::widgets::TableState,
    files: bool,
}

async fn table_picker(
    title: &str,
    items: &[Vec<String>],
    headers: &[&str],
    filter: impl Fn(usize, &str) -> bool,
    notice: &str,
    context: &[String],
    memory: &mut PickerState,
) -> Result<Option<usize>> {
    use ratatui::{Terminal, backend::CrosstermBackend};
    execute!(
        io::stdout(),
        terminal::EnterAlternateScreen,
        event::DisableMouseCapture,
        event::DisableBracketedPaste,
        crossterm::style::ResetColor,
        cursor::Hide
    )?;
    write!(io::stdout(), "\x1b[r\x1b[?6l")?;
    let mut ui = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    ui.clear()?;
    let mut filter_edit: Option<(String, usize)> = None;
    let mut redraw = true;
    loop {
        let indices: Vec<_> = (0..items.len())
            .filter(|&i| filter(i, &memory.query))
            .collect();
        memory.selected = memory.selected.min(indices.len().saturating_sub(1));
        memory
            .table
            .select((!indices.is_empty()).then_some(memory.selected));
        if redraw {
            ui.draw(|frame| {
                draw_picker(
                    frame,
                    title,
                    items,
                    headers,
                    &indices,
                    &memory.query,
                    notice,
                    context,
                    &mut memory.table,
                    filter_edit.is_some(),
                )
            })?;
            redraw = false;
        }
        if !event::poll(Duration::ZERO)? {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        }
        let page = usize::from(ui.size()?.height.saturating_sub(context.len() as u16 + 8)).max(1);
        match event::read()? {
            Event::Key(key) if key.kind != KeyEventKind::Release => {
                if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                    return Ok(None);
                }
                if filter_edit.is_some() {
                    match key.code {
                        KeyCode::Enter => {
                            filter_edit = None;
                        }
                        KeyCode::Esc => {
                            let (original_query, original_selected) = filter_edit.take().unwrap();
                            memory.query = original_query;
                            memory.selected = original_selected;
                            *memory.table.offset_mut() = 0;
                        }
                        KeyCode::Backspace => {
                            memory.query.pop();
                            memory.selected = 0;
                            *memory.table.offset_mut() = 0;
                        }
                        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            memory.query.clear();
                            memory.selected = 0;
                            *memory.table.offset_mut() = 0;
                        }
                        KeyCode::Char(c)
                            if !key
                                .modifiers
                                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                        {
                            memory.query.push(c);
                            memory.selected = 0;
                            *memory.table.offset_mut() = 0;
                        }
                        _ => continue,
                    }
                } else {
                    match key.code {
                        KeyCode::Esc => return Ok(None),
                        KeyCode::Char('q')
                            if !key
                                .modifiers
                                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                        {
                            return Ok(None);
                        }
                        KeyCode::Char('/') => {
                            filter_edit = Some((memory.query.clone(), memory.selected));
                        }
                        KeyCode::Up => memory.selected = memory.selected.saturating_sub(1),
                        KeyCode::Down => {
                            memory.selected =
                                (memory.selected + 1).min(indices.len().saturating_sub(1))
                        }
                        KeyCode::PageUp => memory.selected = memory.selected.saturating_sub(page),
                        KeyCode::PageDown => {
                            memory.selected = memory
                                .selected
                                .saturating_add(page)
                                .min(indices.len().saturating_sub(1))
                        }
                        KeyCode::Home => memory.selected = 0,
                        KeyCode::End => memory.selected = indices.len().saturating_sub(1),
                        KeyCode::F(2) | KeyCode::Char('f')
                            if title == "Hosts" && !indices.is_empty() =>
                        {
                            memory.files = true;
                            return Ok(Some(indices[memory.selected]));
                        }
                        KeyCode::Enter if !indices.is_empty() => {
                            memory.files = false;
                            return Ok(Some(indices[memory.selected]));
                        }
                        _ => continue,
                    }
                }
            }
            Event::Resize(_, _) => {}
            _ => continue,
        }
        redraw = true;
    }
}

#[allow(clippy::too_many_arguments)]
fn draw_picker(
    frame: &mut ratatui::Frame,
    title: &str,
    items: &[Vec<String>],
    headers: &[&str],
    indices: &[usize],
    query: &str,
    notice: &str,
    context: &[String],
    state: &mut ratatui::widgets::TableState,
    editing_filter: bool,
) {
    use ratatui::{
        layout::{Constraint, Layout},
        style::{Color, Modifier, Style},
        widgets::{
            Block, Borders, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
        },
    };
    let chunks = Layout::vertical([
        Constraint::Length(context.len() as u16),
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .split(frame.area());
    frame.render_widget(
        Paragraph::new(
            context
                .iter()
                .map(|line| label(line))
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .style(Style::default().fg(Color::Cyan)),
        chunks[0],
    );
    let input_width = chunks[1].width.saturating_sub(2);
    let query_width = ratatui::text::Line::from(query).width();
    let input_offset = query_width.saturating_sub(usize::from(input_width.saturating_sub(1)));
    frame.render_widget(
        Paragraph::new(query)
            .scroll((0, input_offset.min(u16::MAX as usize) as u16))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(if editing_filter {
                        " Filter by host / account — editing "
                    } else {
                        " Filter by host / account — / to edit "
                    })
                    .border_style(Style::default().fg(if editing_filter {
                        Color::Cyan
                    } else {
                        Color::DarkGray
                    })),
            ),
        chunks[1],
    );
    if editing_filter && input_width > 0 && chunks[1].height >= 3 {
        frame.set_cursor_position((
            chunks[1].x + 1 + (query_width - input_offset) as u16,
            chunks[1].y + 1,
        ));
    }
    let columns = if headers.len() == 5 && frame.area().width < 100 {
        4
    } else {
        headers.len()
    };
    let widths = if columns == 4 {
        vec![
            Constraint::Percentage(25),
            Constraint::Percentage(35),
            Constraint::Percentage(25),
            Constraint::Percentage(15),
        ]
    } else if columns == 5 {
        vec![
            Constraint::Percentage(24),
            Constraint::Percentage(28),
            Constraint::Percentage(22),
            Constraint::Percentage(14),
            Constraint::Percentage(12),
        ]
    } else {
        vec![Constraint::Percentage(100)]
    };
    let table = Table::new(
        indices
            .iter()
            .map(|&i| Row::new(items[i].iter().take(columns).cloned().collect::<Vec<_>>())),
        widths,
    )
    .header(
        Row::new(headers.iter().take(columns).copied().collect::<Vec<_>>())
            .style(Style::default().fg(Color::Cyan))
            .bottom_margin(1),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if editing_filter {
                Color::DarkGray
            } else {
                Color::Cyan
            }))
            .title(format!(
                " {title} — {} / {} permitted ",
                indices.len(),
                items.len()
            )),
    )
    .row_highlight_style(
        Style::default()
            .bg(Color::Blue)
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▶ ");
    frame.render_stateful_widget(table, chunks[2], state);
    let viewport = usize::from(chunks[2].height.saturating_sub(4));
    if indices.len() > viewport && viewport > 0 {
        let mut scroll = ScrollbarState::new(indices.len().saturating_sub(viewport) + 1)
            .position(state.offset())
            .viewport_content_length(viewport);
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("▲"))
                .end_symbol(Some("▼")),
            chunks[2],
            &mut scroll,
        );
    }
    if indices.is_empty() {
        frame.render_widget(
            Paragraph::new("No matching hosts / accounts"),
            ratatui::layout::Rect::new(
                chunks[2].x + 2,
                chunks[2].y + 2,
                chunks[2].width.saturating_sub(4),
                chunks[2].height.saturating_sub(4),
            ),
        );
    }
    frame.render_widget(
        Paragraph::new(label(notice)).style(Style::default().fg(Color::Yellow)),
        chunks[3],
    );
    frame.render_widget(
        Paragraph::new(if editing_filter {
            "Type: filter  Enter: apply / return to list  Esc: cancel edit  Ctrl-U: clear"
        } else {
            "/: filter  ↑/↓: select  PgUp/PgDn/Home/End: scroll  Enter: connect  f/F2: files  q: quit / back  Esc: back"
        }),
        chunks[4],
    );
}

pub(crate) fn terminal_url(
    base: &Url,
    host: &str,
    login: &str,
    cols: u16,
    rows: u16,
    term: &str,
) -> Result<Url> {
    let mut url = base.join("/api/v1/terminal")?;
    url.set_scheme(if base.scheme() == "https" {
        "wss"
    } else {
        "ws"
    })
    .map_err(|_| "Invalid WebSocket scheme")?;
    url.query_pairs_mut().extend_pairs([
        ("host_id", host),
        ("login", login),
        ("cols", &cols.to_string()),
        ("rows", &rows.to_string()),
        ("term", term),
    ]);
    Ok(url)
}

#[cfg(unix)]
type TerminalSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

#[cfg(unix)]
async fn send_frame(socket: &mut TerminalSocket, message: Message) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), socket.send(message))
        .await
        .map_err(|_| "Bastion transport stalled while sending")??;
    Ok(())
}

#[cfg(unix)]
async fn terminal_session(base: &Url, token: &str, host: &str, login: &str) -> Result<String> {
    use std::{
        io::Read,
        os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    };
    use tokio::io::unix::AsyncFd;
    let (cols, rows) = terminal::size()?;
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());
    let url = terminal_url(base, host, login, cols, rows, &term)?;
    let mut request = url.as_str().into_client_request()?;
    request
        .headers_mut()
        .insert("Authorization", format!("Bearer {token}").parse()?);
    execute!(
        io::stdout(),
        crossterm::style::ResetColor,
        cursor::MoveTo(0, 0),
        terminal::Clear(ClearType::All)
    )?;
    print!("Connecting… Esc: cancel\r\n");
    io::stdout().flush()?;
    let connect = tokio_tungstenite::connect_async(request);
    tokio::pin!(connect);
    let mut poll = tokio::time::interval(Duration::from_millis(50));
    let deadline = tokio::time::sleep(Duration::from_secs(30));
    tokio::pin!(deadline);
    let (mut socket, _) = loop {
        tokio::select! {
            result = &mut connect => break result?,
            _ = &mut deadline => return Err("WebSocket connection timed out".into()),
            _ = poll.tick() => {
                if event::poll(Duration::ZERO)? && matches!(event::read()?, Event::Key(k) if k.code == KeyCode::Esc) {
                    return Ok("Connection cancelled".into());
                }
            }
        }
    };
    // Wait for authorization, SSH setup and audit to complete on the daemon.
    // During this phase no keyboard bytes are forwarded to the remote shell.
    loop {
        tokio::select! {
            _ = &mut deadline => return Err("Bastion session setup timed out".into()),
            _ = poll.tick() => {
                if event::poll(Duration::ZERO)? && matches!(event::read()?, Event::Key(k) if k.code == KeyCode::Esc) {
                    return Ok("Connection cancelled".into());
                }
            }
            message = socket.next() => match message.ok_or("Bastion disconnected before ready")?? {
                Message::Text(text) => match serde_json::from_str::<Control>(&text)? {
                    Control::Ready { version: 1, session_id } if !session_id.is_empty() => break,
                    Control::Ready { .. } => return Err("Unsupported bastion protocol version or empty session ID".into()),
                    Control::Error { message } => return Err(label(&message).into()),
                    Control::Exit { .. } => return Err("Bastion session exited before ready".into()),
                },
                Message::Ping(bytes) => send_frame(&mut socket, Message::Pong(bytes)).await?,
                Message::Pong(_) => {},
                _ => return Err("Expected bastion ready event before terminal data".into()),
            }
        }
    }
    execute!(
        io::stdout(),
        crossterm::style::ResetColor,
        cursor::MoveTo(0, 0),
        terminal::Clear(ClearType::All),
        cursor::Show
    )?;
    // macOS kqueue cannot register the /dev/tty alias: open the concrete
    // terminal device instead, with an independent nonblocking file description.
    let mut name = [0u8; 1024];
    // SAFETY: name is writable for its full length; stdin is a checked TTY.
    let status =
        unsafe { libc::ttyname_r(libc::STDIN_FILENO, name.as_mut_ptr().cast(), name.len()) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status).into());
    }
    let end = name
        .iter()
        .position(|&b| b == 0)
        .ok_or("Invalid terminal device name")?;
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(std::ffi::OsStr::from_bytes(&name[..end]))?;
    let input = AsyncFd::new(tty)?;
    let mut buffer = [0u8; 8192];
    let mut size = (cols, rows);
    let mut resize = tokio::time::interval(Duration::from_millis(100));
    let mut ping = tokio::time::interval(Duration::from_secs(20));
    ping.tick().await;
    let mut last_received = tokio::time::Instant::now();
    loop {
        tokio::select! {
            ready = input.readable() => {
                let mut ready = ready?;
                match ready.try_io(|inner| inner.get_ref().read(&mut buffer)) {
                    Ok(Ok(0)) => { let _ = tokio::time::timeout(Duration::from_secs(1), socket.close(None)).await; return Ok("Local terminal closed".into()); }
                    Ok(Ok(count)) => send_frame(&mut socket, Message::Binary(buffer[..count].to_vec().into())).await?,
                    Ok(Err(error)) => return Err(error.into()),
                    Err(_) => {}
                }
            }
            message = socket.next() => {
                let Some(message) = message else { return Err("Bastion disconnected without an exit status".into()) };
                last_received = tokio::time::Instant::now();
                match message? {
                    Message::Binary(bytes) => { let mut out = io::stdout(); out.write_all(&bytes)?; out.flush()?; }
                    Message::Text(text) => match serde_json::from_str::<Control>(&text)? {
                        Control::Ready { .. } => return Err("Unexpected duplicate ready event".into()),
                        Control::Error { message } => { let _ = tokio::time::timeout(Duration::from_secs(1), socket.close(None)).await; return Err(label(&message).into()); }
                        Control::Exit { status } => { let _ = tokio::time::timeout(Duration::from_secs(1), socket.close(None)).await; return Ok(format!("Shell exited (status {})", status.map(|v| v.to_string()).unwrap_or_else(|| "unknown".into()))); }
                    },
                    Message::Ping(bytes) => send_frame(&mut socket, Message::Pong(bytes)).await?,
                    Message::Close(_) => return Err("Bastion closed the terminal without an exit status".into()),
                    _ => {}
                }
            }
            _ = resize.tick() => {
                let current = terminal::size()?;
                if current != size {
                    size = current;
                    send_frame(&mut socket, Message::Text(serde_json::to_string(&Resize::new(size.0, size.1))?.into())).await?;
                }
            }
            _ = ping.tick() => {
                if last_received.elapsed() > Duration::from_secs(60) { return Err("Bastion connection lost (keepalive timeout)".into()); }
                send_frame(&mut socket, Message::Ping(Vec::new().into())).await?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Run through examples/verify-terminal.py to supply a controlling PTY.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires a controlling PTY; see examples/verify-terminal.py"]
    #[allow(clippy::result_large_err)] // tungstenite's handshake callback requires this error type
    async fn raw_terminal_fixture() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = secure_url(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let mode = std::env::var("BASTION_FIXTURE_MODE").unwrap_or_else(|_| "success".into());
        let server_mode = mode.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_hdr_async(
                stream,
                |request: &tokio_tungstenite::tungstenite::handshake::server::Request, response| {
                    assert_eq!(request.headers()["Authorization"], "Bearer fixture-token");
                    assert_eq!(request.uri().path(), "/api/v1/terminal");
                    assert!(!request.uri().to_string().contains("fixture-token"));
                    Ok(response)
                },
            )
            .await
            .unwrap();
            if server_mode == "cancel" {
                println!("FIXTURE_WAITING_READY");
                std::future::pending::<()>().await;
            }
            if server_mode == "error" {
                socket
                    .send(Message::Text(
                        r#"{"type":"error","message":"fixture denied"}"#.into(),
                    ))
                    .await
                    .unwrap();
                return;
            }
            socket
                .send(Message::Text(
                    r#"{"type":"ready","version":1,"session_id":"fixture"}"#.into(),
                ))
                .await
                .unwrap();
            socket
                .send(Message::Binary(b"FIXTURE_SHELL_READY\r\n".to_vec().into()))
                .await
                .unwrap();
            let mut input = Vec::new();
            let mut resized = false;
            while input.len() < 6 || !resized {
                match socket.next().await.unwrap().unwrap() {
                    Message::Binary(bytes) => input.extend_from_slice(&bytes),
                    Message::Text(text) => {
                        let resize: serde_json::Value = serde_json::from_str(&text).unwrap();
                        assert_eq!(
                            resize,
                            serde_json::json!({"type":"resize", "version":1, "cols":100, "rows":35})
                        );
                        resized = true;
                    }
                    Message::Ping(bytes) => socket.send(Message::Pong(bytes)).await.unwrap(),
                    other => panic!("Unexpected fixture frame: {other:?}"),
                }
            }
            assert_eq!(input, [3, 0xc3, 0xa9, 0x1b, b'[', b'A']);
            socket
                .send(Message::Text(r#"{"type":"exit","status":0}"#.into()))
                .await
                .unwrap();
        });
        assert!(!terminal::is_raw_mode_enabled().unwrap());
        let guard = TerminalGuard::enter().unwrap();
        let mut items = vec![
            "Fixture staging".to_owned(),
            "Fixture production".to_owned(),
        ];
        items.extend((0..30).map(|i| format!("Fixture production {i}")));
        let rows = items
            .iter()
            .map(|item| vec![item.clone()])
            .collect::<Vec<_>>();
        let mut picker_state = PickerState::default();
        let selected = table_picker(
            "FIXTURE_HOST_LIST",
            &rows,
            &["Name"],
            |i, q| items[i].to_lowercase().contains(&q.to_lowercase()),
            "",
            &[],
            &mut picker_state,
        )
        .await
        .unwrap();
        assert_eq!(selected, Some(items.len() - 1));
        assert_eq!(picker_state.query, "production");
        assert!(picker_state.table.offset() > 0);
        let original_offset = picker_state.table.offset();
        if mode == "panic" {
            install_panic_hook();
            panic!("FIXTURE_EXPECTED_PANIC");
        }
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            terminal_session(&base, "fixture-token", "fixture", "user"),
        )
        .await
        .unwrap();
        assert_eq!(
            table_picker(
                "FIXTURE_RETURNED_LIST",
                &rows,
                &["Name"],
                |i, q| items[i].to_lowercase().contains(&q.to_lowercase()),
                "Session ended; q or Esc to leave",
                &[],
                &mut picker_state,
            )
            .await
            .unwrap(),
            None
        );
        assert_eq!(picker_state.query, "production");
        assert_eq!(picker_state.selected, items.len() - 2);
        if mode != "success" {
            assert_eq!(picker_state.table.offset(), original_offset);
        }
        drop(guard);
        assert!(!terminal::is_raw_mode_enabled().unwrap());
        match mode.as_str() {
            "cancel" => {
                assert_eq!(result.unwrap(), "Connection cancelled");
                server.abort();
            }
            "error" => {
                assert_eq!(result.unwrap_err().to_string(), "fixture denied");
                server.await.unwrap();
            }
            _ => {
                assert_eq!(result.unwrap(), "Shell exited (status 0)");
                server.await.unwrap();
            }
        }
        println!("FIXTURE_RESTORED");
    }

    #[test]
    fn secure_urls() {
        for url in [
            "https://bastion.example",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "http://[::1]:8000",
        ] {
            assert!(secure_url(url).is_ok(), "{url}");
        }
        for url in [
            "http://bastion.example",
            "http://localhost.evil",
            "ws://localhost",
            "https://user:pass@example.org",
            "https://example.org?token=x",
            "https://example.org#fragment",
        ] {
            assert!(secure_url(url).is_err(), "{url}");
        }
    }
    #[test]
    fn config_profiles() {
        let input = "[bastions.\"example.org\"]\nurl='https://example.org'\nissuer='https://idm.example.org'\nclient_id='bastion-client'\ntenant='acme'\nscopes=['openid','bastion']";
        let profile = profile_from(input, "example.org").unwrap();
        assert_eq!(profile.tenant.as_deref(), Some("acme"));
        assert_eq!(profile.scopes, ["openid", "bastion", "bastion:connect"]);
        assert!(
            profile_from(input, "unknown")
                .unwrap_err()
                .to_string()
                .contains("Unknown bastion")
        );
        assert!(profile_from(&input.replace("https://idm", "http://idm"), "example.org").is_err());
    }
    #[test]
    fn filtering() {
        let host = Host {
            address: "host.example".into(),
            port: 22,
            resolved_ips: vec![],
            id: "db-1".into(),
            name: "Database".into(),
            environment: "Production".into(),
            description: "Primary PostgreSQL".into(),
            logins: vec!["postgres".into()],
        };
        for query in ["", "PROD postgres", "db-1", "primary", "host.example"] {
            assert!(matches(&host, query));
        }
        assert!(!matches(&host, "staging"));
        assert_eq!(label("a\x1b\n\rb"), "ab");
    }
    fn screen(ui: &ratatui::Terminal<ratatui::backend::TestBackend>) -> String {
        let buffer = ui.backend().buffer();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn table_scrolls_to_selected_host_and_handles_small_terminals() {
        use ratatui::{Terminal, backend::TestBackend, widgets::TableState};
        let items = (0..40)
            .map(|i| {
                vec![
                    format!("NUC {i:02}"),
                    format!("nuc{i}.cluster"),
                    format!("192.168.125.{i}"),
                    "mares".into(),
                    "infra".into(),
                ]
            })
            .collect::<Vec<_>>();
        let indices = (0..40).collect::<Vec<_>>();
        let mut state = TableState::default().with_selected(Some(39));
        let context = vec!["Welcome to Bastion!".into(), "Signed in as: mares".into()];
        let mut ui = Terminal::new(TestBackend::new(100, 24)).unwrap();
        ui.draw(|frame| {
            draw_picker(
                frame,
                "Hosts",
                &items,
                &["Name", "Hostname", "IP address", "Account", "Environment"],
                &indices,
                "",
                "Shell exited (status 0)",
                &context,
                &mut state,
                false,
            )
        })
        .unwrap();
        let rendered = screen(&ui);
        for text in [
            "Welcome to Bastion!",
            "Signed in as: mares",
            "Filter by host",
            "NUC 39",
            "nuc39.cluster",
            "192.168.125.39",
            "Shell exited",
            "▲",
            "▼",
        ] {
            assert!(rendered.contains(text), "{text}: {rendered}");
        }
        assert!(state.offset() > 0);
        assert!(!rendered.contains("NUC 00"));
        for (width, height) in [(80, 24), (40, 12), (12, 4), (1, 1)] {
            let mut ui = Terminal::new(TestBackend::new(width, height)).unwrap();
            ui.draw(|frame| {
                draw_picker(
                    frame,
                    "Hosts",
                    &items,
                    &["Name"],
                    &[],
                    "Český filtr 界界界",
                    "",
                    &context,
                    &mut state,
                    false,
                )
            })
            .unwrap();
        }
    }

    #[test]
    fn catalog_identity_is_server_metadata_and_old_catalog_is_supported() {
        let mut catalog: Catalog = serde_json::from_value(serde_json::json!({
            "identity": {"username":"alice", "subject":"user-1", "tenant":"tenant-1"},
            "bastion": {"id":"router-1"}, "hosts": []
        }))
        .unwrap();
        catalog.peer_ip = Some("192.168.125.100".parse().unwrap());
        let context = catalog
            .context(&secure_url("https://bastion.example").unwrap())
            .join("\n");
        for text in [
            "alice",
            "user-1",
            "tenant-1",
            "router-1",
            "bastion.example",
            "192.168.125.100",
        ] {
            assert!(context.contains(text));
        }
        let old: Catalog = serde_json::from_str(r#"{"hosts":[]}"#).unwrap();
        assert!(
            old.context(&secure_url("https://bastion.example").unwrap())
                .join("\n")
                .contains("identity unavailable")
        );
    }

    #[test]
    fn protocol_and_query() {
        let base = secure_url("https://example.org").unwrap();
        let url = terminal_url(&base, "a&b", "user+name", 80, 24, "xterm").unwrap();
        assert_eq!(url.scheme(), "wss");
        assert!(url.query_pairs().any(|(k, v)| k == "host_id" && v == "a&b"));
        assert!(!url.as_str().contains("Bearer"));
        assert!(matches!(
            serde_json::from_str::<Control>(r#"{"type":"exit","status":0}"#).unwrap(),
            Control::Exit { status: Some(0) }
        ));
        assert!(matches!(
            serde_json::from_str::<Control>(r#"{"type":"error","message":"denied"}"#).unwrap(),
            Control::Error { .. }
        ));
    }
}
