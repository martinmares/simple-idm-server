//! Local/remote file manager. File bytes are streamed, never buffered as a whole.
use crate::bastion::label;
use crate::file_ops::*;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
#[cfg(test)]
use futures_util::{SinkExt, StreamExt};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{
        Block, Borders, Clear, Gauge, Paragraph, Row, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Table, TableState, Wrap,
    },
};
use russh_sftp::client::SftpSession;
#[cfg(test)]
use russh_sftp::protocol::FileType;
#[cfg(test)]
use std::path::PathBuf;
use std::{
    collections::HashMap,
    ffi::OsString,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
#[cfg(test)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
#[cfg(test)]
use tokio_tungstenite::tungstenite::Message;
use url::Url;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone)]
struct DirectoryPosition {
    filter: String,
    selected: Option<OsString>,
    table: TableState,
}
struct Panel {
    path: Location,
    entries: Vec<Entry>,
    filter: String,
    table: TableState,
    loading: bool,
    history: HashMap<Location, DirectoryPosition>,
}
impl Panel {
    fn new(path: Location) -> Self {
        Self {
            path,
            entries: Vec::new(),
            filter: String::new(),
            table: TableState::default().with_selected(0),
            loading: true,
            history: HashMap::new(),
        }
    }
    fn apply_listing(&mut self, path: Location, entries: Vec<Entry>) {
        let selected = self.selected().map(|entry| entry.name.clone());
        let selection = if self.path != path {
            let exited = (path == self.path.parent())
                .then(|| self.path.name())
                .flatten();
            self.history.insert(
                self.path.clone(),
                DirectoryPosition {
                    filter: self.filter.clone(),
                    selected,
                    table: self.table.clone(),
                },
            );
            self.path = path;
            if let Some(position) = self.history.get(&self.path) {
                self.filter = position.filter.clone();
                self.table = position.table.clone();
                exited.or_else(|| position.selected.clone())
            } else {
                self.filter.clear();
                self.table = TableState::default().with_selected(0);
                exited
            }
        } else {
            selected
        };
        self.entries = entries;
        let visible = self.visible();
        let index = selection
            .and_then(|name| visible.iter().position(|&i| self.entries[i].name == name))
            .unwrap_or_else(|| {
                self.table
                    .selected()
                    .unwrap_or(0)
                    .min(visible.len().saturating_sub(1))
            });
        self.table.select((!visible.is_empty()).then_some(index));
        self.loading = false;
    }
    fn visible(&self) -> Vec<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                e.name
                    .to_string_lossy()
                    .to_lowercase()
                    .contains(&self.filter.to_lowercase())
            })
            .map(|(i, _)| i)
            .collect()
    }
    fn selected(&self) -> Option<&Entry> {
        self.visible()
            .get(self.table.selected().unwrap_or(0))
            .map(|&i| &self.entries[i])
    }
}
#[derive(Debug)]
struct Viewer {
    title: String,
    lines: Vec<String>,
    row: usize,
    column: u16,
    wrap: bool,
}
impl Viewer {
    fn paragraph(&self) -> Paragraph<'static> {
        let paragraph = Paragraph::new(self.lines.join("\n"));
        if self.wrap {
            paragraph.wrap(Wrap { trim: false })
        } else {
            paragraph
        }
    }
    fn scroll_limit(&self, width: u16, height: u16) -> usize {
        self.paragraph()
            .line_count(width.saturating_sub(2))
            .saturating_sub(usize::from(height.saturating_sub(3).max(1)))
    }
    fn toggle_wrap(&mut self) {
        self.wrap = !self.wrap;
        self.row = 0;
        self.column = 0;
    }
}

#[derive(Clone)]
enum Action {
    List(usize, Location),
    Inspect(Location, InspectKind),
    Copy {
        source: Location,
        destination: Location,
        overwrite: bool,
    },
    Rename {
        source: Location,
        destination: Location,
    },
    Mkdir(Location),
    Delete {
        path: Location,
        directory: bool,
    },
}
enum Update {
    Listed(usize, Location, WorkResult<Vec<Entry>>),
    Inspected(WorkResult<Viewer>),
    Progress(u64, u64),
    Done(WorkResult<()>),
    Collision(Action),
}
async fn connect(
    base: &Url,
    token: &str,
    host: &str,
    login: &str,
    sudo_readonly: bool,
) -> Result<(SftpSession, Task)> {
    crate::file_ops::connect(base, token, host, login, sudo_readonly)
        .await
        .map_err(|e| e as Box<dyn std::error::Error>)
}
async fn copy(
    sftp: &SftpSession,
    source: &Location,
    dest: &Location,
    overwrite: bool,
    cancel: &AtomicBool,
    updates: &mpsc::Sender<Update>,
) -> WorkResult<()> {
    crate::file_ops::copy(sftp, source, dest, overwrite, cancel, &|done, total| {
        let _ = updates.try_send(Update::Progress(done, total));
    })
    .await
}
async fn inspect(
    sftp: &SftpSession,
    path: &Location,
    kind: InspectKind,
    cancel: &AtomicBool,
    updates: &mpsc::Sender<Update>,
) -> WorkResult<Viewer> {
    let inspected = crate::file_ops::inspect(sftp, path, kind, cancel, &|done, total| {
        let _ = updates.try_send(Update::Progress(done, total));
    })
    .await?;
    Ok(Viewer {
        title: inspected.title,
        lines: inspected.lines,
        row: 0,
        column: 0,
        wrap: false,
    })
}
fn writes_remote(action: &Action) -> bool {
    match action {
        Action::Copy { destination, .. } => matches!(destination, Location::Remote(_)),
        Action::Rename { source, .. } => matches!(source, Location::Remote(_)),
        Action::Mkdir(path) | Action::Delete { path, .. } => matches!(path, Location::Remote(_)),
        _ => false,
    }
}

async fn worker(
    sftp: SftpSession,
    mut commands: mpsc::Receiver<Action>,
    updates: mpsc::Sender<Update>,
    cancel: Arc<AtomicBool>,
    sudo_readonly: bool,
) {
    while let Some(action) = commands.recv().await {
        if let Action::List(side, path) = action {
            let result = list(&sftp, &path).await;
            if updates
                .send(Update::Listed(side, path, result))
                .await
                .is_err()
            {
                break;
            }
            continue;
        }
        if let Action::Inspect(path, kind) = &action {
            let result = inspect(&sftp, path, *kind, &cancel, &updates).await;
            if updates.send(Update::Inspected(result)).await.is_err() {
                break;
            }
            continue;
        }
        if sudo_readonly && writes_remote(&action) {
            let _ = updates
                .send(Update::Done(Err(
                    "Remote panel is root read-only; switch back with e to upload or modify files"
                        .into(),
                )))
                .await;
            continue;
        }
        let result = match &action {
            Action::Copy {
                source,
                destination,
                overwrite,
            } => match exists(&sftp, destination).await {
                Ok(true) if !overwrite => {
                    let _ = updates.send(Update::Collision(action.clone())).await;
                    continue;
                }
                Err(e) => Err(e),
                _ => copy(&sftp, source, destination, *overwrite, &cancel, &updates).await,
            },
            Action::Rename {
                source,
                destination,
            } => match exists(&sftp, destination).await {
                Ok(true) => Err("Destination already exists".into()),
                Err(e) => Err(e),
                Ok(false) => rename(&sftp, source, destination).await,
            },
            Action::Mkdir(path) => match path {
                Location::Local(p) => tokio::fs::create_dir(p).await.map_err(error),
                Location::Remote(p) => sftp.create_dir(p.clone()).await.map_err(error),
            },
            Action::Delete { path, directory } => remove(&sftp, path, *directory).await,
            Action::List(..) | Action::Inspect(..) => unreachable!(),
        };
        if updates.send(Update::Done(result)).await.is_err() {
            break;
        }
    }
    let _ = sftp.close().await;
}

struct Dialog {
    title: String,
    input: String,
    action: Action,
    edit: bool,
}
struct Manager {
    panels: [Panel; 2],
    active: usize,
    filter_edit: Option<String>,
    dialog: Option<Dialog>,
    viewer: Option<Viewer>,
    busy: bool,
    notice: String,
    progress: Option<(u64, u64, Instant)>,
    sudo_readonly: bool,
}
impl Manager {
    fn request(
        &mut self,
        commands: &mpsc::Sender<Action>,
        side: usize,
        path: Location,
    ) -> WorkResult<()> {
        commands.try_send(Action::List(side, path)).map_err(error)?;
        self.panels[side].loading = true;
        Ok(())
    }
    fn submit(
        &mut self,
        commands: &mpsc::Sender<Action>,
        cancel: &AtomicBool,
        action: Action,
    ) -> WorkResult<()> {
        cancel.store(false, Ordering::Relaxed);
        commands.try_send(action).map_err(error)?;
        self.busy = true;
        self.notice = "Working… Esc: cancel".into();
        Ok(())
    }
}

pub async fn run(
    base: &Url,
    token: &str,
    host: &str,
    name: &str,
    login: &str,
    context: &[String],
) -> Result<String> {
    let mut ui = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    ui.clear()?;
    ui.draw(|f| f.render_widget(Paragraph::new("Connecting file session…"), f.area()))?;
    let setup = connect(base, token, host, login, false);
    tokio::pin!(setup);
    let (sftp, mut transport) = loop {
        tokio::select! {
            result=&mut setup=>break result?,
            _=tokio::time::sleep(Duration::from_millis(50))=>if event::poll(Duration::ZERO)? && matches!(event::read()?,Event::Key(k) if k.code==KeyCode::Esc){return Ok("File connection cancelled".into());}
        }
    };
    let home = sftp.canonicalize(".").await?;
    let cancel = Arc::new(AtomicBool::new(false));
    let (mut commands, receiver) = mpsc::channel(8);
    let (updates, mut events) = mpsc::channel(16);
    let mut worker_task = Task(tokio::spawn(worker(
        sftp,
        receiver,
        updates,
        cancel.clone(),
        false,
    )));
    let mut app = Manager {
        panels: [
            Panel::new(Location::Local(std::env::current_dir()?)),
            Panel::new(Location::Remote(home)),
        ],
        active: 0,
        filter_edit: None,
        dialog: None,
        viewer: None,
        busy: false,
        notice: "Ready".into(),
        progress: None,
        sudo_readonly: false,
    };
    for side in 0..2 {
        app.request(&commands, side, app.panels[side].path.clone())?;
    }
    let mut redraw = true;
    loop {
        while let Ok(update) = events.try_recv() {
            redraw = true;
            match update {
                Update::Listed(side, path, result) => {
                    let panel = &mut app.panels[side];
                    panel.loading = false;
                    match result {
                        Ok(entries) => {
                            panel.apply_listing(path, entries);
                        }
                        Err(e) => app.notice = label(&e),
                    }
                }
                Update::Inspected(result) => {
                    app.busy = false;
                    app.progress = None;
                    match result {
                        Ok(viewer) => {
                            app.viewer = Some(viewer);
                            app.notice = "Ready".into();
                        }
                        Err(e) => app.notice = label(&e),
                    }
                }
                Update::Progress(done, total) => {
                    let start = app.progress.map(|p| p.2).unwrap_or_else(Instant::now);
                    app.progress = Some((done, total, start));
                }
                Update::Done(result) => {
                    app.busy = false;
                    app.notice = result
                        .map(|_| "Operation completed".into())
                        .unwrap_or_else(|e| label(&e));
                    for side in 0..2 {
                        app.request(&commands, side, app.panels[side].path.clone())?;
                    }
                }
                Update::Collision(mut action) => {
                    if let Action::Copy { overwrite, .. } = &mut action {
                        *overwrite = true;
                    }
                    app.busy = false;
                    app.dialog = Some(Dialog {
                        title:
                            "Destination exists — Enter: overwrite, Esc: skip, type another name"
                                .into(),
                        input: if let Action::Copy { destination, .. } = &action {
                            match destination {
                                Location::Local(p) => {
                                    p.file_name().unwrap().to_string_lossy().into_owned()
                                }
                                Location::Remote(p) => p.rsplit('/').next().unwrap().into(),
                            }
                        } else {
                            String::new()
                        },
                        action,
                        edit: true,
                    });
                }
            }
        }
        if redraw {
            ui.draw(|frame| draw(frame, &mut app, name, login, context))?;
            redraw = false;
        }
        if !event::poll(Duration::ZERO)? {
            tokio::time::sleep(Duration::from_millis(40)).await;
            continue;
        }
        let input_event = event::read()?;
        if matches!(input_event, Event::Resize(_, _)) {
            redraw = true;
        }
        let Event::Key(key) = input_event else {
            continue;
        };
        redraw = true;
        if key.kind == KeyEventKind::Release {
            continue;
        }
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            cancel.store(true, Ordering::Relaxed);
            break;
        }
        if let Some(viewer) = &mut app.viewer {
            let dimensions = ui.size()?;
            let page = usize::from(dimensions.height.saturating_sub(3)).max(1);
            let last_row = viewer.scroll_limit(dimensions.width, dimensions.height);
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => app.viewer = None,
                KeyCode::Down => viewer.row = (viewer.row + 1).min(last_row),
                KeyCode::Up => viewer.row = viewer.row.saturating_sub(1),
                KeyCode::PageDown => viewer.row = (viewer.row + page).min(last_row),
                KeyCode::PageUp => viewer.row = viewer.row.saturating_sub(page),
                KeyCode::Home => viewer.row = 0,
                KeyCode::End => viewer.row = last_row,
                KeyCode::Char('w') => viewer.toggle_wrap(),
                KeyCode::Left if !viewer.wrap => viewer.column = viewer.column.saturating_sub(4),
                KeyCode::Right if !viewer.wrap => {
                    viewer.column = viewer.column.saturating_add(4).min(4096)
                }
                _ => {}
            }
            continue;
        }
        if app.busy {
            if matches!(key.code, KeyCode::Esc | KeyCode::Char('q')) {
                cancel.store(true, Ordering::Relaxed);
                app.notice = "Cancelling…".into();
            }
            continue;
        }
        if let Some(mut dialog) = app.dialog.take() {
            match key.code {
                KeyCode::Esc => {
                    app.notice = "Operation skipped".into();
                    continue;
                }
                KeyCode::Enter => {
                    let mut action = dialog.action;
                    if dialog.edit {
                        if !valid_name(&dialog.input) {
                            app.notice = "Enter a single filename, without / or ..".into();
                            app.dialog = Some(Dialog { action, ..dialog });
                            continue;
                        }
                        let name: OsString = dialog.input.into();
                        match &mut action {
                            Action::Copy {
                                destination,
                                overwrite,
                                ..
                            } => {
                                let new = destination.parent().child(&name);
                                *overwrite = *overwrite && new == *destination;
                                *destination = new;
                            }
                            Action::Rename { destination, .. } => {
                                *destination = destination.parent().child(&name)
                            }
                            Action::Mkdir(path) => *path = path.parent().child(&name),
                            _ => {}
                        }
                    }
                    app.progress = None;
                    app.submit(&commands, &cancel, action)?;
                    continue;
                }
                KeyCode::Backspace if dialog.edit => {
                    dialog.input.pop();
                }
                KeyCode::Char('u')
                    if dialog.edit && key.modifiers.contains(KeyModifiers::CONTROL) =>
                {
                    dialog.input.clear()
                }
                KeyCode::Char(c)
                    if dialog.edit
                        && !key
                            .modifiers
                            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    dialog.input.push(c)
                }
                _ => {}
            }
            app.dialog = Some(dialog);
            continue;
        }
        if app.filter_edit.is_some() {
            let panel = &mut app.panels[app.active];
            match key.code {
                KeyCode::Enter => {
                    app.filter_edit = None;
                }
                KeyCode::Esc => panel.filter = app.filter_edit.take().unwrap(),
                KeyCode::Backspace => {
                    panel.filter.pop();
                    panel.table.select(Some(0));
                }
                KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    panel.filter.clear();
                    panel.table.select(Some(0));
                }
                KeyCode::Char(c)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    panel.filter.push(c);
                    panel.table.select(Some(0));
                }
                _ => {}
            }
            continue;
        }
        let side = app.active;
        if app.panels[side].loading {
            if matches!(key.code, KeyCode::Char('q') | KeyCode::Esc) {
                break;
            }
            continue;
        }
        let count = app.panels[side].visible().len();
        let selected = app.panels[side].table.selected().unwrap_or(0);
        let page = usize::from(ui.size()?.height.saturating_sub(10)).max(1);
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            continue;
        }
        let command_key = match key.code {
            KeyCode::Char('c' | 's') => KeyCode::F(5),
            KeyCode::Char('r') => KeyCode::F(6),
            KeyCode::Char('n') => KeyCode::F(7),
            KeyCode::Char('d') => KeyCode::F(8),
            KeyCode::Char('u') => KeyCode::F(4),
            key => key,
        };
        if app.sudo_readonly
            && ((side == 1 && matches!(command_key, KeyCode::F(6) | KeyCode::F(7) | KeyCode::F(8)))
                || (side == 0 && command_key == KeyCode::F(5)))
        {
            app.notice = "Root panel is read-only; press e to return to the login account".into();
            continue;
        }
        match command_key {
            KeyCode::Char('e') => {
                if app.panels[1].loading {
                    app.notice = "Wait for the remote listing to finish".into();
                    continue;
                }
                let target = !app.sudo_readonly;
                app.notice = if target {
                    "Opening root read-only session… Esc: cancel".into()
                } else {
                    "Returning to login account… Esc: cancel".into()
                };
                ui.draw(|frame| draw(frame, &mut app, name, login, context))?;
                let current = app.panels[1].path.clone();
                let setup = async {
                    let (sftp, transport) = connect(base, token, host, login, target).await?;
                    let (path, entries) = match list(&sftp, &current).await {
                        Ok(entries) => (current, entries),
                        Err(_) => {
                            let home = Location::Remote(sftp.canonicalize(".").await?);
                            let entries = list(&sftp, &home).await?;
                            (home, entries)
                        }
                    };
                    Ok::<_, Box<dyn std::error::Error>>((sftp, transport, path, entries))
                };
                tokio::pin!(setup);
                let connected = loop {
                    tokio::select! {
                        result=&mut setup=>break result,
                        _=tokio::time::sleep(Duration::from_millis(50))=>{
                            if event::poll(Duration::ZERO)? && matches!(event::read()?,Event::Key(k) if matches!(k.code,KeyCode::Esc|KeyCode::Char('q'))) { break Err("Mode switch cancelled".into()); }
                        }
                    }
                };
                match connected {
                    Ok((sftp, new_transport, path, entries)) => {
                        let (sender, receiver) = mpsc::channel(8);
                        let (updates, receiver_updates) = mpsc::channel(16);
                        worker_task.0.abort();
                        worker_task = Task(tokio::spawn(worker(
                            sftp,
                            receiver,
                            updates,
                            cancel.clone(),
                            target,
                        )));
                        transport = new_transport;
                        commands = sender;
                        events = receiver_updates;
                        app.sudo_readonly = target;
                        app.progress = None;
                        let panel = &mut app.panels[1];
                        panel.apply_listing(path, entries);
                        app.notice = if target {
                            "Root READ ONLY — downloads, preview and SHA-256 allowed; e returns to login account".into()
                        } else {
                            "Returned to login account".into()
                        };
                    }
                    Err(e) => app.notice = format!("Mode unchanged: {}", label(&e.to_string())),
                }
            }
            KeyCode::Char('q') | KeyCode::Esc => break,
            KeyCode::Tab | KeyCode::BackTab => app.active = 1 - side,
            KeyCode::Char('/') => app.filter_edit = Some(app.panels[side].filter.clone()),
            KeyCode::Up => app.panels[side]
                .table
                .select(Some(selected.saturating_sub(1))),
            KeyCode::Down => app.panels[side]
                .table
                .select(Some((selected + 1).min(count.saturating_sub(1)))),
            KeyCode::PageUp => app.panels[side]
                .table
                .select(Some(selected.saturating_sub(page))),
            KeyCode::PageDown => app.panels[side]
                .table
                .select(Some((selected + page).min(count.saturating_sub(1)))),
            KeyCode::Home => app.panels[side].table.select(Some(0)),
            KeyCode::End => app.panels[side].table.select(Some(count.saturating_sub(1))),
            KeyCode::F(4) => {
                for i in 0..2 {
                    app.request(&commands, i, app.panels[i].path.clone())?;
                }
            }
            KeyCode::F(7) => {
                let path = app.panels[side]
                    .path
                    .child(&OsString::from("new-directory"));
                app.dialog = Some(Dialog {
                    title: "Create directory — Enter: create, Esc: cancel".into(),
                    input: "new-directory".into(),
                    action: Action::Mkdir(path),
                    edit: true,
                });
            }
            KeyCode::Enter | KeyCode::Backspace => {
                let next = if command_key == KeyCode::Backspace {
                    Some(app.panels[side].path.parent())
                } else {
                    app.panels[side]
                        .selected()
                        .filter(|e| e.kind.is_dir())
                        .map(|e| {
                            if e.name == ".." {
                                app.panels[side].path.parent()
                            } else {
                                app.panels[side].path.child(&e.name)
                            }
                        })
                };
                if let Some(next) = next {
                    app.request(&commands, side, next)?;
                } else {
                    app.notice = "Enter opens directories; c/s/F5 copies regular files".into();
                }
            }
            KeyCode::Char('h') | KeyCode::Char('v') | KeyCode::F(3) => {
                if let Some(entry) = app.panels[side].selected().filter(|e| e.kind.is_file()) {
                    let source = app.panels[side].path.child(&entry.name);
                    let kind = if command_key == KeyCode::Char('h') {
                        InspectKind::Hash
                    } else {
                        InspectKind::Preview
                    };
                    app.progress = None;
                    app.submit(&commands, &cancel, Action::Inspect(source, kind))?;
                } else {
                    app.notice = "Select a regular file for SHA-256 or preview".into();
                }
            }
            KeyCode::F(5) | KeyCode::F(6) | KeyCode::F(8) => {
                if let Some(entry) = app.panels[side].selected().cloned() {
                    if entry.name == ".." {
                        continue;
                    }
                    let source = app.panels[side].path.child(&entry.name);
                    match command_key {
                        KeyCode::F(5) if entry.kind.is_file()=>{
                            if app.panels[1-side].loading {continue;}
                            let dest=app.panels[1-side].path.child(&entry.name);
                            app.dialog=Some(Dialog{title:format!("Copy to {} — Enter: copy, Esc: cancel",dest.parent().display()),input:entry.name.to_string_lossy().into_owned(),action:Action::Copy{source,destination:dest,overwrite:false},edit:true});
                        }
                        KeyCode::F(6)=>app.dialog=Some(Dialog{title:"Rename — Enter: rename, Esc: cancel".into(),input:entry.name.to_string_lossy().into_owned(),action:Action::Rename{source:source.clone(),destination:source},edit:true}),
                        KeyCode::F(8)=>app.dialog=Some(Dialog{title:"Delete — Enter: confirm, Esc: cancel".into(),input:source.display(),action:Action::Delete{path:source,directory:entry.kind.is_dir()},edit:false}),
                        _=>app.notice="First version copies regular files only; directories and symlinks are not copied".into(),
                    }
                }
            }
            _ => {}
        }
    }
    drop(worker_task);
    drop(transport);
    Ok("File manager closed".into())
}

fn size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1048576 {
        format!("{:.1} KiB", bytes as f64 / 1024.)
    } else {
        format!("{:.1} MiB", bytes as f64 / 1048576.)
    }
}
fn draw(
    frame: &mut ratatui::Frame,
    app: &mut Manager,
    name: &str,
    login: &str,
    context: &[String],
) {
    let layout = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(5),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .split(frame.area());
    let identity = context
        .iter()
        .find(|s| s.starts_with("Signed in"))
        .cloned()
        .unwrap_or_default();
    frame.render_widget(Paragraph::new(format!("{}\nRemote: {} · account: {}{}\nTab: switch panel · /: filter · Enter: directory · Backspace: parent",label(&identity),label(name),label(login),if app.sudo_readonly {" → root · READ ONLY"}else{""})).style(Style::default().fg(Color::Cyan)),layout[0]);
    let panels = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(layout[1]);
    for (side, area) in panels.iter().enumerate() {
        let p = &mut app.panels[side];
        let indices = p.visible();
        let selected = p
            .table
            .selected()
            .unwrap_or(0)
            .min(indices.len().saturating_sub(1));
        p.table.select((!indices.is_empty()).then_some(selected));
        let parts = Layout::vertical([
            Constraint::Length(2),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .split(*area);
        frame.render_widget(
            Paragraph::new(format!(
                "{}\nFilter: {}{}",
                p.path.display(),
                label(&p.filter),
                if app.active == side && app.filter_edit.is_some() {
                    "▏"
                } else {
                    ""
                }
            ))
            .style(Style::default().fg(
                if app.active == side && app.filter_edit.is_some() {
                    Color::Cyan
                } else {
                    Color::Reset
                },
            )),
            parts[0],
        );
        let rows = indices.iter().map(|&i| {
            let e = &p.entries[i];
            Row::new(vec![
                e.display(),
                if e.kind.is_dir() {
                    "<DIR>".into()
                } else if e.kind.is_symlink() {
                    "<LINK>".into()
                } else {
                    size(e.size)
                },
            ])
        });
        let table = Table::new(rows, [Constraint::Min(8), Constraint::Length(12)])
            .header(Row::new(["Name", "Size"]).style(Style::default().fg(Color::Cyan)))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(if side == 0 {
                        " LOCAL "
                    } else if app.sudo_readonly {
                        " REMOTE · ROOT READ ONLY "
                    } else {
                        " REMOTE "
                    })
                    .border_style(Style::default().fg(if app.active == side {
                        if side == 1 && app.sudo_readonly {
                            Color::Yellow
                        } else {
                            Color::Cyan
                        }
                    } else {
                        if side == 1 && app.sudo_readonly {
                            Color::Yellow
                        } else {
                            Color::DarkGray
                        }
                    })),
            )
            .row_highlight_style(
                Style::default()
                    .bg(if app.active == side {
                        Color::Blue
                    } else {
                        Color::DarkGray
                    })
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");
        frame.render_stateful_widget(table, parts[1], &mut p.table);
        let mut scroll = ScrollbarState::new(indices.len()).position(selected);
        if parts[1].width > 2 && parts[1].height > 2 {
            frame.render_stateful_widget(
                Scrollbar::new(ScrollbarOrientation::VerticalRight)
                    .begin_symbol(Some("▲"))
                    .end_symbol(Some("▼")),
                Rect {
                    x: parts[1].x,
                    y: parts[1].y + 1,
                    width: parts[1].width,
                    height: parts[1].height - 2,
                },
                &mut scroll,
            );
        }
        frame.render_widget(
            Paragraph::new(if p.loading {
                "Loading…".into()
            } else {
                format!(
                    "{} / {} entries",
                    indices
                        .iter()
                        .filter(|&&i| p.entries[i].name != "..")
                        .count(),
                    p.entries.len().saturating_sub(1)
                )
            }),
            parts[2],
        );
    }
    if let Some((done, total, start)) = app.progress {
        let ratio = if total == 0 {
            0.
        } else {
            (done as f64 / total as f64).min(1.)
        };
        let speed = done as f64 / start.elapsed().as_secs_f64().max(0.1);
        frame.render_widget(
            Gauge::default()
                .block(Block::default().borders(Borders::ALL).title(if app.busy {
                    " Progress — Esc: cancel "
                } else {
                    " Progress "
                }))
                .gauge_style(Style::default().fg(Color::Cyan))
                .ratio(ratio)
                .label(format!(
                    "{} / {} · {}/s",
                    size(done),
                    size(total),
                    size(speed as u64)
                )),
            layout[2],
        );
    } else {
        frame.render_widget(Paragraph::new("Files are transferred through the bastion; directories are not copied recursively."),layout[2]);
    }
    frame.render_widget(Paragraph::new(label(&app.notice)), layout[3]);
    frame.render_widget(
        Paragraph::new(
            "e root/user  v view  h SHA256  c/s copy  r rename  n mkdir  d del  u reload  q back",
        ),
        layout[4],
    );
    if let Some(viewer) = &mut app.viewer {
        let area = frame.area();
        frame.render_widget(Clear, area);
        let parts = Layout::vertical([Constraint::Min(3), Constraint::Length(1)]).split(area);
        viewer.row = viewer.row.min(viewer.scroll_limit(area.width, area.height));
        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!(
                "wrap {} · {}",
                if viewer.wrap { "ON" } else { "OFF" },
                label(&viewer.title)
            ))
            .border_style(Style::default().fg(Color::Cyan));
        frame.render_widget(
            viewer
                .paragraph()
                .scroll((viewer.row.min(u16::MAX as usize) as u16, viewer.column))
                .block(block),
            parts[0],
        );
        frame.render_widget(
            Paragraph::new(if viewer.wrap {
                "w: wrap OFF  ↑/↓ PgUp/PgDn Home/End: scroll  q/Esc/Enter: close"
            } else {
                "w: wrap ON  ↑/↓ PgUp/PgDn: scroll  ←/→: horizontal  q/Esc: close"
            }),
            parts[1],
        );
    }
    if let Some(dialog) = &app.dialog {
        let a = frame.area();
        let width = a.width.saturating_sub(4).min(100);
        let height = 5.min(a.height);
        let area = Rect {
            x: a.x + (a.width - width) / 2,
            y: a.y + (a.height - height) / 2,
            width,
            height,
        };
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(label(&dialog.input)).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(label(&dialog.title))
                    .border_style(Style::default().fg(Color::Cyan)),
            ),
            area,
        );
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn directory_return_restores_filter_selection_and_scroll_on_both_panels() {
        for parent in [
            Location::Local("/tmp".into()),
            Location::Remote("/home/mares".into()),
        ] {
            let entries = || {
                (0..100)
                    .map(|i| Entry {
                        name: format!("folder-{i:03}").into(),
                        kind: FileType::Dir,
                        size: 0,
                    })
                    .collect::<Vec<_>>()
            };
            let mut panel = Panel::new(parent.clone());
            panel.apply_listing(parent.clone(), entries());
            panel.filter = "FOLDER".into();
            panel.table.select(Some(70));
            *panel.table.offset_mut() = 60;
            let child = parent.child(&panel.selected().unwrap().name);
            panel.apply_listing(
                child.clone(),
                vec![Entry {
                    name: "..".into(),
                    kind: FileType::Dir,
                    size: 0,
                }],
            );
            assert_eq!(panel.table.selected(), Some(0));
            assert!(panel.filter.is_empty());
            let mut updated = entries();
            updated.insert(
                0,
                Entry {
                    name: "folder-new".into(),
                    kind: FileType::Dir,
                    size: 0,
                },
            );
            panel.apply_listing(parent.clone(), updated);
            assert_eq!(panel.selected().unwrap().name, "folder-070");
            assert_eq!(panel.filter, "FOLDER");
            assert_eq!(panel.table.offset(), 60);
            // Re-entering also restores the child directory's selection.
            panel.apply_listing(
                child,
                vec![Entry {
                    name: "..".into(),
                    kind: FileType::Dir,
                    size: 0,
                }],
            );
            assert_eq!(panel.selected().unwrap().name, "..");
        }
    }
    #[test]
    fn first_parent_visit_selects_exited_directory() {
        let mut panel = Panel::new(Location::Remote("/home/mares".into()));
        panel.apply_listing(
            Location::Remote("/home".into()),
            vec![
                Entry {
                    name: "other".into(),
                    kind: FileType::Dir,
                    size: 0,
                },
                Entry {
                    name: "mares".into(),
                    kind: FileType::Dir,
                    size: 0,
                },
            ],
        );
        assert_eq!(panel.selected().unwrap().name, "mares");
    }
    #[test]
    fn names_cannot_escape_destination() {
        for name in ["", ".", "..", "/tmp/x", "a/b", "a\\b", "x\0y", "x\ny"] {
            assert!(!valid_name(name));
        }
        assert!(valid_name("nginx.conf"));
    }
    #[test]
    fn remote_paths_use_posix_and_root_is_stable() {
        let root = Location::Remote("/".into());
        assert_eq!(root.parent(), root);
        let child = root.child(&"app.jar".into());
        assert_eq!(child, Location::Remote("/app.jar".into()));
        assert_eq!(child.parent(), root);
    }

    #[test]
    fn preview_uses_text_or_safe_hex_and_marks_truncation() {
        let (kind, lines) = preview_lines("Hello Žluťoučký\r\nworld\t!".as_bytes(), false);
        assert_eq!(kind, "Text");
        assert_eq!(lines, ["Hello Žluťoučký", "world    !"]);
        for bytes in [&b"\x00\xffabc"[..], &b"\x1b[31m"[..]] {
            let (kind, lines) = preview_lines(bytes, false);
            assert_eq!(kind, "Hex");
            assert!(lines[0].starts_with("00000000"));
            assert!(!lines.iter().any(|s| s.contains('\x1b')));
        }
        let (kind, lines) = preview_lines(&[b'a', 0xc3], true);
        assert_eq!(kind, "Text");
        assert_eq!(lines[0], "a");
        assert!(lines.last().unwrap().contains("limited"));
    }

    #[tokio::test]
    async fn elevated_session_requires_explicit_server_confirmation() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let task = Task(tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            ws.send(Message::Text(
                r#"{"type":"ready","version":1,"session_id":"old-daemon"}"#.into(),
            ))
            .await
            .unwrap();
            let _ = ws.next().await;
        }));
        match connect(&base, "token", "host", "mares", true).await {
            Ok(_) => panic!("accepted an unconfirmed root mode"),
            Err(e) => assert!(e.to_string().contains("did not confirm")),
        }
        drop(task);
    }
    #[test]
    fn read_only_mode_allows_downloads_and_inspection_but_blocks_remote_mutations() {
        let local = Location::Local("/tmp/file".into());
        let remote = Location::Remote("/root/file".into());
        assert!(!writes_remote(&Action::Copy {
            source: remote.clone(),
            destination: local.clone(),
            overwrite: false
        }));
        assert!(!writes_remote(&Action::Inspect(
            remote.clone(),
            InspectKind::Preview
        )));
        assert!(!writes_remote(&Action::Inspect(
            remote.clone(),
            InspectKind::Hash
        )));
        assert!(writes_remote(&Action::Copy {
            source: local,
            destination: remote.clone(),
            overwrite: false
        }));
        assert!(writes_remote(&Action::Rename {
            source: remote.clone(),
            destination: remote.clone()
        }));
        assert!(writes_remote(&Action::Mkdir(remote.clone())));
        assert!(writes_remote(&Action::Delete {
            path: remote,
            directory: false
        }));
    }
    #[test]
    fn wrapped_view_scrolls_all_display_rows_and_preserves_indentation() {
        let mut view = Viewer {
            title: "Text".into(),
            lines: vec![format!("    {}", "abcdefghij".repeat(20))],
            row: 9,
            column: 12,
            wrap: false,
        };
        assert_eq!(view.scroll_limit(22, 8), 0);
        view.toggle_wrap();
        assert!(view.wrap);
        assert_eq!((view.row, view.column), (0, 0));
        assert!(view.scroll_limit(22, 8) > 0);
        let limit = view.scroll_limit(22, 8);
        let mut ui = Terminal::new(ratatui::backend::TestBackend::new(20, 3)).unwrap();
        ui.draw(|f| f.render_widget(view.paragraph(), f.area()))
            .unwrap();
        assert_eq!(ui.backend().buffer()[(0, 0)].symbol(), " ");
        assert_eq!(ui.backend().buffer()[(4, 0)].symbol(), "a");
        view.row = limit;
        ui.draw(|f| f.render_widget(view.paragraph().scroll((view.row as u16, 0)), f.area()))
            .unwrap();
        view.toggle_wrap();
        assert!(!view.wrap);
        assert_eq!(view.row, 0);
    }
    #[test]
    fn filename_filter_is_case_insensitive() {
        let mut panel = Panel::new(Location::Remote("/".into()));
        panel.entries = vec![
            Entry {
                name: "APP.JAR".into(),
                kind: FileType::File,
                size: 0,
            },
            Entry {
                name: "Žluťoučký.txt".into(),
                kind: FileType::File,
                size: 0,
            },
        ];
        panel.filter = "app".into();
        assert_eq!(panel.visible(), [0]);
        panel.filter = "ŽLUŤ".into();
        assert_eq!(panel.visible(), [1]);
        panel.filter = "missing".into();
        assert!(panel.visible().is_empty());
    }
    #[tokio::test]
    #[ignore = "requires local OpenSSH sftp-server; run explicitly for transport integration"]
    async fn websocket_sftp_roundtrip_collisions_and_cancel() {
        tokio::time::timeout(Duration::from_secs(45), async {
            let root = tempfile::tempdir().unwrap();
            let (base, fixture) = fixture(root.path()).await;
            let (sftp, _bridge) = connect(&base, "fixture-token", "fixture", "fixture", false)
                .await
                .unwrap();
            let remote = Location::Remote(sftp.canonicalize(".").await.unwrap());
            let local = tempfile::tempdir().unwrap();
            let source = Location::Local(local.path().join("source.bin"));
            let payload = (0..262144).map(|i| (i % 256) as u8).collect::<Vec<_>>();
            tokio::fs::write(local.path().join("source.bin"), &payload)
                .await
                .unwrap();
            let dest = remote.child(&"žluťoučký.bin".into());
            let cancel = AtomicBool::new(false);
            let (updates, mut receiver) = mpsc::channel(128);
            copy(&sftp, &source, &dest, false, &cancel, &updates)
                .await
                .unwrap();
            assert_eq!(
                sftp.read(match &dest {
                    Location::Remote(p) => p.clone(),
                    _ => unreachable!(),
                })
                .await
                .unwrap(),
                payload
            );
            assert!(
                list(&sftp, &remote)
                    .await
                    .unwrap()
                    .iter()
                    .any(|e| e.name == "žluťoučký.bin")
            );
            tokio::fs::write(local.path().join("source.bin"), b"replacement")
                .await
                .unwrap();
            assert!(
                copy(&sftp, &source, &dest, false, &cancel, &updates)
                    .await
                    .is_err()
            );
            assert_eq!(
                sftp.read(match &dest {
                    Location::Remote(p) => p.clone(),
                    _ => unreachable!(),
                })
                .await
                .unwrap(),
                payload
            );
            copy(&sftp, &source, &dest, true, &cancel, &updates)
                .await
                .unwrap();
            let download = Location::Local(local.path().join("download.bin"));
            copy(&sftp, &dest, &download, false, &cancel, &updates)
                .await
                .unwrap();
            assert_eq!(
                tokio::fs::read(local.path().join("download.bin"))
                    .await
                    .unwrap(),
                b"replacement"
            );
            tokio::fs::write(local.path().join("download.bin"), b"old-local")
                .await
                .unwrap();
            copy(&sftp, &dest, &download, true, &cancel, &updates)
                .await
                .unwrap();
            assert_eq!(
                tokio::fs::read(local.path().join("download.bin"))
                    .await
                    .unwrap(),
                b"replacement"
            );
            cancel.store(true, Ordering::Relaxed);
            assert!(
                inspect(&sftp, &dest, InspectKind::Hash, &cancel, &updates)
                    .await
                    .unwrap_err()
                    .contains("cancelled")
            );
            let cancelled = remote.child(&"cancelled.bin".into());
            assert!(
                copy(&sftp, &source, &cancelled, false, &cancel, &updates)
                    .await
                    .unwrap_err()
                    .contains("cancelled")
            );
            assert!(!exists(&sftp, &cancelled).await.unwrap());
            assert!(
                !list(&sftp, &remote)
                    .await
                    .unwrap()
                    .iter()
                    .any(|e| e.name.to_string_lossy().starts_with(".simple-idm-"))
            );
            assert!(receiver.try_recv().is_ok());
            let renamed = remote.child(&"renamed.bin".into());
            rename(&sftp, &dest, &renamed).await.unwrap();
            remove(&sftp, &renamed, false).await.unwrap();
            let directory = remote.child(&"directory".into());
            if let Location::Remote(p) = &directory {
                sftp.create_dir(p.clone()).await.unwrap();
            }
            cancel.store(false, Ordering::Relaxed);
            assert!(
                copy(&sftp, &source, &directory, true, &cancel, &updates)
                    .await
                    .is_err()
            );
            assert!(exists(&sftp, &directory).await.unwrap());
            remove(&sftp, &directory, true).await.unwrap();

            let (readonly, _readonly_bridge) =
                connect(&base, "fixture-token", "fixture", "fixture", true)
                    .await
                    .unwrap();
            let secret = root.path().join("protected.txt");
            tokio::fs::write(&secret, b"root-readable").await.unwrap();
            let remote_secret = Location::Remote(secret.to_str().unwrap().into());
            assert!(
                inspect(
                    &readonly,
                    &remote_secret,
                    InspectKind::Preview,
                    &cancel,
                    &updates
                )
                .await
                .is_ok()
            );
            assert!(
                readonly
                    .write(secret.to_str().unwrap(), b"overwrite")
                    .await
                    .is_err()
            );
            assert!(
                readonly
                    .remove_file(secret.to_str().unwrap())
                    .await
                    .is_err()
            );
            let download = Location::Local(local.path().join("protected.txt"));
            copy(
                &readonly,
                &remote_secret,
                &download,
                false,
                &cancel,
                &updates,
            )
            .await
            .unwrap();
            assert_eq!(
                tokio::fs::read(local.path().join("protected.txt"))
                    .await
                    .unwrap(),
                b"root-readable"
            );
            drop(fixture);
        })
        .await
        .expect("SFTP fixture timed out");
    }
    pub(crate) async fn fixture(root: &std::path::Path) -> (Url, Task) {
        let binary = [
            "/usr/libexec/sftp-server",
            "/usr/lib/openssh/sftp-server",
            "/usr/lib/ssh/sftp-server",
        ]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .expect("install OpenSSH sftp-server");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let remote_root = root.to_path_buf();
        let fixture = Task(tokio::spawn(async move {
            let mut clients = tokio::task::JoinSet::new();
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let remote_root = remote_root.clone();
                clients.spawn(async move {
            let readonly=Arc::new(AtomicBool::new(false));
            let requested=readonly.clone();
            let terminal=Arc::new(AtomicBool::new(false));
            let requested_terminal=terminal.clone();
            let mut ws = tokio_tungstenite::accept_hdr_async(
                stream,
                move |request: &tokio_tungstenite::tungstenite::handshake::server::Request, response| {
                    assert!(request.uri().path().ends_with("/files") || request.uri().path().ends_with("/terminal"));
                    requested_terminal.store(request.uri().path().ends_with("/terminal"),Ordering::Relaxed);
                    requested.store(request.uri().query().unwrap_or("").contains("sudo_readonly=true"),Ordering::Relaxed);
                    assert_eq!(request.headers()["authorization"], "Bearer fixture-token");
                    Ok(response)
                },
            )
            .await
            .unwrap();
            if terminal.load(Ordering::Relaxed) {
                ws.send(Message::Text(serde_json::json!({"type":"ready","version":1,"session_id":"fixture"}).to_string().into())).await.unwrap();
                ws.send(Message::Binary(b"Bastion terminal fixture\r\n$ ".to_vec().into())).await.unwrap();
                while let Some(Ok(message)) = ws.next().await {
                    match message {
                        Message::Binary(bytes) => { if ws.send(Message::Binary(bytes)).await.is_err() { break; } },
                        Message::Text(text) => { let value:serde_json::Value=serde_json::from_str(&text).unwrap();assert_eq!(value["type"],"resize"); },
                        Message::Ping(bytes) => { let _=ws.send(Message::Pong(bytes)).await; },
                        Message::Pong(_) => {},
                        _ => break,
                    }
                }
                return;
            }
            let mut command=tokio::process::Command::new(binary);
            command.arg("-e");if readonly.load(Ordering::Relaxed){command.arg("-R");}
            let mut child = command.current_dir(remote_root).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).kill_on_drop(true).spawn().unwrap();
            let mut input = child.stdin.take().unwrap();
            let mut output = child.stdout.take().unwrap();
            ws.send(Message::Text(
                serde_json::json!({"type":"ready","version":1,"session_id":"fixture","sudo_readonly":readonly.load(Ordering::Relaxed)}).to_string().into(),
            ))
            .await
            .unwrap();
            ws.send(Message::Ping(vec![1, 2, 3].into())).await.unwrap();
            let mut buffer = [0; 4096];
            loop {
                tokio::select! {
                    count = output.read(&mut buffer) => {
                        let count = count.unwrap(); if count == 0 {break;}
                        // Deliberately split SFTP packets across WebSocket messages.
                        for chunk in buffer[..count].chunks(127) { if ws.send(Message::Binary(chunk.to_vec().into())).await.is_err() {return;} }
                    }
                    frame = ws.next() => match frame {
                        Some(Ok(Message::Binary(bytes))) => input.write_all(&bytes).await.unwrap(),
                        Some(Ok(Message::Pong(_))) => {},
                        _ => break,
                    }
                }
            }
            let _ = child.start_kill();
            let _ = child.wait().await;
                });
            }
        }));
        (base, fixture)
    }

    #[tokio::test]
    #[ignore = "requires controlling terminal; see examples/verify-files.py"]
    async fn file_manager_terminal_fixture() {
        let root = PathBuf::from(std::env::var("FILES_FIXTURE_ROOT").unwrap());
        let (base, _fixture) = fixture(&root).await;
        let guard = crate::bastion::TerminalGuard::enter().unwrap();
        run(
            &base,
            "fixture-token",
            "fixture",
            "Fixture",
            "fixture",
            &["Signed in as: fixture".into()],
        )
        .await
        .unwrap();
        drop(guard);
        println!("FIXTURE_FILES_DONE");
    }
    #[test]
    fn panels_render_small_terminals_and_scroll_selection() {
        for (width, height) in [(20, 6), (80, 24), (140, 40)] {
            let mut app = Manager {
                panels: [
                    Panel::new(Location::Local("/tmp".into())),
                    Panel::new(Location::Remote("/home/fixture".into())),
                ],
                active: 1,
                filter_edit: None,
                dialog: None,
                viewer: None,
                busy: false,
                notice: "Ready".into(),
                progress: None,
                sudo_readonly: false,
            };
            app.panels[1].entries = (0..100)
                .map(|i| Entry {
                    name: format!("file-{i:03}").into(),
                    kind: FileType::File,
                    size: 1024,
                })
                .collect();
            app.panels[1].table.select(Some(99));
            let mut ui = Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
            ui.draw(|f| draw(f, &mut app, "fixture", "fixture", &[]))
                .unwrap();
            if height > 10 {
                assert!(app.panels[1].table.offset() > 0);
            }
        }
    }
}
