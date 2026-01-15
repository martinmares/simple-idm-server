use anyhow::{anyhow, Context, Result};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Tabs},
    Terminal,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use rand::RngCore;
use serde_json::json;
use std::{io, time::Duration};
use tui_input::{backend::crossterm::EventHandler, Input};
use url::Url;

use crate::{ClaimMapRow, ClientRow, GroupRow, HttpClient, UserGroupRow, UserRow};

const PAGE_SIZE: usize = 25;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tab {
    Users,
    Groups,
    Clients,
    ClaimMaps,
    UserGroups,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Normal,
    Form,
    Picker,
}

#[derive(Clone, Debug)]
enum FieldKind {
    Text,
    Secret,
    Bool,
}

#[derive(Clone, Debug)]
struct FormField {
    label: &'static str,
    kind: FieldKind,
    optional: bool,
    input: Input,
    reveal: bool,
}

impl FormField {
    fn new(label: &'static str, value: String) -> Self {
        Self {
            label,
            kind: FieldKind::Text,
            optional: false,
            input: input_with_value(value),
            reveal: false,
        }
    }

    fn secret(label: &'static str, value: String) -> Self {
        Self {
            label,
            kind: FieldKind::Secret,
            optional: false,
            input: input_with_value(value),
            reveal: false,
        }
    }

    fn boolean(label: &'static str, value: bool) -> Self {
        Self {
            label,
            kind: FieldKind::Bool,
            optional: false,
            input: input_with_value(value.to_string()),
            reveal: false,
        }
    }

    fn optional(mut self) -> Self {
        self.optional = true;
        self
    }

    fn display(&self) -> String {
        match self.kind {
            FieldKind::Secret => {
                if self.reveal {
                    self.input.value().to_string()
                } else {
                    "*".repeat(self.input.value().len())
                }
            }
            _ => self.input.value().to_string(),
        }
    }

    fn toggle_bool(&mut self) {
        let val = self.input.value().eq_ignore_ascii_case("true");
        let next = (!val).to_string();
        self.input = input_with_value(next);
    }

    fn value(&self) -> String {
        self.input.value().to_string()
    }

}

#[derive(Clone, Debug)]
enum FormAction {
    CreateUser,
    UpdateUser(String),
    DeleteUser(String),
    CreateGroup,
    UpdateGroup(String),
    DeleteGroup(String),
    CreateClient,
    UpdateClient(String),
    DeleteClient(String),
    CreateClaimMap,
    DeleteClaimMap(String),
    AddUserGroup,
    RemoveUserGroup,
}

#[derive(Clone, Debug)]
struct FormState {
    title: String,
    action: FormAction,
    fields: Vec<FormField>,
    index: usize,
    error: Option<String>,
}

struct EntityState<T> {
    items: Vec<T>,
    state: TableState,
    page: usize,
}

impl<T> EntityState<T> {
    fn new() -> Self {
        Self {
            items: Vec::new(),
            state: TableState::default(),
            page: 1,
        }
    }

    fn selected(&self) -> Option<usize> {
        self.state.selected()
    }

    fn select_first(&mut self) {
        if self.items.is_empty() {
            self.state.select(None);
        } else {
            self.state.select(Some(0));
        }
    }

    fn select_next(&mut self) {
        if self.items.is_empty() {
            self.state.select(None);
            return;
        }
        let next = match self.state.selected() {
            Some(idx) => (idx + 1).min(self.items.len() - 1),
            None => 0,
        };
        self.state.select(Some(next));
    }

    fn select_prev(&mut self) {
        if self.items.is_empty() {
            self.state.select(None);
            return;
        }
        let prev = match self.state.selected() {
            Some(idx) => idx.saturating_sub(1),
            None => 0,
        };
        self.state.select(Some(prev));
    }
}

struct App {
    tab: Tab,
    users: EntityState<UserRow>,
    groups: EntityState<GroupRow>,
    clients: EntityState<ClientRow>,
    claim_maps: EntityState<ClaimMapRow>,
    user_groups: EntityState<UserGroupRow>,
    mode: Mode,
    form: Option<FormState>,
    status: String,
    pending_select: Option<SelectHint>,
    picker: Option<PickerState>,
}

impl App {
    fn new() -> Self {
        Self {
            tab: Tab::Users,
            users: EntityState::new(),
            groups: EntityState::new(),
            clients: EntityState::new(),
            claim_maps: EntityState::new(),
            user_groups: EntityState::new(),
            mode: Mode::Normal,
            form: None,
            status: String::new(),
            pending_select: None,
            picker: None,
        }
    }

    fn tabs() -> Vec<(Tab, &'static str)> {
        vec![
            (Tab::Users, "Users"),
            (Tab::Groups, "Groups"),
            (Tab::Clients, "Clients"),
            (Tab::ClaimMaps, "Claim maps"),
            (Tab::UserGroups, "User groups"),
        ]
    }

    fn set_status(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
    }
}

#[derive(Clone, Debug)]
struct PickerOption {
    label: &'static str,
    value: &'static str,
    selected: bool,
}

#[derive(Clone, Debug)]
struct PickerState {
    title: String,
    options: Vec<PickerOption>,
    index: usize,
    target_field: &'static str,
}

impl PickerState {
    fn new_grant_types(selected: &[String]) -> Self {
        let options = supported_grant_types()
            .iter()
            .map(|(label, value)| PickerOption {
                label,
                value,
                selected: selected.iter().any(|item| item == value),
            })
            .collect();

        Self {
            title: "Select grant types".to_string(),
            options,
            index: 0,
            target_field: "grant_types",
        }
    }

    fn selected_values(&self) -> Vec<String> {
        self.options
            .iter()
            .filter(|opt| opt.selected)
            .map(|opt| opt.value.to_string())
            .collect()
    }
}

fn supported_grant_types() -> Vec<(&'static str, &'static str)> {
    vec![
        ("authorization_code", "authorization_code"),
        ("refresh_token", "refresh_token"),
        ("client_credentials", "client_credentials"),
        ("device_code", "urn:ietf:params:oauth:grant-type:device_code"),
    ]
}
#[derive(Clone, Debug)]
struct SelectHint {
    tab: Tab,
    id: String,
}

pub async fn run_tui(http: &HttpClient) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    refresh_active_tab(&mut app, http).await?;

    let res = event_loop(&mut terminal, http, &mut app).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    res
}

async fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    http: &HttpClient,
    app: &mut App,
) -> Result<()> {
    loop {
        terminal.draw(|frame| draw_ui(frame, app))?;

        if !event::poll(Duration::from_millis(200))? {
            continue;
        }

        let event = event::read()?;
        if app.mode == Mode::Picker {
            let handled = handle_picker_event(app, event)?;
            if handled == PickerResult::Applied || handled == PickerResult::Cancelled {
                app.mode = Mode::Form;
            }
            continue;
        }

        if app.mode == Mode::Form {
            let handled = handle_form_event(app, event, http).await?;
            if handled == FormResult::Submitted || handled == FormResult::Cancelled {
                app.mode = Mode::Normal;
                app.form = None;
                refresh_active_tab(app, http).await?;
            }
            continue;
        }

        if let Event::Key(key) = event {
            if handle_normal_key(app, key, http).await? {
                break;
            }
        }
    }

    Ok(())
}

async fn handle_normal_key(app: &mut App, key: KeyEvent, http: &HttpClient) -> Result<bool> {
    match key.code {
        KeyCode::Char('q') => return Ok(true),
        KeyCode::Tab => next_tab(app, http).await?,
        KeyCode::BackTab => prev_tab(app, http).await?,
        KeyCode::Down => select_next(app),
        KeyCode::Up => select_prev(app),
        KeyCode::Char('r') => refresh_active_tab(app, http).await?,
        KeyCode::Char('[') => page_prev(app, http).await?,
        KeyCode::Char(']') => page_next(app, http).await?,
        KeyCode::Char('n') => {
            if let Err(err) = open_create_form(app) {
                app.set_status(err.to_string());
            }
        }
        KeyCode::Char('e') => {
            if let Err(err) = open_edit_form(app) {
                app.set_status(err.to_string());
            }
        }
        KeyCode::Char('d') => {
            if let Err(err) = open_delete_form(app) {
                app.set_status(err.to_string());
            }
        }
        KeyCode::Char('a') => {
            if let Err(err) = open_add_user_group(app) {
                app.set_status(err.to_string());
            }
        }
        KeyCode::Char('x') => {
            if let Err(err) = open_remove_user_group(app) {
                app.set_status(err.to_string());
            }
        }
        _ => {}
    }
    Ok(false)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PickerResult {
    Continue,
    Applied,
    Cancelled,
}

fn handle_picker_event(app: &mut App, event: Event) -> Result<PickerResult> {
    let Some(picker) = app.picker.as_mut() else {
        return Ok(PickerResult::Cancelled);
    };

    let Event::Key(key) = event else {
        return Ok(PickerResult::Continue);
    };

    match key.code {
        KeyCode::Esc => {
            app.picker = None;
            return Ok(PickerResult::Cancelled);
        }
        KeyCode::Up => {
            picker.index = picker.index.saturating_sub(1);
        }
        KeyCode::Down => {
            picker.index = (picker.index + 1).min(picker.options.len().saturating_sub(1));
        }
        KeyCode::Char(' ') => {
            if let Some(option) = picker.options.get_mut(picker.index) {
                option.selected = !option.selected;
            }
        }
        KeyCode::Enter => {
            if let Some(form) = app.form.as_mut() {
                let values = picker.selected_values();
                set_field_value(form, picker.target_field, values.join(", "));
            }
            app.picker = None;
            return Ok(PickerResult::Applied);
        }
        _ => {}
    }

    Ok(PickerResult::Continue)
}

fn select_next(app: &mut App) {
    match app.tab {
        Tab::Users => app.users.select_next(),
        Tab::Groups => app.groups.select_next(),
        Tab::Clients => app.clients.select_next(),
        Tab::ClaimMaps => app.claim_maps.select_next(),
        Tab::UserGroups => app.user_groups.select_next(),
    }
}

fn select_prev(app: &mut App) {
    match app.tab {
        Tab::Users => app.users.select_prev(),
        Tab::Groups => app.groups.select_prev(),
        Tab::Clients => app.clients.select_prev(),
        Tab::ClaimMaps => app.claim_maps.select_prev(),
        Tab::UserGroups => app.user_groups.select_prev(),
    }
}

async fn next_tab(app: &mut App, http: &HttpClient) -> Result<()> {
    let tabs = App::tabs();
    let idx = tabs
        .iter()
        .position(|(tab, _)| *tab == app.tab)
        .unwrap_or(0);
    let next = (idx + 1) % tabs.len();
    app.tab = tabs[next].0;
    refresh_active_tab(app, http).await
}

async fn prev_tab(app: &mut App, http: &HttpClient) -> Result<()> {
    let tabs = App::tabs();
    let idx = tabs
        .iter()
        .position(|(tab, _)| *tab == app.tab)
        .unwrap_or(0);
    let prev = if idx == 0 { tabs.len() - 1 } else { idx - 1 };
    app.tab = tabs[prev].0;
    refresh_active_tab(app, http).await
}

async fn page_next(app: &mut App, http: &HttpClient) -> Result<()> {
    match app.tab {
        Tab::Users => app.users.page += 1,
        Tab::Groups => app.groups.page += 1,
        Tab::Clients => app.clients.page += 1,
        Tab::ClaimMaps => app.claim_maps.page += 1,
        Tab::UserGroups => app.user_groups.page += 1,
    }
    refresh_active_tab(app, http).await
}

async fn page_prev(app: &mut App, http: &HttpClient) -> Result<()> {
    match app.tab {
        Tab::Users => app.users.page = app.users.page.saturating_sub(1).max(1),
        Tab::Groups => app.groups.page = app.groups.page.saturating_sub(1).max(1),
        Tab::Clients => app.clients.page = app.clients.page.saturating_sub(1).max(1),
        Tab::ClaimMaps => app.claim_maps.page = app.claim_maps.page.saturating_sub(1).max(1),
        Tab::UserGroups => app.user_groups.page = app.user_groups.page.saturating_sub(1).max(1),
    }
    refresh_active_tab(app, http).await
}

async fn refresh_active_tab(app: &mut App, http: &HttpClient) -> Result<()> {
    match app.tab {
        Tab::Users => {
            match fetch_users(http, app.users.page).await {
                Ok(users) => {
                    app.users.items = users;
                    apply_selection(app, EntityKind::Users);
                }
                Err(err) => app.set_status(err.to_string()),
            }
        }
        Tab::Groups => {
            match fetch_groups(http, app.groups.page).await {
                Ok(groups) => {
                    app.groups.items = groups;
                    apply_selection(app, EntityKind::Groups);
                }
                Err(err) => app.set_status(err.to_string()),
            }
        }
        Tab::Clients => {
            match fetch_clients(http, app.clients.page).await {
                Ok(clients) => {
                    app.clients.items = clients;
                    apply_selection(app, EntityKind::Clients);
                }
                Err(err) => app.set_status(err.to_string()),
            }
        }
        Tab::ClaimMaps => {
            match fetch_claim_maps(http, app.claim_maps.page).await {
                Ok(maps) => {
                    app.claim_maps.items = maps;
                    apply_selection(app, EntityKind::ClaimMaps);
                }
                Err(err) => app.set_status(err.to_string()),
            }
        }
        Tab::UserGroups => {
            match fetch_user_groups(http, app.user_groups.page).await {
                Ok(rows) => {
                    app.user_groups.items = rows;
                    apply_selection(app, EntityKind::UserGroups);
                }
                Err(err) => app.set_status(err.to_string()),
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum EntityKind {
    Users,
    Groups,
    Clients,
    ClaimMaps,
    UserGroups,
}

fn apply_selection(app: &mut App, kind: EntityKind) {
    let hint = app.pending_select.clone();
    let mut matched = false;

    if let Some(hint) = hint {
        match kind {
            EntityKind::Users if hint.tab == Tab::Users => {
                if let Some(idx) = app.users.items.iter().position(|u| u.id == hint.id) {
                    app.users.state.select(Some(idx));
                    matched = true;
                }
            }
            EntityKind::Groups if hint.tab == Tab::Groups => {
                if let Some(idx) = app.groups.items.iter().position(|g| g.id == hint.id) {
                    app.groups.state.select(Some(idx));
                    matched = true;
                }
            }
            EntityKind::Clients if hint.tab == Tab::Clients => {
                if let Some(idx) = app.clients.items.iter().position(|c| c.id == hint.id) {
                    app.clients.state.select(Some(idx));
                    matched = true;
                }
            }
            EntityKind::ClaimMaps if hint.tab == Tab::ClaimMaps => {
                if let Some(idx) = app
                    .claim_maps
                    .items
                    .iter()
                    .position(|c| c.id == hint.id)
                {
                    app.claim_maps.state.select(Some(idx));
                    matched = true;
                }
            }
            EntityKind::UserGroups if hint.tab == Tab::UserGroups => {
                if let Some(idx) = app
                    .user_groups
                    .items
                    .iter()
                    .position(|row| row.user_id == hint.id)
                {
                    app.user_groups.state.select(Some(idx));
                    matched = true;
                }
            }
            _ => {}
        }
        app.pending_select = None;
    }

    if !matched {
        match kind {
            EntityKind::Users => app.users.select_first(),
            EntityKind::Groups => app.groups.select_first(),
            EntityKind::Clients => app.clients.select_first(),
            EntityKind::ClaimMaps => app.claim_maps.select_first(),
            EntityKind::UserGroups => app.user_groups.select_first(),
        }
    }
}

async fn fetch_users(http: &HttpClient, page: usize) -> Result<Vec<UserRow>> {
    let path = format!("/admin/users?page={page}&limit={PAGE_SIZE}");
    let body = http.get(&path).await?;
    serde_json::from_str(&body).map_err(|e| anyhow!("Failed to parse users: {e}"))
}

async fn fetch_groups(http: &HttpClient, page: usize) -> Result<Vec<GroupRow>> {
    let path = format!("/admin/groups?page={page}&limit={PAGE_SIZE}");
    let body = http.get(&path).await?;
    serde_json::from_str(&body).map_err(|e| anyhow!("Failed to parse groups: {e}"))
}

async fn fetch_clients(http: &HttpClient, page: usize) -> Result<Vec<ClientRow>> {
    let path = format!("/admin/oauth-clients?page={page}&limit={PAGE_SIZE}");
    let body = http.get(&path).await?;
    serde_json::from_str(&body).map_err(|e| anyhow!("Failed to parse clients: {e}"))
}

async fn fetch_claim_maps(http: &HttpClient, page: usize) -> Result<Vec<ClaimMapRow>> {
    let path = format!("/admin/claim-maps?page={page}&limit={PAGE_SIZE}");
    let body = http.get(&path).await?;
    serde_json::from_str(&body).map_err(|e| anyhow!("Failed to parse claim maps: {e}"))
}

async fn fetch_user_groups(http: &HttpClient, page: usize) -> Result<Vec<UserGroupRow>> {
    let path = format!("/admin/user-groups?page={page}&limit={PAGE_SIZE}");
    let body = http.get(&path).await?;
    serde_json::from_str(&body).map_err(|e| anyhow!("Failed to parse user groups: {e}"))
}

fn open_create_form(app: &mut App) -> Result<()> {
    let form = match app.tab {
        Tab::Users => FormState {
            title: "Create user".to_string(),
            action: FormAction::CreateUser,
            fields: vec![
                FormField::new("username", String::new()),
                FormField::new("email", String::new()),
                FormField::secret("password", String::new()),
                FormField::boolean("is_active", true),
            ],
            index: 0,
            error: None,
        },
        Tab::Groups => FormState {
            title: "Create group".to_string(),
            action: FormAction::CreateGroup,
            fields: vec![
                FormField::new("name", String::new()),
                FormField::new("description", String::new()).optional(),
            ],
            index: 0,
            error: None,
        },
        Tab::Clients => FormState {
            title: "Create client".to_string(),
            action: FormAction::CreateClient,
            fields: vec![
                FormField::new("client_id", String::new()),
                FormField::secret("client_secret", String::new()),
                FormField::new("name", String::new()),
                FormField::new("redirect_uris", String::new()).optional(),
                FormField::new("grant_types", String::new()),
                FormField::new("scope", String::new()),
                FormField::boolean("is_active", true),
            ],
            index: 0,
            error: None,
        },
        Tab::ClaimMaps => FormState {
            title: "Create claim map".to_string(),
            action: FormAction::CreateClaimMap,
            fields: vec![
                FormField::new("client_id", String::new()),
                FormField::new("group_id", String::new()),
                FormField::new("claim_name", String::new()),
                FormField::new("claim_value", String::new()).optional(),
            ],
            index: 0,
            error: None,
        },
        Tab::UserGroups => FormState {
            title: "Add user to group".to_string(),
            action: FormAction::AddUserGroup,
            fields: vec![
                FormField::new("user_id", String::new()),
                FormField::new("group_id", String::new()),
            ],
            index: 0,
            error: None,
        },
    };
    app.mode = Mode::Form;
    app.form = Some(form);
    Ok(())
}

fn open_edit_form(app: &mut App) -> Result<()> {
    let form = match app.tab {
        Tab::Users => {
            let user = selected_item(&app.users.items, app.users.selected())?;
            FormState {
                title: "Update user".to_string(),
                action: FormAction::UpdateUser(user.id.clone()),
                fields: vec![
                    FormField::new("email", user.email.clone()).optional(),
                    FormField::secret("password", String::new()).optional(),
                    FormField::boolean("is_active", user.is_active),
                ],
                index: 0,
                error: None,
            }
        }
        Tab::Groups => {
            let group = selected_item(&app.groups.items, app.groups.selected())?;
            FormState {
                title: "Update group".to_string(),
                action: FormAction::UpdateGroup(group.id.clone()),
                fields: vec![
                    FormField::new("name", group.name.clone()).optional(),
                    FormField::new("description", group.description.clone().unwrap_or_default())
                        .optional(),
                ],
                index: 0,
                error: None,
            }
        }
        Tab::Clients => {
            let client = selected_item(&app.clients.items, app.clients.selected())?;
            FormState {
                title: "Update client".to_string(),
                action: FormAction::UpdateClient(client.id.clone()),
                fields: vec![
                    FormField::new("name", client.name.clone()).optional(),
                    FormField::secret("client_secret", String::new()).optional(),
                    FormField::new("redirect_uris", client.redirect_uris.join(", ")).optional(),
                    FormField::new("grant_types", client.grant_types.join(", ")).optional(),
                    FormField::new("scope", client.scope.clone()).optional(),
                    FormField::boolean("is_active", client.is_active),
                ],
                index: 0,
                error: None,
            }
        }
        Tab::ClaimMaps => {
            return Err(anyhow!("Claim maps cannot be updated"));
        }
        Tab::UserGroups => {
            return Err(anyhow!("User groups cannot be edited"));
        }
    };
    app.mode = Mode::Form;
    app.form = Some(form);
    Ok(())
}

fn open_delete_form(app: &mut App) -> Result<()> {
    let form = match app.tab {
        Tab::Users => {
            let user = selected_item(&app.users.items, app.users.selected())?;
            FormState {
                title: "Delete user".to_string(),
                action: FormAction::DeleteUser(user.id.clone()),
                fields: vec![FormField::boolean("confirm", false)],
                index: 0,
                error: None,
            }
        }
        Tab::Groups => {
            let group = selected_item(&app.groups.items, app.groups.selected())?;
            FormState {
                title: "Delete group".to_string(),
                action: FormAction::DeleteGroup(group.id.clone()),
                fields: vec![FormField::boolean("confirm", false)],
                index: 0,
                error: None,
            }
        }
        Tab::Clients => {
            let client = selected_item(&app.clients.items, app.clients.selected())?;
            FormState {
                title: "Delete client".to_string(),
                action: FormAction::DeleteClient(client.id.clone()),
                fields: vec![FormField::boolean("confirm", false)],
                index: 0,
                error: None,
            }
        }
        Tab::ClaimMaps => {
            let map = selected_item(&app.claim_maps.items, app.claim_maps.selected())?;
            FormState {
                title: "Delete claim map".to_string(),
                action: FormAction::DeleteClaimMap(map.id.clone()),
                fields: vec![FormField::boolean("confirm", false)],
                index: 0,
                error: None,
            }
        }
        Tab::UserGroups => {
            return Err(anyhow!("Use remove to delete user-group mappings"));
        }
    };
    app.mode = Mode::Form;
    app.form = Some(form);
    Ok(())
}

fn open_add_user_group(app: &mut App) -> Result<()> {
    if app.tab != Tab::UserGroups {
        return Ok(());
    }
    let form = FormState {
        title: "Add user to group".to_string(),
        action: FormAction::AddUserGroup,
        fields: vec![
            FormField::new("user_id", String::new()),
            FormField::new("group_id", String::new()),
        ],
        index: 0,
        error: None,
    };
    app.mode = Mode::Form;
    app.form = Some(form);
    Ok(())
}

fn open_remove_user_group(app: &mut App) -> Result<()> {
    if app.tab != Tab::UserGroups {
        return Ok(());
    }
    let form = FormState {
        title: "Remove user from group".to_string(),
        action: FormAction::RemoveUserGroup,
        fields: vec![
            FormField::new("user_id", String::new()),
            FormField::new("group_id", String::new()),
        ],
        index: 0,
        error: None,
    };
    app.mode = Mode::Form;
    app.form = Some(form);
    Ok(())
}

fn selected_item<'a, T>(items: &'a [T], idx: Option<usize>) -> Result<&'a T> {
    idx.and_then(|i| items.get(i))
        .ok_or_else(|| anyhow!("No row selected"))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FormResult {
    Continue,
    Submitted,
    Cancelled,
}

async fn handle_form_event(
    app: &mut App,
    event: Event,
    http: &HttpClient,
) -> Result<FormResult> {
    let Some(form) = app.form.as_mut() else {
        return Ok(FormResult::Cancelled);
    };

    let Event::Key(key) = event else {
        return Ok(FormResult::Continue);
    };

    match key.code {
        KeyCode::Esc => return Ok(FormResult::Cancelled),
        KeyCode::Tab => form.index = (form.index + 1) % form.fields.len(),
        KeyCode::BackTab => {
            if form.index == 0 {
                form.index = form.fields.len() - 1;
            } else {
                form.index -= 1;
            }
        }
        KeyCode::Enter => {
            if form.index + 1 < form.fields.len() {
                form.index += 1;
            } else {
                match submit_form(http, form).await {
                    Ok(result) => {
                        app.set_status(result.message);
                        app.pending_select = result.select_id;
                        return Ok(FormResult::Submitted);
                    }
                    Err(err) => {
                        form.error = Some(err.to_string());
                    }
                }
            }
        }
        KeyCode::Char(' ') => {
            if let Some(field) = form.fields.get_mut(form.index) {
                if matches!(field.kind, FieldKind::Bool) {
                    field.toggle_bool();
                    return Ok(FormResult::Continue);
                }
            }
        }
        KeyCode::Char('g') => {
            if !key.modifiers.contains(KeyModifiers::CONTROL) {
                if let Some(field) = form.fields.get(form.index) {
                    if field.label == "grant_types" {
                        let values = split_csv(Some(field.value()));
                        app.picker = Some(PickerState::new_grant_types(&values));
                        app.mode = Mode::Picker;
                    }
                }
            }
        }
        _ => {}
    }

    if key.modifiers.contains(KeyModifiers::CONTROL) {
        if let Some(field) = form.fields.get_mut(form.index) {
            if field.label == "client_secret" && key.code == KeyCode::Char('g') {
                let secret = generate_secret();
                field.input = input_with_value(secret);
            }
            if matches!(field.kind, FieldKind::Secret) && key.code == KeyCode::Char('v') {
                field.reveal = !field.reveal;
            }
        }
        return Ok(FormResult::Continue);
    }

    if let Some(field) = form.fields.get_mut(form.index) {
        if !matches!(field.kind, FieldKind::Bool) {
            field.input.handle_event(&event);
        }
    }

    Ok(FormResult::Continue)
}

struct SubmitResult {
    message: String,
    select_id: Option<SelectHint>,
}

async fn submit_form(http: &HttpClient, form: &FormState) -> Result<SubmitResult> {
    match &form.action {
        FormAction::CreateUser => {
            let payload = json!({
                "username": field_value(form, "username")?,
                "email": field_value(form, "email")?,
                "password": field_value(form, "password")?,
                "is_active": field_bool(form, "is_active"),
            });
            let body = http.post_json("/admin/users", payload).await?;
            let created: UserRow =
                serde_json::from_str(&body).context("Failed to parse user response")?;
            Ok(SubmitResult {
                message: "User created".to_string(),
                select_id: Some(SelectHint {
                    tab: Tab::Users,
                    id: created.id,
                }),
            })
        }
        FormAction::UpdateUser(id) => {
            let email = field_optional(form, "email");
            let password = field_optional(form, "password");
            let payload = json!({
                "email": email,
                "password": password,
                "is_active": field_bool(form, "is_active"),
            });
            http.put_json(&format!("/admin/users/{id}"), payload)
                .await?;
            Ok(SubmitResult {
                message: "User updated".to_string(),
                select_id: Some(SelectHint {
                    tab: Tab::Users,
                    id: id.clone(),
                }),
            })
        }
        FormAction::DeleteUser(id) => {
            ensure_confirm(form)?;
            http.delete(&format!("/admin/users/{id}")).await?;
            Ok(SubmitResult {
                message: "User deleted".to_string(),
                select_id: None,
            })
        }
        FormAction::CreateGroup => {
            let payload = json!({
                "name": field_value(form, "name")?,
                "description": field_optional(form, "description"),
            });
            let body = http.post_json("/admin/groups", payload).await?;
            let created: GroupRow =
                serde_json::from_str(&body).context("Failed to parse group response")?;
            Ok(SubmitResult {
                message: "Group created".to_string(),
                select_id: Some(SelectHint {
                    tab: Tab::Groups,
                    id: created.id,
                }),
            })
        }
        FormAction::UpdateGroup(id) => {
            let payload = json!({
                "name": field_optional(form, "name"),
                "description": field_optional(form, "description"),
            });
            http.put_json(&format!("/admin/groups/{id}"), payload)
                .await?;
            Ok(SubmitResult {
                message: "Group updated".to_string(),
                select_id: Some(SelectHint {
                    tab: Tab::Groups,
                    id: id.clone(),
                }),
            })
        }
        FormAction::DeleteGroup(id) => {
            ensure_confirm(form)?;
            http.delete(&format!("/admin/groups/{id}")).await?;
            Ok(SubmitResult {
                message: "Group deleted".to_string(),
                select_id: None,
            })
        }
        FormAction::CreateClient => {
            let redirect_uris = parse_redirect_uris(field_optional(form, "redirect_uris"))?;
            let grant_types = parse_grant_types(Some(field_value(form, "grant_types")?))?;
            let payload = json!({
                "client_id": field_value(form, "client_id")?,
                "client_secret": field_value(form, "client_secret")?,
                "name": field_value(form, "name")?,
                "redirect_uris": redirect_uris,
                "grant_types": grant_types,
                "scope": field_value(form, "scope")?,
                "is_active": field_bool(form, "is_active"),
            });
            let body = http.post_json("/admin/oauth-clients", payload).await?;
            let created: ClientRow =
                serde_json::from_str(&body).context("Failed to parse client response")?;
            Ok(SubmitResult {
                message: "Client created".to_string(),
                select_id: Some(SelectHint {
                    tab: Tab::Clients,
                    id: created.id,
                }),
            })
        }
        FormAction::UpdateClient(id) => {
            let redirect_uris = parse_redirect_uris(field_optional(form, "redirect_uris"))?;
            let grant_types = parse_grant_types(field_optional(form, "grant_types"))?;
            let payload = json!({
                "name": field_optional(form, "name"),
                "client_secret": field_optional(form, "client_secret"),
                "redirect_uris": if redirect_uris.is_empty() { None } else { Some(redirect_uris) },
                "grant_types": if grant_types.is_empty() { None } else { Some(grant_types) },
                "scope": field_optional(form, "scope"),
                "is_active": field_bool(form, "is_active"),
            });
            http.put_json(&format!("/admin/oauth-clients/{id}"), payload)
                .await?;
            Ok(SubmitResult {
                message: "Client updated".to_string(),
                select_id: Some(SelectHint {
                    tab: Tab::Clients,
                    id: id.clone(),
                }),
            })
        }
        FormAction::DeleteClient(id) => {
            ensure_confirm(form)?;
            http.delete(&format!("/admin/oauth-clients/{id}")).await?;
            Ok(SubmitResult {
                message: "Client deleted".to_string(),
                select_id: None,
            })
        }
        FormAction::CreateClaimMap => {
            let payload = json!({
                "client_id": field_value(form, "client_id")?,
                "group_id": field_value(form, "group_id")?,
                "claim_name": field_value(form, "claim_name")?,
                "claim_value": field_optional(form, "claim_value"),
            });
            let body = http.post_json("/admin/claim-maps", payload).await?;
            let created: ClaimMapRow =
                serde_json::from_str(&body).context("Failed to parse claim map response")?;
            Ok(SubmitResult {
                message: "Claim map created".to_string(),
                select_id: Some(SelectHint {
                    tab: Tab::ClaimMaps,
                    id: created.id,
                }),
            })
        }
        FormAction::DeleteClaimMap(id) => {
            ensure_confirm(form)?;
            http.delete(&format!("/admin/claim-maps/{id}")).await?;
            Ok(SubmitResult {
                message: "Claim map deleted".to_string(),
                select_id: None,
            })
        }
        FormAction::AddUserGroup => {
            let user_id = field_value(form, "user_id")?;
            let group_id = field_value(form, "group_id")?;
            let payload = json!({ "group_id": group_id });
            http.post_json(&format!("/admin/users/{user_id}/groups"), payload)
                .await?;
            Ok(SubmitResult {
                message: "User added to group".to_string(),
                select_id: None,
            })
        }
        FormAction::RemoveUserGroup => {
            let user_id = field_value(form, "user_id")?;
            let group_id = field_value(form, "group_id")?;
            http.delete(&format!("/admin/users/{user_id}/groups/{group_id}"))
                .await?;
            Ok(SubmitResult {
                message: "User removed from group".to_string(),
                select_id: None,
            })
        }
    }
}

fn field_value(form: &FormState, name: &str) -> Result<String> {
    let value = field_optional(form, name).unwrap_or_default();
    if value.trim().is_empty() {
        return Err(anyhow!("Field '{name}' is required"));
    }
    Ok(value)
}

fn field_optional(form: &FormState, name: &str) -> Option<String> {
    form.fields
        .iter()
        .find(|f| f.label == name)
        .map(|f| f.value().trim().to_string())
        .filter(|v| !v.is_empty())
}

fn field_bool(form: &FormState, name: &str) -> bool {
    form.fields
        .iter()
        .find(|f| f.label == name)
        .map(|f| f.value().eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn ensure_confirm(form: &FormState) -> Result<()> {
    if !field_bool(form, "confirm") {
        return Err(anyhow!("Confirmation is required"));
    }
    Ok(())
}

fn set_field_value(form: &mut FormState, name: &str, value: String) {
    if let Some(field) = form.fields.iter_mut().find(|f| f.label == name) {
        field.input = input_with_value(value);
    }
}

fn split_csv(input: Option<String>) -> Vec<String> {
    input
        .unwrap_or_default()
        .split(',')
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
        .collect()
}

fn input_with_value(value: String) -> Input {
    let mut input = Input::default();
    input = input.with_value(value);
    input
}

fn generate_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    BASE64_STANDARD.encode(bytes)
}

fn parse_redirect_uris(input: Option<String>) -> Result<Vec<String>> {
    let values = split_csv(input);
    let mut parsed = Vec::new();
    for value in values {
        if value.contains('*') {
            return Err(anyhow!("redirect_uris cannot contain wildcard '*'."));
        }
        let url = Url::parse(&value).map_err(|_| anyhow!("Invalid redirect_uri: {value}"))?;
        let scheme = url.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(anyhow!("redirect_uris must be http or https: {value}"));
        }
        parsed.push(value);
    }
    Ok(parsed)
}

fn parse_grant_types(input: Option<String>) -> Result<Vec<String>> {
    let values = split_csv(input);
    if values.is_empty() {
        return Ok(Vec::new());
    }
    let allowed: Vec<&str> = supported_grant_types().iter().map(|(_, v)| *v).collect();
    for value in &values {
        if !allowed.iter().any(|allowed| allowed == value) {
            return Err(anyhow!("Unsupported grant_type: {value}"));
        }
    }
    Ok(values)
}

fn draw_ui(frame: &mut ratatui::Frame, app: &mut App) {
    let size = frame.size();
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(3)])
        .split(size);

    draw_tabs(frame, layout[0], app);
    draw_body(frame, layout[1], app);
    draw_status(frame, layout[2], app);

    if app.form.is_some() {
        draw_form(frame, size, app);
    }
}

fn draw_tabs(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let titles: Vec<Line> = App::tabs()
        .iter()
        .map(|(_, title)| Line::from(Span::raw(*title)))
        .collect();
    let selected = App::tabs()
        .iter()
        .position(|(tab, _)| *tab == app.tab)
        .unwrap_or(0);
    let tabs = Tabs::new(titles)
        .select(selected)
        .block(Block::default().borders(Borders::ALL).title("simple-idm-ctl"))
        .highlight_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));
    frame.render_widget(tabs, area);
}

fn draw_body(frame: &mut ratatui::Frame, area: Rect, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(10)])
        .split(area);
    draw_table(frame, chunks[0], app);
    draw_details(frame, chunks[1], app);
}

fn draw_table(frame: &mut ratatui::Frame, area: Rect, app: &mut App) {
    let page = active_page(app);
    let title = tab_title(app.tab);
    let (header, rows, state, constraints) = match app.tab {
        Tab::Users => (
            Row::new(vec!["Username", "Email", "Active"]),
            app.users
                .items
                .iter()
                .map(|u| {
                    Row::new(vec![
                        Cell::from(u.username.clone()),
                        Cell::from(u.email.clone()),
                        Cell::from(u.is_active.to_string()),
                    ])
                })
                .collect::<Vec<_>>(),
            &mut app.users.state,
            vec![
                Constraint::Percentage(30),
                Constraint::Percentage(50),
                Constraint::Percentage(20),
            ],
        ),
        Tab::Groups => (
            Row::new(vec!["Name", "Description"]),
            app.groups
                .items
                .iter()
                .map(|g| {
                    Row::new(vec![
                        Cell::from(g.name.clone()),
                        Cell::from(g.description.clone().unwrap_or_default()),
                    ])
                })
                .collect::<Vec<_>>(),
            &mut app.groups.state,
            vec![Constraint::Percentage(35), Constraint::Percentage(65)],
        ),
        Tab::Clients => (
            Row::new(vec!["Client ID", "Name", "Grants"]),
            app.clients
                .items
                .iter()
                .map(|c| {
                    Row::new(vec![
                        Cell::from(c.client_id.clone()),
                        Cell::from(c.name.clone()),
                        Cell::from(c.grant_types.join(", ")),
                    ])
                })
                .collect::<Vec<_>>(),
            &mut app.clients.state,
            vec![
                Constraint::Percentage(35),
                Constraint::Percentage(35),
                Constraint::Percentage(30),
            ],
        ),
        Tab::ClaimMaps => (
            Row::new(vec!["Claim", "Client", "Group"]),
            app.claim_maps
                .items
                .iter()
                .map(|c| {
                    Row::new(vec![
                        Cell::from(c.claim_name.clone()),
                        Cell::from(c.client_id.clone()),
                        Cell::from(c.group_id.clone()),
                    ])
                })
                .collect::<Vec<_>>(),
            &mut app.claim_maps.state,
            vec![
                Constraint::Percentage(30),
                Constraint::Percentage(35),
                Constraint::Percentage(35),
            ],
        ),
        Tab::UserGroups => (
            Row::new(vec!["User", "Group"]),
            app.user_groups
                .items
                .iter()
                .map(|ug| {
                    Row::new(vec![
                        Cell::from(ug.username.clone()),
                        Cell::from(ug.group_name.clone()),
                    ])
                })
                .collect::<Vec<_>>(),
            &mut app.user_groups.state,
            vec![Constraint::Percentage(50), Constraint::Percentage(50)],
        ),
    };

    let table = Table::new(rows, constraints)
        .header(header.style(Style::default().add_modifier(Modifier::BOLD)))
        .block(Block::default().borders(Borders::ALL).title(format!(
            "{title} (page {page})"
        )))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");
    frame.render_stateful_widget(table, area, state);
}

fn draw_details(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let lines = match app.tab {
        Tab::Users => detail_users(app),
        Tab::Groups => detail_groups(app),
        Tab::Clients => detail_clients(app),
        Tab::ClaimMaps => detail_claim_maps(app),
        Tab::UserGroups => detail_user_groups(app),
    };
    let paragraph = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Details"))
        .alignment(Alignment::Left);
    frame.render_widget(paragraph, area);
}

fn draw_status(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let help = "q quit | tab switch | r refresh | n new | e edit | d delete | [/] page | a add | x remove";
    let status = if app.status.is_empty() {
        help.to_string()
    } else {
        format!("{} | {}", app.status, help)
    };
    let block = Block::default().borders(Borders::ALL).title("Status");
    let paragraph = Paragraph::new(status).block(block);
    frame.render_widget(paragraph, area);
}

fn draw_form(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let form = match &app.form {
        Some(form) => form,
        None => return,
    };
    let popup = centered_rect(70, 60, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(form.title.clone());
    frame.render_widget(block, popup);

    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(2)])
        .margin(1)
        .split(popup);

    let mut lines = Vec::new();
    let mut cursor = None;
    for (idx, field) in form.fields.iter().enumerate() {
        let is_active = idx == form.index;
        let prefix = if is_active { "> " } else { "  " };
        let value = field.display();
        let mut spans = vec![
            Span::styled(prefix, Style::default().fg(Color::Yellow)),
            Span::styled(
                format!("{}: ", field.label),
                Style::default()
                    .fg(if is_active { Color::Cyan } else { Color::White })
                    .add_modifier(if is_active { Modifier::BOLD } else { Modifier::empty() }),
            ),
            Span::styled(
                value,
                Style::default()
                    .fg(if is_active { Color::Cyan } else { Color::White })
                    .add_modifier(if is_active { Modifier::BOLD } else { Modifier::empty() }),
            ),
        ];
        if field.optional {
            spans.push(Span::styled(
                " (optional)",
                Style::default().fg(Color::DarkGray),
            ));
        }
        if matches!(field.kind, FieldKind::Bool) {
            spans.push(Span::styled(
                " (space toggles)",
                Style::default().fg(Color::DarkGray),
            ));
        }
        if matches!(field.kind, FieldKind::Secret) {
            spans.push(Span::styled(
                " (Ctrl+V reveal)",
                Style::default().fg(Color::DarkGray),
            ));
        }
        if field.label == "client_secret" {
            spans.push(Span::styled(
                " (Ctrl+G generate)",
                Style::default().fg(Color::DarkGray),
            ));
        }
        if field.label == "grant_types" {
            spans.push(Span::styled(
                " (g picker)",
                Style::default().fg(Color::DarkGray),
            ));
        }
        if is_active && !matches!(field.kind, FieldKind::Bool) {
            let cursor_offset = field.input.cursor();
            let cursor_x = inner[0].x
                + (prefix.len() + field.label.len() + 2 + cursor_offset) as u16;
            let cursor_y = inner[0].y + idx as u16;
            cursor = Some((cursor_x, cursor_y));
        }
        lines.push(Line::from(spans));
    }

    if let Some(error) = &form.error {
        lines.push(Line::from(Span::styled(
            error.clone(),
            Style::default().fg(Color::Red),
        )));
    }

    let paragraph = Paragraph::new(lines).alignment(Alignment::Left);
    frame.render_widget(paragraph, inner[0]);
    if let Some((x, y)) = cursor {
        frame.set_cursor(x, y);
    }

    let footer = Paragraph::new("Enter next/submit | Tab switch | Esc cancel | g grant types | Ctrl+G secret | Ctrl+V reveal")
        .alignment(Alignment::Center);
    frame.render_widget(footer, inner[1]);

    if let Some(picker) = &app.picker {
        draw_picker(frame, area, picker);
    }
}

fn tab_title(tab: Tab) -> &'static str {
    match tab {
        Tab::Users => "Users",
        Tab::Groups => "Groups",
        Tab::Clients => "Clients",
        Tab::ClaimMaps => "Claim maps",
        Tab::UserGroups => "User groups",
    }
}

fn active_page(app: &App) -> usize {
    match app.tab {
        Tab::Users => app.users.page,
        Tab::Groups => app.groups.page,
        Tab::Clients => app.clients.page,
        Tab::ClaimMaps => app.claim_maps.page,
        Tab::UserGroups => app.user_groups.page,
    }
}

fn detail_users(app: &App) -> Vec<Line<'static>> {
    let Some(user) = app.users.selected().and_then(|idx| app.users.items.get(idx)) else {
        return vec![Line::from("No user selected")];
    };
    vec![
        line_kv("id", &user.id),
        line_kv("username", &user.username),
        line_kv("email", &user.email),
        line_kv("is_active", &user.is_active.to_string()),
    ]
}

fn detail_groups(app: &App) -> Vec<Line<'static>> {
    let Some(group) = app.groups.selected().and_then(|idx| app.groups.items.get(idx)) else {
        return vec![Line::from("No group selected")];
    };
    vec![
        line_kv("id", &group.id),
        line_kv("name", &group.name),
        line_kv(
            "description",
            group.description.as_deref().unwrap_or(""),
        ),
    ]
}

fn detail_clients(app: &App) -> Vec<Line<'static>> {
    let Some(client) = app.clients.selected().and_then(|idx| app.clients.items.get(idx)) else {
        return vec![Line::from("No client selected")];
    };
    vec![
        line_kv("id", &client.id),
        line_kv("client_id", &client.client_id),
        line_kv("name", &client.name),
        line_kv("redirect_uris", &client.redirect_uris.join(", ")),
        line_kv("grant_types", &client.grant_types.join(", ")),
        line_kv("scope", &client.scope),
        line_kv("is_active", &client.is_active.to_string()),
    ]
}

fn detail_claim_maps(app: &App) -> Vec<Line<'static>> {
    let Some(map) = app
        .claim_maps
        .selected()
        .and_then(|idx| app.claim_maps.items.get(idx))
    else {
        return vec![Line::from("No claim map selected")];
    };
    vec![
        line_kv("id", &map.id),
        line_kv("client_id", &map.client_id),
        line_kv("group_id", &map.group_id),
        line_kv("claim_name", &map.claim_name),
        line_kv("claim_value", map.claim_value.as_deref().unwrap_or("")),
    ]
}

fn detail_user_groups(app: &App) -> Vec<Line<'static>> {
    let Some(row) = app
        .user_groups
        .selected()
        .and_then(|idx| app.user_groups.items.get(idx))
    else {
        return vec![Line::from("No entry selected")];
    };
    vec![
        line_kv("user_id", &row.user_id),
        line_kv("username", &row.username),
        line_kv("email", &row.email),
        line_kv("group_id", &row.group_id),
        line_kv("group_name", &row.group_name),
    ]
}

fn line_kv(key: &str, value: &str) -> Line<'static> {
    let key = format!("{key}: ");
    let value = value.to_string();
    Line::from(vec![
        Span::styled(key, Style::default().fg(Color::DarkGray)),
        Span::raw(value),
    ])
}

fn centered_rect(percent_x: u16, percent_y: u16, rect: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(rect);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn draw_picker(frame: &mut ratatui::Frame, area: Rect, picker: &PickerState) {
    let popup = centered_rect(50, 50, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(picker.title.clone());
    frame.render_widget(block, popup);

    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(2)])
        .margin(1)
        .split(popup);

    let lines: Vec<Line> = picker
        .options
        .iter()
        .enumerate()
        .map(|(idx, option)| {
            let marker = if option.selected { "[x]" } else { "[ ]" };
            let prefix = if idx == picker.index { ">" } else { " " };
            Line::from(vec![
                Span::styled(prefix, Style::default().fg(Color::Yellow)),
                Span::raw(format!(" {marker} {} ({})", option.label, option.value)),
            ])
        })
        .collect();

    let paragraph = Paragraph::new(lines).alignment(Alignment::Left);
    frame.render_widget(paragraph, inner[0]);

    let footer = Paragraph::new("Space toggle | Enter apply | Esc cancel")
        .alignment(Alignment::Center);
    frame.render_widget(footer, inner[1]);
}
