use anyhow::{anyhow, bail, Context, Result};
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
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Tabs, Wrap},
    Terminal,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use rand::RngCore;
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    io,
    time::Duration,
};
use tui_input::{backend::crossterm::EventHandler, Input};
use url::Url;

use crate::{ClaimMapRow, ClientRow, GroupRow, HttpClient, UserGroupRow, UserRow};

const PAGE_SIZE: usize = 25;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tab {
    Users,
    Groups,
    Clients,
    ClientClaims,
    GroupClaims,
    UserGroups,
    GroupUsers,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Normal,
    Form,
    Picker,
    Selector,
    PasswordGen,
    RelationEditor,
    ClaimEditor,
    ClaimEntry,
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
    group_depths: HashMap<String, usize>,
    clients: EntityState<ClientRow>,
    client_claims: EntityState<ClientClaimsRow>,
    group_claims: EntityState<GroupClaimsRow>,
    user_groups: EntityState<UserGroupsRow>,
    group_users: EntityState<GroupUsersRow>,
    mode: Mode,
    form: Option<FormState>,
    status: String,
    pending_select: Option<SelectHint>,
    picker: Option<PickerState>,
    selector: Option<SelectorState>,
    password_gen: Option<PasswordGenState>,
    relation_editor: Option<RelationEditorState>,
    claim_editor: Option<ClaimEditorState>,
    claim_entry: Option<ClaimEntryState>,
    cursor_visible: bool,
}

impl App {
    fn new() -> Self {
        Self {
            tab: Tab::Users,
            users: EntityState::new(),
            groups: EntityState::new(),
            group_depths: HashMap::new(),
            clients: EntityState::new(),
            client_claims: EntityState::new(),
            group_claims: EntityState::new(),
            user_groups: EntityState::new(),
            group_users: EntityState::new(),
            mode: Mode::Normal,
            form: None,
            status: String::new(),
            pending_select: None,
            picker: None,
            selector: None,
            password_gen: None,
            relation_editor: None,
            claim_editor: None,
            claim_entry: None,
            cursor_visible: false,
        }
    }

    fn tabs() -> Vec<(Tab, &'static str)> {
        vec![
            (Tab::Users, "Users"),
            (Tab::Groups, "Groups"),
            (Tab::Clients, "Clients"),
            (Tab::ClientClaims, "Client claims"),
            (Tab::GroupClaims, "Group claims"),
            (Tab::UserGroups, "User groups"),
            (Tab::GroupUsers, "Group users"),
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
    single_select: bool,
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
            single_select: false,
        }
    }

    fn new_groups_claim_mode(selected: &str) -> Self {
        let options = ["effective", "direct", "none"]
            .iter()
            .map(|value| PickerOption {
                label: value,
                value,
                selected: *value == selected,
            })
            .collect();

        Self {
            title: "Select groups_claim_mode".to_string(),
            options,
            index: 0,
            target_field: "groups_claim_mode",
            single_select: true,
        }
    }

    fn selected_values(&self) -> Vec<String> {
        if self.single_select {
            let selected = self
                .options
                .iter()
                .find(|opt| opt.selected)
                .or_else(|| self.options.get(self.index));
            return selected
                .map(|opt| vec![opt.value.to_string()])
                .unwrap_or_default();
        }

        self.options
            .iter()
            .filter(|opt| opt.selected)
            .map(|opt| opt.value.to_string())
            .collect()
    }
}

#[derive(Clone, Debug)]
struct PasswordGenState {
    title: String,
    length: Input,
    include_upper: bool,
    include_lower: bool,
    include_digits: bool,
    include_special_safe: bool,
    include_special_full: bool,
    index: usize,
    error: Option<String>,
    target_field: &'static str,
}

impl PasswordGenState {
    fn new(target_field: &'static str) -> Self {
        Self {
            title: "Generator hesla".to_string(),
            length: input_with_value("16".to_string()),
            include_upper: true,
            include_lower: true,
            include_digits: true,
            include_special_safe: false,
            include_special_full: false,
            index: 0,
            error: None,
            target_field,
        }
    }
}

#[derive(Clone, Debug)]
struct GroupSummary {
    id: String,
    name: String,
}

#[derive(Clone, Debug)]
struct UserSummary {
    id: String,
    username: String,
    email: String,
}

#[derive(Clone, Debug)]
struct UserGroupsRow {
    user_id: String,
    username: String,
    email: String,
    groups: Vec<GroupSummary>,
}

#[derive(Clone, Debug)]
struct GroupUsersRow {
    group_id: String,
    name: String,
    description: Option<String>,
    users: Vec<UserSummary>,
}

#[derive(Clone, Debug)]
struct ClaimSummary {
    id: String,
    claim_name: String,
    claim_value: Option<Value>,
    other_id: String,
    other_label: String,
}

#[derive(Clone, Debug)]
struct ClientClaimsRow {
    client_id: String,
    client_name: String,
    claims: Vec<ClaimSummary>,
}

#[derive(Clone, Debug)]
struct GroupClaimsRow {
    group_id: String,
    group_name: String,
    description: Option<String>,
    claims: Vec<ClaimSummary>,
}

#[derive(Debug)]
enum SelectorItems {
    Users(Vec<UserRow>),
    Groups(Vec<GroupRow>),
    Clients(Vec<ClientRow>),
}

#[derive(Debug)]
enum SelectorKind {
    Users,
    Groups,
    Clients,
}

#[derive(Debug)]
enum SelectorTarget {
    FormField(&'static str),
    ClaimEntryOther,
}

#[derive(Debug)]
struct SelectorState {
    title: String,
    items: SelectorItems,
    filter: Input,
    filter_active: bool,
    index: usize,
    filtered: Vec<usize>,
    target: SelectorTarget,
}

impl SelectorState {
    fn new_users(items: Vec<UserRow>, target: SelectorTarget) -> Self {
        let mut state = Self {
            title: "Vyber uživatele".to_string(),
            items: SelectorItems::Users(items),
            filter: Input::default(),
            filter_active: false,
            index: 0,
            filtered: Vec::new(),
            target,
        };
        state.apply_filter();
        state
    }

    fn new_groups(items: Vec<GroupRow>, target: SelectorTarget) -> Self {
        let mut state = Self {
            title: "Vyber skupinu".to_string(),
            items: SelectorItems::Groups(items),
            filter: Input::default(),
            filter_active: false,
            index: 0,
            filtered: Vec::new(),
            target,
        };
        state.apply_filter();
        state
    }

    fn new_clients(items: Vec<ClientRow>, target: SelectorTarget) -> Self {
        let mut state = Self {
            title: "Vyber klienta".to_string(),
            items: SelectorItems::Clients(items),
            filter: Input::default(),
            filter_active: false,
            index: 0,
            filtered: Vec::new(),
            target,
        };
        state.apply_filter();
        state
    }

    fn apply_filter(&mut self) {
        let needle = self.filter.value().to_lowercase();
        self.filtered.clear();
        match &self.items {
            SelectorItems::Users(items) => {
                for (idx, user) in items.iter().enumerate() {
                    if needle.is_empty()
                        || user.username.to_lowercase().contains(&needle)
                        || user.email.to_lowercase().contains(&needle)
                    {
                        self.filtered.push(idx);
                    }
                }
            }
            SelectorItems::Groups(items) => {
                for (idx, group) in items.iter().enumerate() {
                    let desc = group.description.clone().unwrap_or_default();
                    if needle.is_empty()
                        || group.name.to_lowercase().contains(&needle)
                        || desc.to_lowercase().contains(&needle)
                    {
                        self.filtered.push(idx);
                    }
                }
            }
            SelectorItems::Clients(items) => {
                for (idx, client) in items.iter().enumerate() {
                    if needle.is_empty()
                        || client.client_id.to_lowercase().contains(&needle)
                        || client.name.to_lowercase().contains(&needle)
                    {
                        self.filtered.push(idx);
                    }
                }
            }
        }

        if self.filtered.is_empty() {
            self.index = 0;
        } else {
            self.index = self.index.min(self.filtered.len() - 1);
        }
    }

    fn selected_index(&self) -> Option<usize> {
        self.filtered.get(self.index).copied()
    }
}

#[derive(Clone, Debug)]
struct RelationOption {
    id: String,
    label: String,
    selected: bool,
}

#[derive(Clone, Debug)]
enum RelationMode {
    UserGroups { user_id: String, username: String },
    GroupUsers { group_id: String, group_name: String },
}

#[derive(Clone, Debug)]
struct RelationEditorState {
    title: String,
    mode: RelationMode,
    options: Vec<RelationOption>,
    index: usize,
    error: Option<String>,
    original_selected: HashSet<String>,
}

impl RelationEditorState {
    fn new(mode: RelationMode, options: Vec<RelationOption>) -> Self {
        let original_selected = options
            .iter()
            .filter(|opt| opt.selected)
            .map(|opt| opt.id.clone())
            .collect();
        let title = match &mode {
            RelationMode::UserGroups { username, .. } => {
                format!("Skupiny pro uživatele {username}")
            }
            RelationMode::GroupUsers { group_name, .. } => {
                format!("Uživatelé ve skupině {group_name}")
            }
        };
        Self {
            title,
            mode,
            options,
            index: 0,
            error: None,
            original_selected,
        }
    }

    fn selected_ids(&self) -> HashSet<String> {
        self.options
            .iter()
            .filter(|opt| opt.selected)
            .map(|opt| opt.id.clone())
            .collect()
    }
}

#[derive(Clone, Debug)]
enum ClaimEditorMode {
    ClientClaims {
        client_id: String,
        client_label: String,
    },
    GroupClaims {
        group_id: String,
        group_label: String,
    },
}

#[derive(Clone, Debug)]
struct ClaimEditorItem {
    id: Option<String>,
    claim_name: String,
    claim_value: Option<Value>,
    other_id: String,
    other_label: String,
}

#[derive(Clone, Debug)]
struct ClaimEditorState {
    title: String,
    mode: ClaimEditorMode,
    items: Vec<ClaimEditorItem>,
    original: Vec<ClaimEditorItem>,
    index: usize,
    error: Option<String>,
}

impl ClaimEditorState {
    fn new(mode: ClaimEditorMode, items: Vec<ClaimEditorItem>) -> Self {
        let title = match &mode {
            ClaimEditorMode::ClientClaims { client_label, .. } => {
                format!("Claim maps pro klienta {client_label}")
            }
            ClaimEditorMode::GroupClaims { group_label, .. } => {
                format!("Claim maps pro skupinu {group_label}")
            }
        };
        Self {
            title,
            mode,
            original: items.clone(),
            items,
            index: 0,
            error: None,
        }
    }
}

#[derive(Clone, Debug)]
enum ClaimEntryMode {
    Add,
    Edit(usize),
}

#[derive(Clone, Debug)]
struct ClaimEntryState {
    title: String,
    mode: ClaimEntryMode,
    claim_name: Input,
    claim_value: Input,
    other_id: Option<String>,
    other_label: Option<String>,
    index: usize,
    error: Option<String>,
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
    label: Option<String>,
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
        if app.cursor_visible {
            terminal.show_cursor()?;
        } else {
            terminal.hide_cursor()?;
        }

        if !event::poll(Duration::from_millis(200))? {
            continue;
        }

        let event = event::read()?;
        if app.mode == Mode::RelationEditor {
            let handled = handle_relation_event(app, event, http).await?;
            if handled == RelationResult::Applied {
                app.mode = Mode::Normal;
                refresh_active_tab(app, http).await?;
            } else if handled == RelationResult::Cancelled {
                app.mode = Mode::Normal;
            }
            continue;
        }
        if app.mode == Mode::ClaimEditor {
            let handled = handle_claim_editor_event(app, event, http).await?;
            if handled == ClaimEditorResult::Applied {
                app.mode = Mode::Normal;
                app.claim_editor = None;
                refresh_active_tab(app, http).await?;
            } else if handled == ClaimEditorResult::Cancelled {
                app.mode = Mode::Normal;
                app.claim_editor = None;
            }
            continue;
        }
        if app.mode == Mode::ClaimEntry {
            let handled = handle_claim_entry_event(app, event, http).await?;
            if handled == ClaimEntryResult::Applied || handled == ClaimEntryResult::Cancelled {
                app.mode = Mode::ClaimEditor;
            }
            continue;
        }
        if app.mode == Mode::PasswordGen {
            let handled = handle_password_gen_event(app, event)?;
            if handled == PasswordGenResult::Applied || handled == PasswordGenResult::Cancelled {
                app.mode = Mode::Form;
            }
            continue;
        }
        if app.mode == Mode::Selector {
            let handled = handle_selector_event(app, event)?;
            if handled == SelectorResult::Applied || handled == SelectorResult::Cancelled {
                if app.claim_entry.is_some() {
                    app.mode = Mode::ClaimEntry;
                } else {
                    app.mode = Mode::Form;
                }
            }
            continue;
        }
        if app.mode == Mode::Picker {
            let handled = handle_picker_event(app, event)?;
            if handled == PickerResult::Applied || handled == PickerResult::Cancelled {
                app.mode = Mode::Form;
            }
            continue;
        }

        if app.mode == Mode::Form {
            let handled = handle_form_event(app, event, http).await?;
            if handled == FormResult::Submitted {
                app.mode = Mode::Normal;
                app.form = None;
                refresh_active_tab(app, http).await?;
            } else if handled == FormResult::Cancelled {
                app.mode = Mode::Normal;
                app.form = None;
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
            if app.tab != Tab::ClientClaims && app.tab != Tab::GroupClaims {
                if let Err(err) = open_create_form(app) {
                    app.set_status(err.to_string());
                }
            }
        }
        KeyCode::Char('e') => {
            if let Err(err) = open_edit_form(app, http).await {
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum SelectorResult {
    Continue,
    Applied,
    Cancelled,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PasswordGenResult {
    Continue,
    Applied,
    Cancelled,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RelationResult {
    Continue,
    Applied,
    Cancelled,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ClaimEditorResult {
    Continue,
    Applied,
    Cancelled,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ClaimEntryResult {
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
            if picker.single_select {
                return Ok(PickerResult::Continue);
            }
            if let Some(option) = picker.options.get_mut(picker.index) {
                option.selected = !option.selected;
            }
        }
        KeyCode::Enter => {
            if picker.single_select {
                for (idx, opt) in picker.options.iter_mut().enumerate() {
                    opt.selected = idx == picker.index;
                }
            } else if !picker.options.iter().any(|opt| opt.selected) {
                if let Some(option) = picker.options.get_mut(picker.index) {
                    option.selected = true;
                }
            }
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

async fn handle_relation_event(
    app: &mut App,
    event: Event,
    http: &HttpClient,
) -> Result<RelationResult> {
    let Some(editor) = app.relation_editor.as_mut() else {
        return Ok(RelationResult::Cancelled);
    };

    let Event::Key(key) = event else {
        return Ok(RelationResult::Continue);
    };

    match key.code {
        KeyCode::Esc => {
            app.pending_select = Some(relation_hint(&editor.mode));
            app.relation_editor = None;
            return Ok(RelationResult::Cancelled);
        }
        KeyCode::Up => {
            editor.index = editor.index.saturating_sub(1);
        }
        KeyCode::Down => {
            editor.index = (editor.index + 1).min(editor.options.len().saturating_sub(1));
        }
        KeyCode::Char(' ') => {
            if let Some(option) = editor.options.get_mut(editor.index) {
                option.selected = !option.selected;
            }
        }
        KeyCode::Enter => {
            if let Err(err) = apply_relation_changes(editor, http).await {
                editor.error = Some(err.to_string());
                return Ok(RelationResult::Continue);
            }
            let (tab, id, label) = match &editor.mode {
                RelationMode::UserGroups { user_id, username } => {
                    (Tab::UserGroups, user_id.clone(), Some(username.clone()))
                }
                RelationMode::GroupUsers { group_id, group_name } => {
                    (Tab::GroupUsers, group_id.clone(), Some(group_name.clone()))
                }
            };
            app.pending_select = Some(SelectHint { tab, id, label });
            app.relation_editor = None;
            return Ok(RelationResult::Applied);
        }
        _ => {}
    }

    Ok(RelationResult::Continue)
}

async fn handle_claim_editor_event(
    app: &mut App,
    event: Event,
    http: &HttpClient,
) -> Result<ClaimEditorResult> {
    let Some(editor) = app.claim_editor.as_mut() else {
        return Ok(ClaimEditorResult::Cancelled);
    };

    let Event::Key(key) = event else {
        return Ok(ClaimEditorResult::Continue);
    };

    match key.code {
        KeyCode::Esc => {
            app.pending_select = Some(claim_editor_hint(&editor.mode));
            return Ok(ClaimEditorResult::Cancelled);
        }
        KeyCode::Up => {
            editor.index = editor.index.saturating_sub(1);
        }
        KeyCode::Down => {
            editor.index = (editor.index + 1).min(editor.items.len().saturating_sub(1));
        }
        KeyCode::Char('a') => {
            app.claim_entry = Some(ClaimEntryState {
                title: "Přidat claim map".to_string(),
                mode: ClaimEntryMode::Add,
                claim_name: Input::default(),
                claim_value: Input::default(),
                other_id: None,
                other_label: None,
                index: 0,
                error: None,
            });
            app.mode = Mode::ClaimEntry;
            return Ok(ClaimEditorResult::Continue);
        }
        KeyCode::Char('e') => {
            if let Some(item) = editor.items.get(editor.index).cloned() {
                app.claim_entry = Some(ClaimEntryState {
                    title: "Upravit claim map".to_string(),
                    mode: ClaimEntryMode::Edit(editor.index),
                    claim_name: input_with_value(item.claim_name),
                    claim_value: input_with_value(claim_value_to_input(&item.claim_value)),
                    other_id: Some(item.other_id),
                    other_label: Some(item.other_label),
                    index: 0,
                    error: None,
                });
                app.mode = Mode::ClaimEntry;
            }
            return Ok(ClaimEditorResult::Continue);
        }
        KeyCode::Char('d') => {
            if !editor.items.is_empty() {
                editor.items.remove(editor.index);
                if editor.index >= editor.items.len() && !editor.items.is_empty() {
                    editor.index = editor.items.len() - 1;
                }
            }
        }
        KeyCode::Enter => {
            if let Err(err) = apply_claim_changes(editor, http).await {
                editor.error = Some(err.to_string());
                return Ok(ClaimEditorResult::Continue);
            }
            app.pending_select = Some(claim_editor_hint(&editor.mode));
            app.claim_editor = None;
            return Ok(ClaimEditorResult::Applied);
        }
        _ => {}
    }

    Ok(ClaimEditorResult::Continue)
}

async fn handle_claim_entry_event(
    app: &mut App,
    event: Event,
    http: &HttpClient,
) -> Result<ClaimEntryResult> {
    let Some(entry) = app.claim_entry.as_mut() else {
        return Ok(ClaimEntryResult::Cancelled);
    };

    let Event::Key(key) = event else {
        return Ok(ClaimEntryResult::Continue);
    };

    let mode = app
        .claim_editor
        .as_ref()
        .map(|editor| editor.mode.clone());

    match key.code {
        KeyCode::Esc => {
            app.claim_entry = None;
            return Ok(ClaimEntryResult::Cancelled);
        }
        KeyCode::Tab => {
            entry.index = (entry.index + 1) % 3;
            return Ok(ClaimEntryResult::Continue);
        }
        KeyCode::BackTab => {
            if entry.index == 0 {
                entry.index = 2;
            } else {
                entry.index -= 1;
            }
            return Ok(ClaimEntryResult::Continue);
        }
        KeyCode::Enter => {
            if entry.index < 2 {
                entry.index += 1;
                return Ok(ClaimEntryResult::Continue);
            }
            let claim_name = entry.claim_name.value().trim().to_string();
            if claim_name.is_empty() {
                entry.error = Some("claim_name je povinný".to_string());
                return Ok(ClaimEntryResult::Continue);
            }
            let Some(other_id) = entry.other_id.clone() else {
                entry.error = Some("Vyber klienta nebo skupinu".to_string());
                return Ok(ClaimEntryResult::Continue);
            };
            let claim_value_input = entry.claim_value.value().to_string();
            let claim_value = match parse_claim_value_input(&claim_value_input) {
                Ok(value) => value,
                Err(err) => {
                    entry.error = Some(err.to_string());
                    return Ok(ClaimEntryResult::Continue);
                }
            };
            let other_label = entry
                .other_label
                .clone()
                .unwrap_or_else(|| other_id.clone());

            if let Some(editor) = app.claim_editor.as_mut() {
                match entry.mode {
                    ClaimEntryMode::Add => {
                        editor.items.push(ClaimEditorItem {
                            id: None,
                            claim_name,
                            claim_value,
                            other_id,
                            other_label,
                        });
                        editor.index = editor.items.len().saturating_sub(1);
                    }
                    ClaimEntryMode::Edit(idx) => {
                        if let Some(item) = editor.items.get_mut(idx) {
                            item.claim_name = claim_name;
                            item.claim_value = claim_value;
                            item.other_id = other_id;
                            item.other_label = other_label;
                        }
                        editor.index = idx;
                    }
                }
            }
            app.claim_entry = None;
            return Ok(ClaimEntryResult::Applied);
        }
        KeyCode::Char('g') => {
            if key.modifiers.contains(KeyModifiers::CONTROL)
                && matches!(mode, Some(ClaimEditorMode::ClientClaims { .. }))
            {
                entry.index = 2;
                open_selector(app, http, SelectorKind::Groups, SelectorTarget::ClaimEntryOther)
                    .await?;
                return Ok(ClaimEntryResult::Continue);
            }
            if entry.index == 0 {
                entry.claim_name.handle_event(&event);
            } else if entry.index == 1 {
                entry.claim_value.handle_event(&event);
            }
        }
        KeyCode::Char('c') => {
            if key.modifiers.contains(KeyModifiers::CONTROL)
                && matches!(mode, Some(ClaimEditorMode::GroupClaims { .. }))
            {
                entry.index = 2;
                open_selector(app, http, SelectorKind::Clients, SelectorTarget::ClaimEntryOther)
                    .await?;
                return Ok(ClaimEntryResult::Continue);
            }
            if entry.index == 0 {
                entry.claim_name.handle_event(&event);
            } else if entry.index == 1 {
                entry.claim_value.handle_event(&event);
            }
        }
        _ => {
            if entry.index == 0 {
                entry.claim_name.handle_event(&event);
            } else if entry.index == 1 {
                entry.claim_value.handle_event(&event);
            }
        }
    }

    Ok(ClaimEntryResult::Continue)
}

fn handle_selector_event(app: &mut App, event: Event) -> Result<SelectorResult> {
    let Some(selector) = app.selector.as_mut() else {
        return Ok(SelectorResult::Cancelled);
    };

    let Event::Key(key) = event else {
        return Ok(SelectorResult::Continue);
    };

    if selector.filter_active {
        match key.code {
            KeyCode::Esc => {
                selector.filter_active = false;
                return Ok(SelectorResult::Continue);
            }
            KeyCode::Enter => {
                selector.filter_active = false;
                return Ok(SelectorResult::Continue);
            }
            _ => {
                selector.filter.handle_event(&event);
                selector.apply_filter();
                return Ok(SelectorResult::Continue);
            }
        }
    }

    match key.code {
        KeyCode::Esc => {
            app.selector = None;
            return Ok(SelectorResult::Cancelled);
        }
        KeyCode::Up => {
            selector.index = selector.index.saturating_sub(1);
        }
        KeyCode::Down => {
            selector.index = (selector.index + 1).min(selector.filtered.len().saturating_sub(1));
        }
        KeyCode::Char('/') => {
            selector.filter_active = true;
            selector.filter = Input::default();
        }
        KeyCode::Enter => {
            let Some(selected_idx) = selector.selected_index() else {
                return Ok(SelectorResult::Continue);
            };
            let (value, label) = match &selector.items {
                SelectorItems::Users(items) => (
                    items[selected_idx].id.clone(),
                    items[selected_idx].username.clone(),
                ),
                SelectorItems::Groups(items) => (
                    items[selected_idx].id.clone(),
                    items[selected_idx].name.clone(),
                ),
                SelectorItems::Clients(items) => (
                    items[selected_idx].id.clone(),
                    items[selected_idx].client_id.clone(),
                ),
            };
            match &selector.target {
                SelectorTarget::FormField(field) => {
                    if let Some(form) = app.form.as_mut() {
                        set_field_value(form, field, value);
                    }
                }
                SelectorTarget::ClaimEntryOther => {
                    if let Some(entry) = app.claim_entry.as_mut() {
                        entry.other_id = Some(value);
                        entry.other_label = Some(label);
                    }
                }
            }
            app.selector = None;
            return Ok(SelectorResult::Applied);
        }
        _ => {}
    }

    Ok(SelectorResult::Continue)
}

fn handle_password_gen_event(app: &mut App, event: Event) -> Result<PasswordGenResult> {
    let Some(gen) = app.password_gen.as_mut() else {
        return Ok(PasswordGenResult::Cancelled);
    };

    let Event::Key(key) = event else {
        return Ok(PasswordGenResult::Continue);
    };

    match key.code {
        KeyCode::Esc => {
            app.password_gen = None;
            return Ok(PasswordGenResult::Cancelled);
        }
        KeyCode::Tab => gen.index = (gen.index + 1) % 7,
        KeyCode::BackTab => {
            if gen.index == 0 {
                gen.index = 6;
            } else {
                gen.index -= 1;
            }
        }
        KeyCode::Char(' ') => {
            match gen.index {
                1 => gen.include_upper = !gen.include_upper,
                2 => gen.include_lower = !gen.include_lower,
                3 => gen.include_digits = !gen.include_digits,
                4 => gen.include_special_safe = !gen.include_special_safe,
                5 => gen.include_special_full = !gen.include_special_full,
                _ => {}
            }
        }
        KeyCode::Enter => {
            if gen.index == 6 {
                match generate_password(gen) {
                    Ok(value) => {
                        if let Some(form) = app.form.as_mut() {
                            set_field_value(form, gen.target_field, value);
                        }
                        app.password_gen = None;
                        return Ok(PasswordGenResult::Applied);
                    }
                    Err(err) => gen.error = Some(err.to_string()),
                }
            } else if gen.index == 0 {
                let mut length = gen.length.value().to_string();
                if length.is_empty() {
                    length = "16".to_string();
                }
                gen.length = input_with_value(length);
            } else {
                gen.index = 6;
            }
        }
        _ => {}
    }

    if gen.index == 0 {
        gen.length.handle_event(&event);
    }

    Ok(PasswordGenResult::Continue)
}

fn select_next(app: &mut App) {
    match app.tab {
        Tab::Users => app.users.select_next(),
        Tab::Groups => app.groups.select_next(),
        Tab::Clients => app.clients.select_next(),
        Tab::ClientClaims => app.client_claims.select_next(),
        Tab::GroupClaims => app.group_claims.select_next(),
        Tab::UserGroups => app.user_groups.select_next(),
        Tab::GroupUsers => app.group_users.select_next(),
    }
}

fn select_prev(app: &mut App) {
    match app.tab {
        Tab::Users => app.users.select_prev(),
        Tab::Groups => app.groups.select_prev(),
        Tab::Clients => app.clients.select_prev(),
        Tab::ClientClaims => app.client_claims.select_prev(),
        Tab::GroupClaims => app.group_claims.select_prev(),
        Tab::UserGroups => app.user_groups.select_prev(),
        Tab::GroupUsers => app.group_users.select_prev(),
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
        Tab::ClientClaims => app.client_claims.page += 1,
        Tab::GroupClaims => app.group_claims.page += 1,
        Tab::UserGroups => app.user_groups.page += 1,
        Tab::GroupUsers => app.group_users.page += 1,
    }
    refresh_active_tab(app, http).await
}

async fn page_prev(app: &mut App, http: &HttpClient) -> Result<()> {
    match app.tab {
        Tab::Users => app.users.page = app.users.page.saturating_sub(1).max(1),
        Tab::Groups => app.groups.page = app.groups.page.saturating_sub(1).max(1),
        Tab::Clients => app.clients.page = app.clients.page.saturating_sub(1).max(1),
        Tab::ClientClaims => app.client_claims.page = app.client_claims.page.saturating_sub(1).max(1),
        Tab::GroupClaims => app.group_claims.page = app.group_claims.page.saturating_sub(1).max(1),
        Tab::UserGroups => app.user_groups.page = app.user_groups.page.saturating_sub(1).max(1),
        Tab::GroupUsers => app.group_users.page = app.group_users.page.saturating_sub(1).max(1),
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
            match fetch_groups_tree(http).await {
                Ok((groups, depths)) => {
                    app.groups.items = groups;
                    app.group_depths = depths;
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
        Tab::ClientClaims => {
            match fetch_client_claims(http).await {
                Ok(rows) => {
                    app.client_claims.items = rows;
                    apply_selection(app, EntityKind::ClientClaims);
                }
                Err(err) => app.set_status(err.to_string()),
            }
        }
        Tab::GroupClaims => {
            match fetch_group_claims(http).await {
                Ok(rows) => {
                    app.group_claims.items = rows;
                    apply_selection(app, EntityKind::GroupClaims);
                }
                Err(err) => app.set_status(err.to_string()),
            }
        }
        Tab::UserGroups => {
            match fetch_user_groups(http).await {
                Ok(rows) => {
                    app.user_groups.items = rows;
                    apply_selection(app, EntityKind::UserGroups);
                }
                Err(err) => app.set_status(err.to_string()),
            }
        }
        Tab::GroupUsers => {
            match fetch_group_users(http).await {
                Ok(rows) => {
                    app.group_users.items = rows;
                    apply_selection(app, EntityKind::GroupUsers);
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
    ClientClaims,
    GroupClaims,
    UserGroups,
    GroupUsers,
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
            EntityKind::UserGroups if hint.tab == Tab::UserGroups => {
                if let Some(idx) = app
                    .user_groups
                    .items
                    .iter()
                    .position(|row| row.user_id == hint.id)
                {
                    app.user_groups.state.select(Some(idx));
                    matched = true;
                } else if let Some(label) = &hint.label {
                    if let Some(idx) = app
                        .user_groups
                        .items
                        .iter()
                        .position(|row| row.username == *label)
                    {
                        app.user_groups.state.select(Some(idx));
                        matched = true;
                    }
                }
            }
            EntityKind::GroupUsers if hint.tab == Tab::GroupUsers => {
                if let Some(idx) = app
                    .group_users
                    .items
                    .iter()
                    .position(|row| row.group_id == hint.id)
                {
                    app.group_users.state.select(Some(idx));
                    matched = true;
                } else if let Some(label) = &hint.label {
                    if let Some(idx) = app
                        .group_users
                        .items
                        .iter()
                        .position(|row| row.name == *label)
                    {
                        app.group_users.state.select(Some(idx));
                        matched = true;
                    }
                }
            }
            EntityKind::ClientClaims if hint.tab == Tab::ClientClaims => {
                if let Some(idx) = app
                    .client_claims
                    .items
                    .iter()
                    .position(|row| row.client_id == hint.id)
                {
                    app.client_claims.state.select(Some(idx));
                    matched = true;
                } else if let Some(label) = &hint.label {
                    if let Some(idx) = app
                        .client_claims
                        .items
                        .iter()
                        .position(|row| row.client_name == *label)
                    {
                        app.client_claims.state.select(Some(idx));
                        matched = true;
                    }
                }
            }
            EntityKind::GroupClaims if hint.tab == Tab::GroupClaims => {
                if let Some(idx) = app
                    .group_claims
                    .items
                    .iter()
                    .position(|row| row.group_id == hint.id)
                {
                    app.group_claims.state.select(Some(idx));
                    matched = true;
                } else if let Some(label) = &hint.label {
                    if let Some(idx) = app
                        .group_claims
                        .items
                        .iter()
                        .position(|row| row.group_name == *label)
                    {
                        app.group_claims.state.select(Some(idx));
                        matched = true;
                    }
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
            EntityKind::ClientClaims => app.client_claims.select_first(),
            EntityKind::GroupClaims => app.group_claims.select_first(),
            EntityKind::UserGroups => app.user_groups.select_first(),
            EntityKind::GroupUsers => app.group_users.select_first(),
        }
    }
}

async fn fetch_users(http: &HttpClient, page: usize) -> Result<Vec<UserRow>> {
    let path = format!("/admin/users?page={page}&limit={PAGE_SIZE}");
    let body = http.get(&path).await?;
    serde_json::from_str(&body).map_err(|e| anyhow!("Failed to parse users: {e}"))
}

async fn fetch_groups_tree(http: &HttpClient) -> Result<(Vec<GroupRow>, HashMap<String, usize>)> {
    let groups = fetch_groups_for_selector(http).await?;
    if groups.is_empty() {
        return Ok((Vec::new(), HashMap::new()));
    }

    let mut group_map: HashMap<String, GroupRow> = HashMap::new();
    for group in &groups {
        group_map.insert(group.id.clone(), group.clone());
    }

    let mut children_map: HashMap<String, Vec<String>> = HashMap::new();
    for group in &groups {
        let path = format!("/admin/groups/{}/children", group.id);
        let body = http.get(&path).await?;
        let mut children: Vec<GroupRow> =
            serde_json::from_str(&body).map_err(|e| anyhow!("Failed to parse group children: {e}"))?;
        children.sort_by(|a, b| a.name.cmp(&b.name));
        let child_ids = children.into_iter().map(|child| child.id).collect::<Vec<_>>();
        children_map.insert(group.id.clone(), child_ids);
    }

    let mut child_set: HashSet<String> = HashSet::new();
    for child_ids in children_map.values() {
        for child_id in child_ids {
            child_set.insert(child_id.clone());
        }
    }

    let mut root_ids: Vec<String> = groups
        .iter()
        .filter(|group| !child_set.contains(&group.id))
        .map(|group| group.id.clone())
        .collect();
    root_ids.sort_by(|a, b| {
        let name_a = group_map.get(a).map(|g| g.name.as_str()).unwrap_or("");
        let name_b = group_map.get(b).map(|g| g.name.as_str()).unwrap_or("");
        name_a.cmp(name_b)
    });

    let mut ordered = Vec::new();
    let mut depths = HashMap::new();
    let mut visited: HashSet<String> = HashSet::new();

    fn visit_group(
        id: &str,
        depth: usize,
        group_map: &HashMap<String, GroupRow>,
        children_map: &HashMap<String, Vec<String>>,
        ordered: &mut Vec<GroupRow>,
        depths: &mut HashMap<String, usize>,
        visited: &mut HashSet<String>,
    ) {
        if visited.contains(id) {
            return;
        }
        let Some(group) = group_map.get(id) else {
            return;
        };
        visited.insert(id.to_string());
        depths.insert(id.to_string(), depth);
        ordered.push(group.clone());
        if let Some(children) = children_map.get(id) {
            for child_id in children {
                visit_group(
                    child_id,
                    depth + 1,
                    group_map,
                    children_map,
                    ordered,
                    depths,
                    visited,
                );
            }
        }
    }

    for root_id in root_ids {
        visit_group(
            &root_id,
            0,
            &group_map,
            &children_map,
            &mut ordered,
            &mut depths,
            &mut visited,
        );
    }

    let mut remaining: Vec<String> = groups
        .iter()
        .filter(|group| !visited.contains(&group.id))
        .map(|group| group.id.clone())
        .collect();
    remaining.sort_by(|a, b| {
        let name_a = group_map.get(a).map(|g| g.name.as_str()).unwrap_or("");
        let name_b = group_map.get(b).map(|g| g.name.as_str()).unwrap_or("");
        name_a.cmp(name_b)
    });
    for id in remaining {
        visit_group(
            &id,
            0,
            &group_map,
            &children_map,
            &mut ordered,
            &mut depths,
            &mut visited,
        );
    }

    Ok((ordered, depths))
}

async fn fetch_users_for_selector(http: &HttpClient) -> Result<Vec<UserRow>> {
    let body = http.get("/admin/users?page=1&limit=1000").await?;
    serde_json::from_str(&body).map_err(|e| anyhow!("Failed to parse users: {e}"))
}

async fn fetch_groups_for_selector(http: &HttpClient) -> Result<Vec<GroupRow>> {
    let body = http.get("/admin/groups?page=1&limit=1000").await?;
    serde_json::from_str(&body).map_err(|e| anyhow!("Failed to parse groups: {e}"))
}

async fn fetch_clients_for_selector(http: &HttpClient) -> Result<Vec<ClientRow>> {
    let body = http.get("/admin/oauth-clients?page=1&limit=1000").await?;
    serde_json::from_str(&body).map_err(|e| anyhow!("Failed to parse clients: {e}"))
}

async fn fetch_clients(http: &HttpClient, page: usize) -> Result<Vec<ClientRow>> {
    let path = format!("/admin/oauth-clients?page={page}&limit={PAGE_SIZE}");
    let body = http.get(&path).await?;
    serde_json::from_str(&body).map_err(|e| anyhow!("Failed to parse clients: {e}"))
}

async fn fetch_claim_maps_flat(http: &HttpClient) -> Result<Vec<ClaimMapRow>> {
    let body = http.get("/admin/claim-maps?page=1&limit=2000").await?;
    serde_json::from_str(&body).map_err(|e| anyhow!("Failed to parse claim maps: {e}"))
}

async fn fetch_client_claims(http: &HttpClient) -> Result<Vec<ClientClaimsRow>> {
    let claim_maps = fetch_claim_maps_flat(http).await?;
    let clients = fetch_clients_for_selector(http).await?;
    let groups = fetch_groups_for_selector(http).await?;
    Ok(aggregate_client_claims(claim_maps, clients, groups))
}

async fn fetch_group_claims(http: &HttpClient) -> Result<Vec<GroupClaimsRow>> {
    let claim_maps = fetch_claim_maps_flat(http).await?;
    let clients = fetch_clients_for_selector(http).await?;
    let groups = fetch_groups_for_selector(http).await?;
    Ok(aggregate_group_claims(claim_maps, clients, groups))
}

async fn fetch_user_groups(http: &HttpClient) -> Result<Vec<UserGroupsRow>> {
    let rows = fetch_user_groups_flat(http).await?;
    Ok(aggregate_user_groups(rows))
}

async fn fetch_group_users(http: &HttpClient) -> Result<Vec<GroupUsersRow>> {
    let rows = fetch_user_groups_flat(http).await?;
    let groups = fetch_groups_for_selector(http).await?;
    Ok(aggregate_group_users(rows, groups))
}

async fn fetch_user_groups_flat(http: &HttpClient) -> Result<Vec<UserGroupRow>> {
    let body = http.get("/admin/user-groups?page=1&limit=2000").await?;
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
                FormField::boolean("is_virtual", false),
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
                FormField::new("groups_claim_mode", "effective".to_string()),
                FormField::boolean("include_claim_maps", true),
                FormField::boolean("ignore_virtual_groups", false),
            ],
            index: 0,
            error: None,
        },
        Tab::ClientClaims | Tab::GroupClaims => {
            open_claim_editor(app)?;
            return Ok(());
        }
        Tab::UserGroups => FormState {
            title: "Create new user-group".to_string(),
            action: FormAction::AddUserGroup,
            fields: vec![
                FormField::new("user_id", String::new()),
                FormField::new("group_id", String::new()),
            ],
            index: 0,
            error: None,
        },
        Tab::GroupUsers => {
            let fields = vec![
                FormField::new("group_id", String::new()),
                FormField::new("user_id", String::new()),
            ];
            FormState {
                title: "Create new group-user".to_string(),
                action: FormAction::AddUserGroup,
                fields,
                index: 0,
                error: None,
            }
        }
    };
    app.mode = Mode::Form;
    app.form = Some(form);
    Ok(())
}

async fn open_edit_form(app: &mut App, http: &HttpClient) -> Result<()> {
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
                    FormField::boolean("is_virtual", group.is_virtual).optional(),
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
                    FormField::new("groups_claim_mode", client.groups_claim_mode.clone())
                        .optional(),
                    FormField::boolean("include_claim_maps", client.include_claim_maps)
                        .optional(),
                    FormField::boolean("ignore_virtual_groups", client.ignore_virtual_groups)
                        .optional(),
                ],
                index: 0,
                error: None,
            }
        }
        Tab::ClientClaims | Tab::GroupClaims => {
            open_claim_editor(app)?;
            return Ok(());
        }
        Tab::UserGroups => {
            let row = selected_item(&app.user_groups.items, app.user_groups.selected())?;
            let groups = fetch_groups_for_selector(http).await?;
            let options = groups
                .into_iter()
                .map(|group| RelationOption {
                    id: group.id.clone(),
                    label: format!("{} ({})", group.name, group.id),
                    selected: row.groups.iter().any(|g| g.id == group.id),
                })
                .collect::<Vec<_>>();
            app.relation_editor = Some(RelationEditorState::new(
                RelationMode::UserGroups {
                    user_id: row.user_id.clone(),
                    username: row.username.clone(),
                },
                options,
            ));
            app.mode = Mode::RelationEditor;
            return Ok(());
        }
        Tab::GroupUsers => {
            let row = selected_item(&app.group_users.items, app.group_users.selected())?;
            let users = fetch_users_for_selector(http).await?;
            let options = users
                .into_iter()
                .map(|user| RelationOption {
                    id: user.id.clone(),
                    label: format!("{} <{}>", user.username, user.email),
                    selected: row.users.iter().any(|u| u.id == user.id),
                })
                .collect::<Vec<_>>();
            app.relation_editor = Some(RelationEditorState::new(
                RelationMode::GroupUsers {
                    group_id: row.group_id.clone(),
                    group_name: row.name.clone(),
                },
                options,
            ));
            app.mode = Mode::RelationEditor;
            return Ok(());
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
        Tab::ClientClaims | Tab::GroupClaims => {
            return Err(anyhow!("Use edit to manage claim maps"));
        }
        Tab::UserGroups => {
            return Err(anyhow!("Use remove to delete user-group mappings"));
        }
        Tab::GroupUsers => {
            return Err(anyhow!("Use remove to delete user-group mappings"));
        }
    };
    app.mode = Mode::Form;
    app.form = Some(form);
    Ok(())
}

fn open_add_user_group(app: &mut App) -> Result<()> {
    if app.tab != Tab::UserGroups && app.tab != Tab::GroupUsers {
        return Ok(());
    }
    let mut fields = vec![
        FormField::new("user_id", String::new()),
        FormField::new("group_id", String::new()),
    ];
    if app.tab == Tab::UserGroups {
        if let Some(row) = app
            .user_groups
            .selected()
            .and_then(|idx| app.user_groups.items.get(idx))
        {
            fields[0] = FormField::new("user_id", row.user_id.clone());
        }
    }
    if app.tab == Tab::GroupUsers {
        if let Some(row) = app
            .group_users
            .selected()
            .and_then(|idx| app.group_users.items.get(idx))
        {
            fields[1] = FormField::new("group_id", row.group_id.clone());
        }
    }
    let form = FormState {
        title: "Add user to group".to_string(),
        action: FormAction::AddUserGroup,
        fields,
        index: 0,
        error: None,
    };
    app.mode = Mode::Form;
    app.form = Some(form);
    Ok(())
}

fn open_remove_user_group(app: &mut App) -> Result<()> {
    if app.tab != Tab::UserGroups && app.tab != Tab::GroupUsers {
        return Ok(());
    }
    let mut fields = vec![
        FormField::new("user_id", String::new()),
        FormField::new("group_id", String::new()),
    ];
    if app.tab == Tab::UserGroups {
        if let Some(row) = app
            .user_groups
            .selected()
            .and_then(|idx| app.user_groups.items.get(idx))
        {
            fields[0] = FormField::new("user_id", row.user_id.clone());
        }
    }
    if app.tab == Tab::GroupUsers {
        if let Some(row) = app
            .group_users
            .selected()
            .and_then(|idx| app.group_users.items.get(idx))
        {
            fields[1] = FormField::new("group_id", row.group_id.clone());
        }
    }
    let form = FormState {
        title: "Remove user from group".to_string(),
        action: FormAction::RemoveUserGroup,
        fields,
        index: 0,
        error: None,
    };
    app.mode = Mode::Form;
    app.form = Some(form);
    Ok(())
}

fn open_claim_editor(app: &mut App) -> Result<()> {
    match app.tab {
        Tab::ClientClaims => {
            let row = selected_item(&app.client_claims.items, app.client_claims.selected())?;
            let items = row
                .claims
                .iter()
                .map(|claim| ClaimEditorItem {
                    id: Some(claim.id.clone()),
                    claim_name: claim.claim_name.clone(),
                    claim_value: claim.claim_value.clone(),
                    other_id: claim.other_id.clone(),
                    other_label: claim.other_label.clone(),
                })
                .collect::<Vec<_>>();
            app.claim_editor = Some(ClaimEditorState::new(
                ClaimEditorMode::ClientClaims {
                    client_id: row.client_id.clone(),
                    client_label: row.client_name.clone(),
                },
                items,
            ));
            app.mode = Mode::ClaimEditor;
        }
        Tab::GroupClaims => {
            let row = selected_item(&app.group_claims.items, app.group_claims.selected())?;
            let items = row
                .claims
                .iter()
                .map(|claim| ClaimEditorItem {
                    id: Some(claim.id.clone()),
                    claim_name: claim.claim_name.clone(),
                    claim_value: claim.claim_value.clone(),
                    other_id: claim.other_id.clone(),
                    other_label: claim.other_label.clone(),
                })
                .collect::<Vec<_>>();
            app.claim_editor = Some(ClaimEditorState::new(
                ClaimEditorMode::GroupClaims {
                    group_id: row.group_id.clone(),
                    group_label: row.group_name.clone(),
                },
                items,
            ));
            app.mode = Mode::ClaimEditor;
        }
        _ => return Err(anyhow!("Claim editor is not available for this view")),
    }
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
    let Event::Key(key) = event else {
        return Ok(FormResult::Continue);
    };

    let Some(form) = app.form.as_mut() else {
        return Ok(FormResult::Cancelled);
    };
    let label = form.fields.get(form.index).map(|field| field.label);
    let is_add_remove = matches!(
        form.action,
        FormAction::AddUserGroup | FormAction::RemoveUserGroup
    );
    let mut request_selector: Option<(SelectorKind, SelectorTarget)> = None;

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
            if key.modifiers.contains(KeyModifiers::CONTROL) {
                if label == Some("grant_types") {
                    let values = split_csv(Some(form.fields[form.index].value()));
                    app.picker = Some(PickerState::new_grant_types(&values));
                    app.mode = Mode::Picker;
                    return Ok(FormResult::Continue);
                }
                if is_add_remove && label == Some("group_id") {
                    request_selector = Some((
                        SelectorKind::Groups,
                        SelectorTarget::FormField("group_id"),
                    ));
                }
            }
        }
        KeyCode::Char('e') => {
            if key.modifiers.contains(KeyModifiers::CONTROL) && label == Some("groups_claim_mode")
            {
                let current = form.fields[form.index].value();
                app.picker = Some(PickerState::new_groups_claim_mode(&current));
                app.mode = Mode::Picker;
                return Ok(FormResult::Continue);
            }
        }
        KeyCode::Char('m') => {
            if key.modifiers.contains(KeyModifiers::CONTROL) && label == Some("groups_claim_mode")
            {
                let current = form.fields[form.index].value();
                app.picker = Some(PickerState::new_groups_claim_mode(&current));
                app.mode = Mode::Picker;
                return Ok(FormResult::Continue);
            }
        }
        KeyCode::Char('u') => {
            if key.modifiers.contains(KeyModifiers::CONTROL) {
                if is_add_remove && label == Some("user_id") {
                    request_selector =
                        Some((SelectorKind::Users, SelectorTarget::FormField("user_id")));
                }
            }
        }
        _ => {}
    }

    if let Some((kind, target)) = request_selector {
        let _ = form;
        if let Err(err) = open_selector(app, http, kind, target).await {
            if let Some(form) = app.form.as_mut() {
                form.error = Some(err.to_string());
            }
        }
        return Ok(FormResult::Continue);
    }

    if key.modifiers.contains(KeyModifiers::CONTROL) {
        if let Some(field) = form.fields.get_mut(form.index) {
            if field.label == "client_secret" && key.code == KeyCode::Char('g') {
                let secret = generate_secret();
                field.input = input_with_value(secret);
            }
            if field.label == "password" && key.code == KeyCode::Char('g') {
                app.password_gen = Some(PasswordGenState::new(field.label));
                app.mode = Mode::PasswordGen;
                return Ok(FormResult::Continue);
            }
            if matches!(field.kind, FieldKind::Secret) && key.code == KeyCode::Char('v') {
                field.reveal = !field.reveal;
            }
        }
        return Ok(FormResult::Continue);
    }

    if let Some(field) = form.fields.get_mut(form.index) {
        if !matches!(field.kind, FieldKind::Bool)
            && field.label != "groups_claim_mode"
        {
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
                    label: Some(created.username.clone()),
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
                    label: None,
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
                "is_virtual": field_bool(form, "is_virtual"),
            });
            let body = http.post_json("/admin/groups", payload).await?;
            let created: GroupRow =
                serde_json::from_str(&body).context("Failed to parse group response")?;
            Ok(SubmitResult {
                message: "Group created".to_string(),
                select_id: Some(SelectHint {
                    tab: Tab::Groups,
                    id: created.id,
                    label: Some(created.name.clone()),
                }),
            })
        }
        FormAction::UpdateGroup(id) => {
            let payload = json!({
                "name": field_optional(form, "name"),
                "description": field_optional(form, "description"),
                "is_virtual": field_bool_optional(form, "is_virtual"),
            });
            http.put_json(&format!("/admin/groups/{id}"), payload)
                .await?;
            Ok(SubmitResult {
                message: "Group updated".to_string(),
                select_id: Some(SelectHint {
                    tab: Tab::Groups,
                    id: id.clone(),
                    label: None,
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
            let groups_claim_mode =
                parse_groups_claim_mode(&field_value(form, "groups_claim_mode")?)?;
            let payload = json!({
                "client_id": field_value(form, "client_id")?,
                "client_secret": field_value(form, "client_secret")?,
                "name": field_value(form, "name")?,
                "redirect_uris": redirect_uris,
                "grant_types": grant_types,
                "scope": field_value(form, "scope")?,
                "is_active": field_bool(form, "is_active"),
                "groups_claim_mode": groups_claim_mode,
                "include_claim_maps": field_bool(form, "include_claim_maps"),
                "ignore_virtual_groups": field_bool(form, "ignore_virtual_groups"),
            });
            let body = http.post_json("/admin/oauth-clients", payload).await?;
            let created: ClientRow =
                serde_json::from_str(&body).context("Failed to parse client response")?;
            Ok(SubmitResult {
                message: "Client created".to_string(),
                select_id: Some(SelectHint {
                    tab: Tab::Clients,
                    id: created.id,
                    label: Some(created.client_id.clone()),
                }),
            })
        }
        FormAction::UpdateClient(id) => {
            let redirect_uris = parse_redirect_uris(field_optional(form, "redirect_uris"))?;
            let grant_types = parse_grant_types(field_optional(form, "grant_types"))?;
            let groups_claim_mode = match field_optional(form, "groups_claim_mode") {
                Some(value) => Some(parse_groups_claim_mode(&value)?),
                None => None,
            };
            let payload = json!({
                "name": field_optional(form, "name"),
                "client_secret": field_optional(form, "client_secret"),
                "redirect_uris": if redirect_uris.is_empty() { None } else { Some(redirect_uris) },
                "grant_types": if grant_types.is_empty() { None } else { Some(grant_types) },
                "scope": field_optional(form, "scope"),
                "is_active": field_bool(form, "is_active"),
                "groups_claim_mode": groups_claim_mode,
                "include_claim_maps": field_bool_optional(form, "include_claim_maps"),
                "ignore_virtual_groups": field_bool_optional(form, "ignore_virtual_groups"),
            });
            http.put_json(&format!("/admin/oauth-clients/{id}"), payload)
                .await?;
            Ok(SubmitResult {
                message: "Client updated".to_string(),
                select_id: Some(SelectHint {
                    tab: Tab::Clients,
                    id: id.clone(),
                    label: None,
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

fn field_bool_optional(form: &FormState, name: &str) -> Option<bool> {
    form.fields
        .iter()
        .find(|f| f.label == name)
        .map(|f| f.value().trim().to_string())
        .filter(|v| !v.is_empty())
        .map(|v| v.eq_ignore_ascii_case("true"))
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

async fn open_selector(
    app: &mut App,
    http: &HttpClient,
    kind: SelectorKind,
    target: SelectorTarget,
) -> Result<()> {
    match kind {
        SelectorKind::Users => {
            let users = fetch_users_for_selector(http).await?;
            app.selector = Some(SelectorState::new_users(users, target));
        }
        SelectorKind::Groups => {
            let groups = fetch_groups_for_selector(http).await?;
            app.selector = Some(SelectorState::new_groups(groups, target));
        }
        SelectorKind::Clients => {
            let clients = fetch_clients_for_selector(http).await?;
            app.selector = Some(SelectorState::new_clients(clients, target));
        }
    }
    app.mode = Mode::Selector;
    Ok(())
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

fn parse_groups_claim_mode(value: &str) -> Result<String> {
    match value.trim() {
        "effective" | "direct" | "none" => Ok(value.trim().to_string()),
        _ => Err(anyhow!(
            "groups_claim_mode must be one of: effective, direct, none"
        )),
    }
}

fn aggregate_user_groups(rows: Vec<UserGroupRow>) -> Vec<UserGroupsRow> {
    let mut map: std::collections::BTreeMap<String, UserGroupsRow> = std::collections::BTreeMap::new();
    for row in rows {
        let entry = map.entry(row.user_id.clone()).or_insert_with(|| UserGroupsRow {
            user_id: row.user_id.clone(),
            username: row.username.clone(),
            email: row.email.clone(),
            groups: Vec::new(),
        });
        entry.groups.push(GroupSummary {
            id: row.group_id.clone(),
            name: row.group_name.clone(),
        });
    }
    let mut values: Vec<UserGroupsRow> = map.into_values().collect();
    values.sort_by(|a, b| a.username.cmp(&b.username));
    values
}

fn aggregate_group_users(rows: Vec<UserGroupRow>, groups: Vec<GroupRow>) -> Vec<GroupUsersRow> {
    let mut group_meta: std::collections::HashMap<String, (String, Option<String>)> =
        std::collections::HashMap::new();
    for group in groups {
        group_meta.insert(group.id.clone(), (group.name.clone(), group.description.clone()));
    }

    let mut map: std::collections::BTreeMap<String, GroupUsersRow> = std::collections::BTreeMap::new();
    for row in rows {
        let (name, description) = group_meta
            .get(&row.group_id)
            .cloned()
            .unwrap_or((row.group_name.clone(), None));
        let entry = map.entry(row.group_id.clone()).or_insert_with(|| GroupUsersRow {
            group_id: row.group_id.clone(),
            name,
            description,
            users: Vec::new(),
        });
        entry.users.push(UserSummary {
            id: row.user_id.clone(),
            username: row.username.clone(),
            email: row.email.clone(),
        });
    }
    let mut values: Vec<GroupUsersRow> = map.into_values().collect();
    values.sort_by(|a, b| a.name.cmp(&b.name));
    values
}

fn aggregate_client_claims(
    rows: Vec<ClaimMapRow>,
    clients: Vec<ClientRow>,
    groups: Vec<GroupRow>,
) -> Vec<ClientClaimsRow> {
    let mut client_meta: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for client in clients {
        client_meta.insert(client.id.clone(), client.name.clone());
    }
    let mut group_meta: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for group in groups {
        group_meta.insert(group.id.clone(), group.name.clone());
    }

    let mut map: std::collections::BTreeMap<String, ClientClaimsRow> =
        std::collections::BTreeMap::new();
    for (id, name) in client_meta.iter() {
        map.entry(id.clone()).or_insert_with(|| ClientClaimsRow {
            client_id: id.clone(),
            client_name: name.clone(),
            claims: Vec::new(),
        });
    }
    for row in rows {
        let client_name = client_meta
            .get(&row.client_id)
            .cloned()
            .unwrap_or_else(|| row.client_id.clone());
        let group_name = group_meta
            .get(&row.group_id)
            .cloned()
            .unwrap_or_else(|| row.group_id.clone());
        let entry = map.entry(row.client_id.clone()).or_insert_with(|| ClientClaimsRow {
            client_id: row.client_id.clone(),
            client_name,
            claims: Vec::new(),
        });
        entry.claims.push(ClaimSummary {
            id: row.id.clone(),
            claim_name: row.claim_name.clone(),
            claim_value: row.claim_value.clone(),
            other_id: row.group_id.clone(),
            other_label: group_name,
        });
    }
    let mut values: Vec<ClientClaimsRow> = map.into_values().collect();
    values.sort_by(|a, b| a.client_name.cmp(&b.client_name));
    values
}

fn aggregate_group_claims(
    rows: Vec<ClaimMapRow>,
    clients: Vec<ClientRow>,
    groups: Vec<GroupRow>,
) -> Vec<GroupClaimsRow> {
    let mut client_meta: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for client in clients {
        client_meta.insert(client.id.clone(), client.name.clone());
    }
    let mut group_meta: std::collections::HashMap<String, (String, Option<String>)> =
        std::collections::HashMap::new();
    for group in groups {
        group_meta.insert(group.id.clone(), (group.name.clone(), group.description.clone()));
    }

    let mut map: std::collections::BTreeMap<String, GroupClaimsRow> =
        std::collections::BTreeMap::new();
    for (id, (name, description)) in group_meta.iter() {
        map.entry(id.clone()).or_insert_with(|| GroupClaimsRow {
            group_id: id.clone(),
            group_name: name.clone(),
            description: description.clone(),
            claims: Vec::new(),
        });
    }
    for row in rows {
        let (group_name, description) = group_meta
            .get(&row.group_id)
            .cloned()
            .unwrap_or((row.group_id.clone(), None));
        let client_name = client_meta
            .get(&row.client_id)
            .cloned()
            .unwrap_or_else(|| row.client_id.clone());
        let entry = map.entry(row.group_id.clone()).or_insert_with(|| GroupClaimsRow {
            group_id: row.group_id.clone(),
            group_name,
            description,
            claims: Vec::new(),
        });
        entry.claims.push(ClaimSummary {
            id: row.id.clone(),
            claim_name: row.claim_name.clone(),
            claim_value: row.claim_value.clone(),
            other_id: row.client_id.clone(),
            other_label: client_name,
        });
    }
    let mut values: Vec<GroupClaimsRow> = map.into_values().collect();
    values.sort_by(|a, b| a.group_name.cmp(&b.group_name));
    values
}

fn generate_password(gen: &PasswordGenState) -> Result<String> {
    let length: usize = gen
        .length
        .value()
        .parse()
        .unwrap_or(16)
        .max(8)
        .min(128);

    let mut charset = String::new();
    if gen.include_upper {
        charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if gen.include_lower {
        charset.push_str("abcdefghijklmnopqrstuvwxyz");
    }
    if gen.include_digits {
        charset.push_str("0123456789");
    }
    if gen.include_special_safe {
        charset.push_str("-_.:;@+");
    }
    if gen.include_special_full {
        charset.push_str("!@#$%^&*()[]{}<>?/\\\\|`~'\"");
    }

    if charset.is_empty() {
        return Err(anyhow!("Vyber alespoň jednu sadu znaků."));
    }

    let bytes = charset.as_bytes();
    let mut rng = rand::rng();
    let mut password = String::with_capacity(length);
    for _ in 0..length {
        let idx = (rng.next_u32() as usize) % bytes.len();
        password.push(bytes[idx] as char);
    }

    Ok(password)
}

async fn apply_relation_changes(
    editor: &RelationEditorState,
    http: &HttpClient,
) -> Result<()> {
    let desired = editor.selected_ids();
    let original = editor.original_selected.clone();

    let to_add: Vec<String> = desired.difference(&original).cloned().collect();
    let to_remove: Vec<String> = original.difference(&desired).cloned().collect();

    match &editor.mode {
        RelationMode::UserGroups { user_id, .. } => {
            for group_id in to_add {
                let payload = json!({ "group_id": group_id });
                http.post_json(&format!("/admin/users/{user_id}/groups"), payload)
                    .await?;
            }
            for group_id in to_remove {
                http.delete(&format!("/admin/users/{user_id}/groups/{group_id}"))
                    .await?;
            }
        }
        RelationMode::GroupUsers { group_id, .. } => {
            for user_id in to_add {
                let payload = json!({ "group_id": group_id });
                http.post_json(&format!("/admin/users/{user_id}/groups"), payload)
                    .await?;
            }
            for user_id in to_remove {
                http.delete(&format!("/admin/users/{user_id}/groups/{group_id}"))
                    .await?;
            }
        }
    }

    Ok(())
}

fn relation_hint(mode: &RelationMode) -> SelectHint {
    match mode {
        RelationMode::UserGroups { user_id, username } => SelectHint {
            tab: Tab::UserGroups,
            id: user_id.clone(),
            label: Some(username.clone()),
        },
        RelationMode::GroupUsers { group_id, group_name } => SelectHint {
            tab: Tab::GroupUsers,
            id: group_id.clone(),
            label: Some(group_name.clone()),
        },
    }
}

async fn apply_claim_changes(editor: &ClaimEditorState, http: &HttpClient) -> Result<()> {
    let mut original_map: std::collections::HashMap<String, ClaimEditorItem> =
        std::collections::HashMap::new();
    for item in &editor.original {
        if let Some(id) = &item.id {
            original_map.insert(id.clone(), item.clone());
        }
    }

    let mut current_map: std::collections::HashMap<String, ClaimEditorItem> =
        std::collections::HashMap::new();
    for item in &editor.items {
        if let Some(id) = &item.id {
            current_map.insert(id.clone(), item.clone());
        }
    }

    let original_ids: std::collections::HashSet<String> = original_map.keys().cloned().collect();
    let current_ids: std::collections::HashSet<String> = current_map.keys().cloned().collect();

    let mut to_delete: Vec<String> = original_ids
        .difference(&current_ids)
        .cloned()
        .collect();
    let mut to_create: Vec<ClaimEditorItem> = Vec::new();

    for item in &editor.items {
        match &item.id {
            None => to_create.push(item.clone()),
            Some(id) => {
                if let Some(original) = original_map.get(id) {
                    let changed = original.claim_name != item.claim_name
                        || original.claim_value != item.claim_value
                        || original.other_id != item.other_id;
                    if changed {
                        to_delete.push(id.clone());
                        to_create.push(item.clone());
                    }
                } else {
                    to_create.push(item.clone());
                }
            }
        }
    }

    for id in to_delete {
        http.delete(&format!("/admin/claim-maps/{id}")).await?;
    }

    for item in to_create {
        let payload = match &editor.mode {
            ClaimEditorMode::ClientClaims { client_id, .. } => json!({
                "client_id": client_id,
                "group_id": item.other_id,
                "claim_name": item.claim_name,
                "claim_value": item.claim_value,
            }),
            ClaimEditorMode::GroupClaims { group_id, .. } => json!({
                "client_id": item.other_id,
                "group_id": group_id,
                "claim_name": item.claim_name,
                "claim_value": item.claim_value,
            }),
        };
        http.post_json("/admin/claim-maps", payload).await?;
    }

    Ok(())
}

fn claim_editor_hint(mode: &ClaimEditorMode) -> SelectHint {
    match mode {
        ClaimEditorMode::ClientClaims {
            client_id,
            client_label,
        } => SelectHint {
            tab: Tab::ClientClaims,
            id: client_id.clone(),
            label: Some(client_label.clone()),
        },
        ClaimEditorMode::GroupClaims {
            group_id,
            group_label,
        } => SelectHint {
            tab: Tab::GroupClaims,
            id: group_id.clone(),
            label: Some(group_label.clone()),
        },
    }
}

fn draw_ui(frame: &mut ratatui::Frame, app: &mut App) {
    let mut cursor_visible = false;
    let size = frame.size();
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(3)])
        .split(size);

    draw_tabs(frame, layout[0], app);
    draw_body(frame, layout[1], app);
    draw_status(frame, layout[2], app);

    if app.form.is_some() {
        draw_form(frame, size, app, &mut cursor_visible);
    }
    if let Some(editor) = &app.relation_editor {
        draw_relation_editor(frame, size, editor);
    }
    if let Some(editor) = &app.claim_editor {
        draw_claim_editor(frame, size, editor);
    }
    if let Some(entry) = &app.claim_entry {
        draw_claim_entry(frame, size, app, entry, &mut cursor_visible);
    }

    if app.form.is_none() {
        if let Some(selector) = &app.selector {
            draw_selector(frame, size, selector, &mut cursor_visible);
        }
    }

    app.cursor_visible = cursor_visible;
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
                Constraint::Percentage(20),
                Constraint::Percentage(30),
                Constraint::Percentage(50),
            ],
        ),
        Tab::Groups => (
            Row::new(vec!["Name", "Description"]),
            app.groups
                .items
                .iter()
                .map(|g| {
                    let depth = app.group_depths.get(&g.id).copied().unwrap_or(0);
                    let prefix = if depth == 0 {
                        String::new()
                    } else {
                        format!(" {}→ ", " ".repeat(depth.saturating_sub(1)))
                    };
                    let mut name_spans = vec![Span::raw(format!("{prefix}{}", g.name))];
                    if g.is_virtual {
                        name_spans.push(Span::styled(
                            " [virt]",
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::DIM),
                        ));
                    }
                    Row::new(vec![
                        Cell::from(Line::from(name_spans)),
                        Cell::from(g.description.clone().unwrap_or_default()),
                    ])
                })
                .collect::<Vec<_>>(),
            &mut app.groups.state,
            vec![Constraint::Percentage(20), Constraint::Percentage(80)],
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
                Constraint::Percentage(20),
                Constraint::Percentage(30),
                Constraint::Percentage(50),
            ],
        ),
        Tab::ClientClaims => (
            Row::new(vec!["Client", "Claims"]),
            app.client_claims
                .items
                .iter()
                .map(|row| {
                    let claims = row
                        .claims
                        .iter()
                        .map(|c| {
                            let value = claim_value_to_display(&c.claim_value);
                            if value.is_empty() {
                                format!("{} ({})", c.claim_name, c.other_label)
                            } else {
                                format!("{}={} ({})", c.claim_name, value, c.other_label)
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    Row::new(vec![Cell::from(row.client_name.clone()), Cell::from(claims)])
                })
                .collect::<Vec<_>>(),
            &mut app.client_claims.state,
            vec![Constraint::Percentage(20), Constraint::Percentage(80)],
        ),
        Tab::GroupClaims => (
            Row::new(vec!["Group", "Claims"]),
            app.group_claims
                .items
                .iter()
                .map(|row| {
                    let claims = row
                        .claims
                        .iter()
                        .map(|c| {
                            let value = claim_value_to_display(&c.claim_value);
                            if value.is_empty() {
                                format!("{} ({})", c.claim_name, c.other_label)
                            } else {
                                format!("{}={} ({})", c.claim_name, value, c.other_label)
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    Row::new(vec![Cell::from(row.group_name.clone()), Cell::from(claims)])
                })
                .collect::<Vec<_>>(),
            &mut app.group_claims.state,
            vec![Constraint::Percentage(20), Constraint::Percentage(80)],
        ),
        Tab::UserGroups => (
            Row::new(vec!["User", "Groups"]),
            app.user_groups
                .items
                .iter()
                .map(|ug| {
                    Row::new(vec![
                        Cell::from(ug.username.clone()),
                        Cell::from(
                            ug.groups
                                .iter()
                                .map(|g| g.name.clone())
                                .collect::<Vec<_>>()
                                .join(", "),
                        ),
                    ])
                })
                .collect::<Vec<_>>(),
            &mut app.user_groups.state,
            vec![Constraint::Percentage(20), Constraint::Percentage(80)],
        ),
        Tab::GroupUsers => (
            Row::new(vec!["Group", "Users"]),
            app.group_users
                .items
                .iter()
                .map(|gu| {
                    Row::new(vec![
                        Cell::from(gu.name.clone()),
                        Cell::from(
                            gu.users
                                .iter()
                                .map(|u| u.username.clone())
                                .collect::<Vec<_>>()
                                .join(", "),
                        ),
                    ])
                })
                .collect::<Vec<_>>(),
            &mut app.group_users.state,
            vec![Constraint::Percentage(20), Constraint::Percentage(80)],
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
        Tab::ClientClaims => detail_client_claims(app),
        Tab::GroupClaims => detail_group_claims(app),
        Tab::UserGroups => detail_user_groups(app),
        Tab::GroupUsers => detail_group_users(app),
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

fn draw_form(
    frame: &mut ratatui::Frame,
    area: Rect,
    app: &App,
    cursor_visible: &mut bool,
) {
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
        .constraints([Constraint::Min(1), Constraint::Length(3), Constraint::Length(2)])
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
        if field.label == "password" {
            spans.push(Span::styled(
                " (Ctrl+G generate)",
                Style::default().fg(Color::DarkGray),
            ));
        }
        if field.label == "grant_types" {
            spans.push(Span::styled(
                " (Ctrl+G picker)",
                Style::default().fg(Color::DarkGray),
            ));
        }
        if field.label == "groups_claim_mode" {
            spans.push(Span::styled(
                " (Ctrl+E picker)",
                Style::default().fg(Color::DarkGray),
            ));
        }
        if field.label == "user_id" {
            spans.push(Span::styled(
                " (Ctrl+U select)",
                Style::default().fg(Color::DarkGray),
            ));
        }
        if field.label == "group_id" {
            spans.push(Span::styled(
                " (Ctrl+G select)",
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
    if app.selector.is_none()
        && app.picker.is_none()
        && app.password_gen.is_none()
        && app.relation_editor.is_none()
        && app.claim_editor.is_none()
        && app.claim_entry.is_none()
    {
        if let Some((x, y)) = cursor {
            frame.set_cursor(x, y);
            *cursor_visible = true;
        }
    }

    let footer = Paragraph::new("Enter next/submit | Tab switch | Esc cancel | Ctrl+E groups_claim_mode picker | Ctrl+G grant types | Ctrl+U user select | Ctrl+G group select | Ctrl+G secret | Ctrl+V reveal")
        .alignment(Alignment::Center);
    frame.render_widget(footer, inner[1]);

    if let Some(picker) = &app.picker {
        draw_picker(frame, area, picker);
    }
    if let Some(selector) = &app.selector {
        draw_selector(frame, area, selector, cursor_visible);
    }
    if let Some(gen) = &app.password_gen {
        draw_password_gen(frame, area, gen, cursor_visible);
    }
}

fn tab_title(tab: Tab) -> &'static str {
    match tab {
        Tab::Users => "Users",
        Tab::Groups => "Groups",
        Tab::Clients => "Clients",
        Tab::ClientClaims => "Client claims",
        Tab::GroupClaims => "Group claims",
        Tab::UserGroups => "User groups",
        Tab::GroupUsers => "Group users",
    }
}

fn active_page(app: &App) -> usize {
    match app.tab {
        Tab::Users => app.users.page,
        Tab::Groups => app.groups.page,
        Tab::Clients => app.clients.page,
        Tab::ClientClaims => app.client_claims.page,
        Tab::GroupClaims => app.group_claims.page,
        Tab::UserGroups => app.user_groups.page,
        Tab::GroupUsers => app.group_users.page,
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
        line_kv("is_virtual", &group.is_virtual.to_string()),
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
        line_kv("groups_claim_mode", &client.groups_claim_mode),
        line_kv("include_claim_maps", &client.include_claim_maps.to_string()),
        line_kv(
            "ignore_virtual_groups",
            &client.ignore_virtual_groups.to_string(),
        ),
    ]
}

fn detail_client_claims(app: &App) -> Vec<Line<'static>> {
    let Some(row) = app
        .client_claims
        .selected()
        .and_then(|idx| app.client_claims.items.get(idx))
    else {
        return vec![Line::from("No client selected")];
    };
    let mut lines = vec![
        line_kv("client_id", &row.client_id),
        line_kv("client_name", &row.client_name),
    ];
    for claim in &row.claims {
        let value = claim_value_to_display(&claim.claim_value);
        let value = if value.is_empty() {
            claim.other_label.clone()
        } else {
            format!("{} ({})", value, claim.other_label)
        };
        lines.push(line_kv(&claim.claim_name, &value));
    }
    lines
}

fn detail_group_claims(app: &App) -> Vec<Line<'static>> {
    let Some(row) = app
        .group_claims
        .selected()
        .and_then(|idx| app.group_claims.items.get(idx))
    else {
        return vec![Line::from("No group selected")];
    };
    let mut lines = vec![
        line_kv("group_id", &row.group_id),
        line_kv("group_name", &row.group_name),
        line_kv(
            "description",
            row.description.as_deref().unwrap_or(""),
        ),
    ];
    for claim in &row.claims {
        let value = claim_value_to_display(&claim.claim_value);
        let value = if value.is_empty() {
            claim.other_label.clone()
        } else {
            format!("{} ({})", value, claim.other_label)
        };
        lines.push(line_kv(&claim.claim_name, &value));
    }
    lines
}

fn detail_user_groups(app: &App) -> Vec<Line<'static>> {
    let Some(row) = app
        .user_groups
        .selected()
        .and_then(|idx| app.user_groups.items.get(idx))
    else {
        return vec![Line::from("No entry selected")];
    };
    let groups = row
        .groups
        .iter()
        .map(|g| g.name.clone())
        .collect::<Vec<_>>()
        .join(", ");
    vec![
        line_kv("user_id", &row.user_id),
        line_kv("username", &row.username),
        line_kv("email", &row.email),
        line_kv("groups", &groups),
    ]
}

fn detail_group_users(app: &App) -> Vec<Line<'static>> {
    let Some(row) = app
        .group_users
        .selected()
        .and_then(|idx| app.group_users.items.get(idx))
    else {
        return vec![Line::from("No entry selected")];
    };
    let users = row
        .users
        .iter()
        .map(|u| format!("{} <{}>", u.username, u.email))
        .collect::<Vec<_>>()
        .join(", ");
    vec![
        line_kv("group_id", &row.group_id),
        line_kv("name", &row.name),
        line_kv(
            "description",
            row.description.as_deref().unwrap_or(""),
        ),
        line_kv("users", &users),
    ]
}

fn claim_value_to_display(value: &Option<Value>) -> String {
    match value {
        None => String::new(),
        Some(Value::String(val)) => val.clone(),
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        Some(other) => other.to_string(),
    }
}

fn claim_value_to_input(value: &Option<Value>) -> String {
    match value {
        None => String::new(),
        Some(Value::String(val)) => val.clone(),
        Some(Value::Array(values)) => serde_json::to_string(values).unwrap_or_default(),
        Some(other) => other.to_string(),
    }
}

fn parse_claim_value_input(input: &str) -> Result<Option<Value>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    if trimmed.starts_with('[') {
        let parsed: Value =
            serde_json::from_str(trimmed).context("claim_value musí být JSON array")?;
        let arr = parsed
            .as_array()
            .ok_or_else(|| anyhow!("claim_value musí být JSON array"))?;
        let strings: Vec<Value> = arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| Value::String(s.to_string())))
            .collect();
        if strings.is_empty() {
            bail!("claim_value array musí obsahovat alespoň jeden string");
        }
        return Ok(Some(Value::Array(strings)));
    }

    Ok(Some(Value::String(trimmed.to_string())))
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
        .constraints([Constraint::Min(1), Constraint::Length(1), Constraint::Length(2)])
        .margin(1)
        .split(popup);

    let lines: Vec<Line> = picker
        .options
        .iter()
        .enumerate()
        .map(|(idx, option)| {
            let prefix = if idx == picker.index { ">" } else { " " };
            let label = if picker.single_select {
                format!(" {} ({})", option.label, option.value)
            } else {
                let marker = if option.selected { "[x]" } else { "[ ]" };
                format!(" {marker} {} ({})", option.label, option.value)
            };
            Line::from(vec![
                Span::styled(prefix, Style::default().fg(Color::Yellow)),
                Span::raw(label),
            ])
        })
        .collect();

    let paragraph = Paragraph::new(lines).alignment(Alignment::Left);
    frame.render_widget(paragraph, inner[0]);

    let footer = Paragraph::new(if picker.single_select {
        "Enter select | Esc cancel"
    } else {
        "Space select | Enter apply | Esc cancel"
    })
    .alignment(Alignment::Center);
    frame.render_widget(footer, inner[1]);
}

fn draw_selector(
    frame: &mut ratatui::Frame,
    area: Rect,
    selector: &SelectorState,
    cursor_visible: &mut bool,
) {
    let popup = centered_rect(70, 70, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(selector.title.clone());
    frame.render_widget(block, popup);

    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(1), Constraint::Length(2)])
        .margin(1)
        .split(popup);

    let filter_line = if selector.filter_active {
        format!("/ {}", selector.filter.value())
    } else if selector.filter.value().is_empty() {
        "/ (filtr: napiš a potvrď Enter)".to_string()
    } else {
        format!("/ {}", selector.filter.value())
    };
    let filter = Paragraph::new(filter_line)
        .block(Block::default().borders(Borders::ALL).title("Filter"));
    frame.render_widget(filter, inner[0]);

    match &selector.items {
        SelectorItems::Users(items) => {
            let rows = selector
                .filtered
                .iter()
                .map(|idx| {
                    let user = &items[*idx];
                    Row::new(vec![
                        Cell::from(user.username.clone()),
                        Cell::from(user.email.clone()),
                        Cell::from(user.is_active.to_string()),
                    ])
                })
                .collect::<Vec<_>>();
            let table = Table::new(
                rows,
                vec![
                    Constraint::Percentage(35),
                    Constraint::Percentage(50),
                    Constraint::Percentage(15),
                ],
            )
            .header(
                Row::new(vec!["Username", "Email", "Active"])
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .block(Block::default().borders(Borders::ALL))
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">> ");
            let mut state = TableState::default();
            if !selector.filtered.is_empty() {
                state.select(Some(selector.index));
            }
            frame.render_stateful_widget(table, inner[1], &mut state);
        }
        SelectorItems::Groups(items) => {
            let rows = selector
                .filtered
                .iter()
                .map(|idx| {
                    let group = &items[*idx];
                    Row::new(vec![
                        Cell::from(group.name.clone()),
                        Cell::from(group.description.clone().unwrap_or_default()),
                    ])
                })
                .collect::<Vec<_>>();
            let table = Table::new(
                rows,
                vec![Constraint::Percentage(35), Constraint::Percentage(65)],
            )
            .header(
                Row::new(vec!["Name", "Description"])
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .block(Block::default().borders(Borders::ALL))
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">> ");
            let mut state = TableState::default();
            if !selector.filtered.is_empty() {
                state.select(Some(selector.index));
            }
            frame.render_stateful_widget(table, inner[1], &mut state);
        }
        SelectorItems::Clients(items) => {
            let rows = selector
                .filtered
                .iter()
                .map(|idx| {
                    let client = &items[*idx];
                    Row::new(vec![
                        Cell::from(client.client_id.clone()),
                        Cell::from(client.name.clone()),
                    ])
                })
                .collect::<Vec<_>>();
            let table = Table::new(
                rows,
                vec![Constraint::Percentage(45), Constraint::Percentage(55)],
            )
            .header(
                Row::new(vec!["Client ID", "Name"])
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .block(Block::default().borders(Borders::ALL))
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">> ");
            let mut state = TableState::default();
            if !selector.filtered.is_empty() {
                state.select(Some(selector.index));
            }
            frame.render_stateful_widget(table, inner[1], &mut state);
        }
    }

    let footer = Paragraph::new("↑↓ select | Enter apply | / filter | Esc cancel")
        .alignment(Alignment::Center);
    frame.render_widget(footer, inner[2]);

    if selector.filter_active {
        let cursor_x = inner[0].x + 3 + selector.filter.cursor() as u16;
        let cursor_y = inner[0].y + 1;
        frame.set_cursor(cursor_x, cursor_y);
        *cursor_visible = true;
    }
}

fn draw_password_gen(
    frame: &mut ratatui::Frame,
    area: Rect,
    gen: &PasswordGenState,
    cursor_visible: &mut bool,
) {
    let popup = centered_rect(60, 60, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(gen.title.clone());
    frame.render_widget(block, popup);

    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1), Constraint::Length(2)])
        .margin(1)
        .split(popup);

    let rows = vec![
        format!("Length: {}", gen.length.value()),
        format!("[{}] Uppercase (A-Z)", mark(gen.include_upper)),
        format!("[{}] Lowercase (a-z)", mark(gen.include_lower)),
        format!("[{}] Digits (0-9)", mark(gen.include_digits)),
        format!(
            "[{}] Special safe (- _ . , : ; @ +)",
            mark(gen.include_special_safe)
        ),
        format!("[{}] Special full (! @ # $ % ...)", mark(gen.include_special_full)),
        "Generate".to_string(),
    ];

    let lines: Vec<Line> = rows
        .into_iter()
        .enumerate()
        .map(|(idx, text)| {
            let prefix = if idx == gen.index { "> " } else { "  " };
            Line::from(vec![
                Span::styled(prefix, Style::default().fg(Color::Yellow)),
                Span::raw(text),
            ])
        })
        .collect();

    let mut lines = lines;
    if let Some(error) = &gen.error {
        lines.push(Line::from(Span::styled(
            error.clone(),
            Style::default().fg(Color::Red),
        )));
    }

    let paragraph = Paragraph::new(lines).alignment(Alignment::Left);
    frame.render_widget(paragraph, inner[0]);

    let footer = Paragraph::new("Tab move | Space toggle | Enter apply | Esc cancel")
        .alignment(Alignment::Center);
    frame.render_widget(footer, inner[1]);

    if gen.index == 0 {
        let prefix = "Length: ";
        let cursor_x = inner[0].x + 2 + prefix.len() as u16 + gen.length.cursor() as u16;
        let cursor_y = inner[0].y;
        frame.set_cursor(cursor_x, cursor_y);
        *cursor_visible = true;
    }
}

fn draw_relation_editor(frame: &mut ratatui::Frame, area: Rect, editor: &RelationEditorState) {
    let popup = centered_rect(70, 70, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(editor.title.clone());
    frame.render_widget(block, popup);

    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1), Constraint::Length(2)])
        .margin(1)
        .split(popup);

    let mut lines: Vec<Line> = editor
        .options
        .iter()
        .enumerate()
        .map(|(idx, option)| {
            let marker = if option.selected { "[x]" } else { "[ ]" };
            let prefix = if idx == editor.index { "> " } else { "  " };
            Line::from(vec![
                Span::styled(prefix, Style::default().fg(Color::Yellow)),
                Span::raw(format!("{marker} {}", option.label)),
            ])
        })
        .collect();

    if let Some(error) = &editor.error {
        lines.push(Line::from(Span::styled(
            error.clone(),
            Style::default().fg(Color::Red),
        )));
    }

    let paragraph = Paragraph::new(lines).alignment(Alignment::Left);
    frame.render_widget(paragraph, inner[0]);

    let footer = Paragraph::new("Space toggle | Enter apply | Esc cancel")
        .alignment(Alignment::Center);
    frame.render_widget(footer, inner[1]);
}

fn draw_claim_editor(frame: &mut ratatui::Frame, area: Rect, editor: &ClaimEditorState) {
    let popup = centered_rect(75, 70, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(editor.title.clone());
    frame.render_widget(block, popup);

    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1), Constraint::Length(2)])
        .margin(1)
        .split(popup);

    let rows = editor
        .items
        .iter()
        .map(|item| {
            let value = claim_value_to_display(&item.claim_value);
            let target = format_other_label(&item.other_label, &item.other_id);
            Row::new(vec![item.claim_name.clone(), value, target])
        })
        .collect::<Vec<_>>();
    let mut state = TableState::default();
    if !editor.items.is_empty() {
        state.select(Some(editor.index));
    }
    let table = Table::new(
        rows,
        vec![
            Constraint::Percentage(30),
            Constraint::Percentage(30),
            Constraint::Percentage(40),
        ],
    )
    .header(Row::new(vec!["Claim", "Value", "Target"]).style(Style::default().add_modifier(Modifier::BOLD)))
    .highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol(">> ");
    frame.render_stateful_widget(table, inner[0], &mut state);

    let error_lines = editor
        .error
        .as_ref()
        .map(|err| {
            err.lines()
                .map(|line| Line::from(Span::styled(line.to_string(), Style::default().fg(Color::Red))))
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec![Line::from("")]);
    let error = Paragraph::new(error_lines).wrap(Wrap { trim: true });
    frame.render_widget(error, inner[1]);

    let footer = Paragraph::new("a add | e edit | d delete | Enter apply | Esc cancel")
        .alignment(Alignment::Center);
    frame.render_widget(footer, inner[2]);
}

fn draw_claim_entry(
    frame: &mut ratatui::Frame,
    area: Rect,
    app: &App,
    entry: &ClaimEntryState,
    cursor_visible: &mut bool,
) {
    let popup = centered_rect(65, 60, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(entry.title.clone());
    frame.render_widget(block, popup);

    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1), Constraint::Length(2)])
        .margin(1)
        .split(popup);

    let other_label = entry
        .other_label
        .clone()
        .or_else(|| entry.other_id.clone())
        .unwrap_or_else(|| "<select>".to_string());
    let other_line = format_other_label(&other_label, entry.other_id.as_deref().unwrap_or(""));

    let mode = app
        .claim_editor
        .as_ref()
        .map(|editor| editor.mode.clone());
    let other_hint = match mode {
        Some(ClaimEditorMode::ClientClaims { .. }) => " (Ctrl+G select group)",
        Some(ClaimEditorMode::GroupClaims { .. }) => " (Ctrl+C select client)",
        None => "",
    };

    let fields = vec![
        ("claim_name", entry.claim_name.value().to_string(), ""),
        (
            "claim_value",
            entry.claim_value.value().to_string(),
            " (string nebo JSON array)",
        ),
        ("target", other_line, other_hint),
    ];

    let mut lines = Vec::new();
    let mut cursor = None;
    for (idx, (label, value, hint)) in fields.into_iter().enumerate() {
        let is_active = idx == entry.index;
        let prefix = if is_active { "> " } else { "  " };
        let mut spans = vec![
            Span::styled(prefix, Style::default().fg(Color::Yellow)),
            Span::styled(
                format!("{label}: "),
                Style::default()
                    .fg(if is_active { Color::Cyan } else { Color::White })
                    .add_modifier(if is_active { Modifier::BOLD } else { Modifier::empty() }),
            ),
            Span::styled(
                value.clone(),
                Style::default()
                    .fg(if is_active { Color::Cyan } else { Color::White })
                    .add_modifier(if is_active { Modifier::BOLD } else { Modifier::empty() }),
            ),
        ];
        if !hint.is_empty() {
            spans.push(Span::styled(hint, Style::default().fg(Color::DarkGray)));
        }
        lines.push(Line::from(spans));

        if is_active && idx < 2 {
            let cursor_offset = if idx == 0 {
                entry.claim_name.cursor()
            } else {
                entry.claim_value.cursor()
            };
            let cursor_x =
                inner[0].x + (prefix.len() + label.len() + 2 + cursor_offset) as u16;
            let cursor_y = inner[0].y + idx as u16;
            cursor = Some((cursor_x, cursor_y));
        }
    }

    if let Some(error) = &entry.error {
        lines.push(Line::from(Span::styled(
            error.clone(),
            Style::default().fg(Color::Red),
        )));
    }

    let paragraph = Paragraph::new(lines).alignment(Alignment::Left);
    frame.render_widget(paragraph, inner[0]);
    if let Some((x, y)) = cursor {
        frame.set_cursor(x, y);
        *cursor_visible = true;
    }

    let footer = Paragraph::new("Tab move | Enter next/save | Esc cancel")
        .alignment(Alignment::Center);
    frame.render_widget(footer, inner[1]);
}

fn format_other_label(label: &str, id: &str) -> String {
    if id.is_empty() {
        label.to_string()
    } else if label == id {
        label.to_string()
    } else {
        format!("{label} ({id})")
    }
}

fn mark(value: bool) -> char {
    if value { 'x' } else { ' ' }
}
