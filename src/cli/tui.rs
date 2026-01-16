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
use std::{collections::HashSet, io, time::Duration};
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
    cursor_visible: bool,
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
            group_users: EntityState::new(),
            mode: Mode::Normal,
            form: None,
            status: String::new(),
            pending_select: None,
            picker: None,
            selector: None,
            password_gen: None,
            relation_editor: None,
            cursor_visible: false,
        }
    }

    fn tabs() -> Vec<(Tab, &'static str)> {
        vec![
            (Tab::Users, "Users"),
            (Tab::Groups, "Groups"),
            (Tab::Clients, "Clients"),
            (Tab::ClaimMaps, "Claim maps"),
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

#[derive(Debug)]
enum SelectorItems {
    Users(Vec<UserRow>),
    Groups(Vec<GroupRow>),
}

#[derive(Debug)]
struct SelectorState {
    title: String,
    items: SelectorItems,
    filter: Input,
    filter_active: bool,
    index: usize,
    filtered: Vec<usize>,
    target_field: &'static str,
}

impl SelectorState {
    fn new_users(items: Vec<UserRow>, target_field: &'static str) -> Self {
        let mut state = Self {
            title: "Vyber uživatele".to_string(),
            items: SelectorItems::Users(items),
            filter: Input::default(),
            filter_active: false,
            index: 0,
            filtered: Vec::new(),
            target_field,
        };
        state.apply_filter();
        state
    }

    fn new_groups(items: Vec<GroupRow>, target_field: &'static str) -> Self {
        let mut state = Self {
            title: "Vyber skupinu".to_string(),
            items: SelectorItems::Groups(items),
            filter: Input::default(),
            filter_active: false,
            index: 0,
            filtered: Vec::new(),
            target_field,
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
            if handled == RelationResult::Applied || handled == RelationResult::Cancelled {
                app.mode = Mode::Normal;
                refresh_active_tab(app, http).await?;
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
                app.mode = Mode::Form;
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
            let value = match &selector.items {
                SelectorItems::Users(items) => items[selected_idx].id.clone(),
                SelectorItems::Groups(items) => items[selected_idx].id.clone(),
            };
            if let Some(form) = app.form.as_mut() {
                set_field_value(form, selector.target_field, value);
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
        Tab::ClaimMaps => app.claim_maps.select_next(),
        Tab::UserGroups => app.user_groups.select_next(),
        Tab::GroupUsers => app.group_users.select_next(),
    }
}

fn select_prev(app: &mut App) {
    match app.tab {
        Tab::Users => app.users.select_prev(),
        Tab::Groups => app.groups.select_prev(),
        Tab::Clients => app.clients.select_prev(),
        Tab::ClaimMaps => app.claim_maps.select_prev(),
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
        Tab::ClaimMaps => app.claim_maps.page += 1,
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
        Tab::ClaimMaps => app.claim_maps.page = app.claim_maps.page.saturating_sub(1).max(1),
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
    ClaimMaps,
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
            EntityKind::GroupUsers => app.group_users.select_first(),
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

async fn fetch_users_for_selector(http: &HttpClient) -> Result<Vec<UserRow>> {
    let body = http.get("/admin/users?page=1&limit=1000").await?;
    serde_json::from_str(&body).map_err(|e| anyhow!("Failed to parse users: {e}"))
}

async fn fetch_groups_for_selector(http: &HttpClient) -> Result<Vec<GroupRow>> {
    let body = http.get("/admin/groups?page=1&limit=1000").await?;
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
        Tab::GroupUsers => {
            let mut fields = vec![
                FormField::new("user_id", String::new()),
                FormField::new("group_id", String::new()),
            ];
            if let Some(row) = app
                .group_users
                .selected()
                .and_then(|idx| app.group_users.items.get(idx))
            {
                fields[1] = FormField::new("group_id", row.group_id.clone());
            }
            FormState {
                title: "Add user to group".to_string(),
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
    let mut request_selector: Option<&'static str> = None;

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
                if is_add_remove && label == Some("group_id") {
                    request_selector = Some("group_id");
                } else if label == Some("grant_types") {
                    let values = split_csv(Some(form.fields[form.index].value()));
                    app.picker = Some(PickerState::new_grant_types(&values));
                    app.mode = Mode::Picker;
                    return Ok(FormResult::Continue);
                }
            }
        }
        KeyCode::Char('u') => {
            if !key.modifiers.contains(KeyModifiers::CONTROL) {
                if is_add_remove && label == Some("user_id") {
                    request_selector = Some("user_id");
                }
            }
        }
        _ => {}
    }

    if let Some(target) = request_selector {
        let _ = form;
        if let Err(err) = open_selector(app, http, target).await {
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
                    label: Some(created.client_id.clone()),
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
                    label: Some(created.claim_name.clone()),
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

async fn open_selector(app: &mut App, http: &HttpClient, target_field: &'static str) -> Result<()> {
    match target_field {
        "user_id" => {
            let users = fetch_users_for_selector(http).await?;
            app.selector = Some(SelectorState::new_users(users, target_field));
            app.mode = Mode::Selector;
        }
        "group_id" => {
            let groups = fetch_groups_for_selector(http).await?;
            app.selector = Some(SelectorState::new_groups(groups, target_field));
            app.mode = Mode::Selector;
        }
        _ => {}
    }
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
            vec![Constraint::Percentage(35), Constraint::Percentage(65)],
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
            vec![Constraint::Percentage(35), Constraint::Percentage(65)],
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
        if field.label == "password" {
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
        if field.label == "user_id" {
            spans.push(Span::styled(
                " (u select)",
                Style::default().fg(Color::DarkGray),
            ));
        }
        if field.label == "group_id" {
            spans.push(Span::styled(
                " (g select)",
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
    {
        if let Some((x, y)) = cursor {
            frame.set_cursor(x, y);
            *cursor_visible = true;
        }
    }

    let footer = Paragraph::new("Enter next/submit | Tab switch | Esc cancel | g grant types | u user select | g group select | Ctrl+G secret | Ctrl+V reveal")
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
        Tab::ClaimMaps => "Claim maps",
        Tab::UserGroups => "User groups",
        Tab::GroupUsers => "Group users",
    }
}

fn active_page(app: &App) -> usize {
    match app.tab {
        Tab::Users => app.users.page,
        Tab::Groups => app.groups.page,
        Tab::Clients => app.clients.page,
        Tab::ClaimMaps => app.claim_maps.page,
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
        .constraints([Constraint::Min(1), Constraint::Length(2)])
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
        .constraints([Constraint::Min(1), Constraint::Length(2)])
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

fn mark(value: bool) -> char {
    if value { 'x' } else { ' ' }
}
