use crate::{
    dashboard_table::DashboardTable, sandbox_table::SandboxTable, theme, ui_forms::NativeForm,
};
use gantry_desktop::{
    connector::{Connector, Target},
    dashboard_wire::{HostSnapshot, PacketSnapshot},
    inventory::{Filter, Inventory, demo_sandboxes},
    options::{Appearance, Options, SocketDefaults, Source},
    profiles::RemoteProfile,
    workspace::{self, Page, Record},
};
use gpui_kit::component::{
    input::{InputEvent, InputState},
    table::{TableEvent, TableState},
};
use gpui_kit::{AppContext, Context, Entity, FocusHandle, Focusable, Subscription, Task, Window};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

gpui_kit::actions!(
    gantry_desktop,
    [Quit, Refresh, FocusSearch, FocusInventory, CloseForm]
);
pub(crate) enum Connection {
    Connecting,
    Connected(String),
    Offline(String),
    Demo,
}
pub struct PageView {
    pub table: Entity<TableState<DashboardTable>>,
    pub query: String,
    pub selected: Option<String>,
    pub selection_initialized: bool,
}
pub(crate) struct Desktop {
    pub options: Options,
    pub inventory: Inventory,
    pub table: Entity<TableState<SandboxTable>>,
    pub search: Entity<InputState>,
    pub connection: Connection,
    pub refreshing: bool,
    pub last_updated: Option<Instant>,
    pub focus: FocusHandle,
    pub page: Page,
    pub pages: Vec<PageView>,
    pub host: HostSnapshot,
    pub dashboard_available: bool,
    pub control_available: bool,
    pub target: Option<Target>,
    pub profiles: Vec<RemoteProfile>,
    pub profiles_error: Option<String>,
    pub config_dir: Option<PathBuf>,
    pub local_options: Option<Options>,
    pub form: Option<NativeForm>,
    pub writing: bool,
    pub notice: Option<String>,
    pub packets: PacketSnapshot,
    pub packet_sandbox: Option<String>,
    pub connector: Arc<Mutex<Connector>>,
    pub generation: u64,
    _subscriptions: Vec<Subscription>,
    _poll_task: Option<Task<()>>,
    _request_task: Option<Task<()>>,
    pub action_task: Option<Task<()>>,
    pub progress_task: Option<Task<()>>,
}
impl Desktop {
    pub fn new(options: Options, window: &mut Window, cx: &mut Context<Self>) -> Self {
        theme::apply(options.appearance, window, cx);
        let search = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Search this screen…")
                .clean_on_escape()
        });
        let table = cx.new(|cx| {
            TableState::new(SandboxTable::new(), window, cx)
                .row_selectable(true)
                .col_selectable(false)
        });
        let mut subscriptions = vec![
            cx.subscribe_in(
                &search,
                window,
                |this, input, event, window, cx| match event {
                    InputEvent::Change => {
                        let query = input.read(cx).value().to_string();
                        if this.page == Page::Sandboxes {
                            this.inventory.set_query(query);
                            this.sync_table(cx);
                        } else {
                            let page = &mut this.pages[this.page.index()];
                            if page.query != query {
                                page.selection_initialized = false;
                            }
                            page.query = query;
                            this.sync_pages(cx);
                        }
                    }
                    InputEvent::PressEnter { .. } => this.focus_inventory(window, cx),
                    _ => {}
                },
            ),
            cx.subscribe(&table, |this, table, event, cx| {
                if this.page != Page::Sandboxes {
                    return;
                }
                match event {
                    TableEvent::SelectRow(index) => {
                        if let Some(row) = table.read(cx).delegate().rows.get(*index) {
                            this.inventory.select(&row.name);
                        }
                    }
                    TableEvent::ClearSelection => this.inventory.clear_selection(),
                    _ => return,
                }
                cx.notify();
            }),
            cx.observe_window_appearance(window, |this, window, cx| {
                if this.options.appearance == Appearance::System {
                    theme::apply(Appearance::System, window, cx);
                    cx.notify();
                }
            }),
        ];
        let pages = Page::ALL
            .into_iter()
            .map(|page| {
                let table = cx.new(|cx| {
                    TableState::new(DashboardTable::new(page), window, cx)
                        .row_selectable(true)
                        .col_selectable(false)
                });
                subscriptions.push(cx.subscribe(
                    &table,
                    move |this: &mut Self, table, event, cx| {
                        if this.page != page {
                            return;
                        }
                        match event {
                            TableEvent::SelectRow(index) => {
                                this.pages[page.index()].selected = table
                                    .read(cx)
                                    .delegate()
                                    .rows
                                    .get(*index)
                                    .map(|r| r.key.clone())
                            }
                            TableEvent::ClearSelection => this.pages[page.index()].selected = None,
                            _ => return,
                        }
                        cx.notify();
                    },
                ));
                PageView {
                    table,
                    query: String::new(),
                    selected: None,
                    selection_initialized: false,
                }
            })
            .collect();
        let config_dir = if options.source == Source::Demo {
            None
        } else {
            match &options.source {
                Source::Remote { config_dir, .. } => Some(config_dir.clone()),
                _ => SocketDefaults::from_env().base().ok(),
            }
        };
        let local_options = if matches!(options.source, Source::Local(_)) {
            Some(options.clone())
        } else {
            Options::parse([], SocketDefaults::from_env())
                .ok()
                .flatten()
                .map(|mut local| {
                    local.gantry = options.gantry.clone();
                    local
                })
        };
        let connector = Arc::new(Mutex::new(Connector::new(&options)));
        let mut this = Self {
            options,
            connector,
            inventory: Inventory::default(),
            table,
            search,
            connection: Connection::Connecting,
            refreshing: false,
            last_updated: None,
            focus: cx.focus_handle(),
            page: Page::Sandboxes,
            pages,
            host: HostSnapshot::default(),
            dashboard_available: false,
            control_available: false,
            target: None,
            profiles: vec![],
            profiles_error: None,
            config_dir,
            local_options,
            form: None,
            writing: false,
            notice: None,
            packets: PacketSnapshot::default(),
            packet_sandbox: None,
            generation: 0,
            _subscriptions: subscriptions,
            _poll_task: None,
            _request_task: None,
            action_task: None,
            progress_task: None,
        };
        if this.options.source == Source::Demo {
            this.inventory.replace(demo_sandboxes());
            this.inventory.select("dev");
            this.host = workspace::demo();
            this.dashboard_available = true;
            this.control_available = true;
            this.connection = Connection::Demo;
            this.sync_table(cx);
            this.sync_pages(cx);
        } else {
            this.fetch(false, cx);
            this._poll_task = Some(cx.spawn(async move |this, cx| {
                loop {
                    cx.background_executor().timer(Duration::from_secs(3)).await;
                    if this.update(cx, |this, cx| this.fetch(false, cx)).is_err() {
                        break;
                    }
                }
            }));
        }
        this.focus_inventory(window, cx);
        this
    }
    pub fn can_write(&self) -> bool {
        self.options.source != Source::Demo
            && matches!(self.connection, Connection::Connected(_))
            && self.dashboard_available
            && self.control_available
            && self
                .target
                .as_ref()
                .is_some_and(|target| target.source == self.options.source)
            && !self.writing
    }
    pub fn can_edit_profiles(&self) -> bool {
        self.options.source != Source::Demo && self.config_dir.is_some() && !self.writing
    }
    pub fn refresh(&mut self, cx: &mut Context<Self>) {
        self.fetch(true, cx);
    }
    pub fn fetch(&mut self, retry_start: bool, cx: &mut Context<Self>) {
        if self.options.source == Source::Demo || self.refreshing || self.writing {
            return;
        }
        self.refreshing = true;
        let connector = self.connector.clone();
        let base = self.config_dir.clone();
        let generation = self.generation;
        let request = cx.background_spawn(async move {
            let profiles = base
                .as_ref()
                .map(|base| gantry_desktop::profiles::list(base))
                .unwrap_or_else(|| Ok(vec![]));
            let workspace = connector
                .lock()
                .map_err(|_| anyhow::anyhow!("Manager connector failed"))
                .and_then(|mut c| c.workspace(retry_start));
            (workspace, profiles)
        });
        self._request_task = Some(cx.spawn(async move |this, cx| {
            let (result, profiles) = request.await;
            let _ = this.update(cx, |this, cx| {
                if generation != this.generation {
                    return;
                }
                this.refreshing = false;
                match profiles {
                    Ok(profiles) => {
                        this.profiles = profiles;
                        this.profiles_error = None;
                    }
                    Err(error) => {
                        this.profiles.clear();
                        this.profiles_error = Some(error.to_string());
                    }
                }
                match result {
                    Ok(snapshot) => {
                        this.inventory.replace(snapshot.inventory.sandboxes);
                        this.connection = Connection::Connected(snapshot.inventory.version);
                        this.dashboard_available = snapshot.dashboard.is_some();
                        this.control_available = snapshot
                            .inventory
                            .capabilities
                            .iter()
                            .any(|c| c == "dashboard-control-v1");
                        this.host = snapshot.dashboard.unwrap_or_default();
                        this.target = Some(snapshot.target);
                        this.last_updated = Some(Instant::now());
                    }
                    Err(error) => {
                        this.inventory.replace(vec![]);
                        this.host = HostSnapshot::default();
                        this.dashboard_available = false;
                        this.control_available = false;
                        this.target = None;
                        this.connection = Connection::Offline(error.to_string());
                        this.last_updated = None;
                        this.packets = PacketSnapshot::default();
                    }
                }
                this.sync_table(cx);
                this.sync_pages(cx);
            });
        }));
        cx.notify();
    }
    fn sync_table(&mut self, cx: &mut Context<Self>) {
        let rows = self
            .inventory
            .visible()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let selected = self.inventory.selected().map(|r| r.name.as_str());
        let index = rows.iter().position(|r| Some(r.name.as_str()) == selected);
        self.table.update(cx, |table, cx| {
            let old = table
                .selected_row()
                .and_then(|i| table.delegate().rows.get(i))
                .map(|r| r.name.clone());
            table.delegate_mut().rows = rows;
            match index {
                Some(i) if table.selected_row() != Some(i) || old.as_deref() != selected => {
                    table.set_selected_row(i, cx)
                }
                None if table.selected_row().is_some() => table.clear_selection(cx),
                _ => {}
            }
            cx.notify();
        });
        cx.notify();
    }
    pub fn sync_pages(&mut self, cx: &mut Context<Self>) {
        for page in Page::ALL {
            if page == Page::Sandboxes {
                continue;
            }
            let state = &mut self.pages[page.index()];
            let query = state.query.to_lowercase();
            let rows = workspace::rows(page, &self.host, &self.profiles, &self.packets)
                .into_iter()
                .filter(|r| {
                    query.is_empty() || r.cells.iter().any(|s| s.to_lowercase().contains(&query))
                })
                .collect::<Vec<_>>();
            if (!state.selection_initialized || state.selected.is_some())
                && !rows.iter().any(|r| Some(&r.key) == state.selected.as_ref())
            {
                state.selected = rows.first().map(|r| r.key.clone());
            }
            if !rows.is_empty() {
                state.selection_initialized = true;
            }
            let index = rows
                .iter()
                .position(|r| Some(&r.key) == state.selected.as_ref());
            state.table.update(cx, |table, cx| {
                table.delegate_mut().rows = rows;
                match index {
                    Some(i) if table.selected_row() != Some(i) => table.set_selected_row(i, cx),
                    None if table.selected_row().is_some() => table.clear_selection(cx),
                    _ => {}
                }
                cx.notify();
            });
        }
        cx.notify();
    }
    pub fn selected_record(&self, cx: &Context<Self>) -> Option<Record> {
        let state = &self.pages[self.page.index()];
        state
            .table
            .read(cx)
            .delegate()
            .rows
            .iter()
            .find(|r| Some(&r.key) == state.selected.as_ref())
            .map(|r| r.record.clone())
    }
    pub fn switch_page(&mut self, page: Page, window: &mut Window, cx: &mut Context<Self>) {
        if self.form.is_some() {
            return;
        }
        self.page = page;
        let query = if page == Page::Sandboxes {
            self.inventory.query.clone()
        } else {
            self.pages[page.index()].query.clone()
        };
        self.search
            .update(cx, |s, cx| s.set_value(query, window, cx));
        self.focus_inventory(window, cx);
        cx.notify();
    }
    pub fn switch_source(&mut self, options: Options, window: &mut Window, cx: &mut Context<Self>) {
        if self.writing || self.form.is_some() || self.options.source == Source::Demo {
            return;
        }
        self.generation += 1;
        self._request_task = None;
        self.refreshing = false;
        self.options = options;
        self.connector = Arc::new(Mutex::new(Connector::new(&self.options)));
        self.inventory.replace(vec![]);
        self.host = HostSnapshot::default();
        self.target = None;
        self.dashboard_available = false;
        self.control_available = false;
        self.connection = Connection::Connecting;
        self.last_updated = None;
        self.packets = PacketSnapshot::default();
        self.packet_sandbox = None;
        self.notice = None;
        for state in &mut self.pages {
            state.selected = None;
            state.selection_initialized = false;
        }
        self.sync_table(cx);
        self.sync_pages(cx);
        self.fetch(false, cx);
        self.focus_inventory(window, cx);
    }
    pub fn set_filter(&mut self, filter: Filter, cx: &mut Context<Self>) {
        self.inventory.set_filter(filter);
        self.sync_table(cx);
    }
    pub fn cycle_theme(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.options.appearance = self.options.appearance.next();
        theme::apply(self.options.appearance, window, cx);
        cx.notify();
    }
    pub fn focus_search(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.form.is_none() {
            self.search.focus_handle(cx).focus(window, cx);
        }
    }
    pub fn focus_inventory(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.form.is_some() {
            return;
        }
        if self.page != Page::Sandboxes {
            self.pages[self.page.index()]
                .table
                .focus_handle(cx)
                .focus(window, cx);
        } else if self.inventory.visible().is_empty() {
            self.focus.focus(window, cx);
        } else {
            self.table.focus_handle(cx).focus(window, cx);
        }
    }
}
