use crate::{
    dashboard_table::{DashboardTable, TableScale},
    sandbox_table::{RowExtras, SandboxTable, TrafficTrend},
    theme,
    ui_forms::NativeForm,
};
use gantry_desktop::{
    connector::{Connector, Target},
    dashboard_wire::{HostSnapshot, PacketSnapshot},
    detail,
    inventory::{Filter, Inventory, demo_sandboxes},
    launcher::CliMissing,
    options::{Appearance, Options, SocketDefaults, Source},
    org::{self, OrgSnapshot},
    profiles::RemoteProfile,
    telemetry::Throughput,
    workspace::{self, Page, Record},
};
use gpui_kit::component::{
    input::{InputEvent, InputState},
    table::{TableEvent, TableState},
};
use gpui_kit::{AppContext, Context, Entity, FocusHandle, Focusable, Subscription, Task, Window};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

gpui_kit::actions!(
    gantry_desktop,
    [
        Quit,
        Refresh,
        FocusSearch,
        FocusInventory,
        CloseForm,
        NewSandbox,
        EditSandbox,
        StartSandbox,
        StopSandbox,
        DeleteSandbox,
        ToggleInspector,
        ToggleActivity,
        CycleAppearance,
        ShowConnections,
        ShowOverview,
        ShowImages,
        ShowManual,
        MinimizeWindow,
        ZoomWindow,
        FullScreen
    ]
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
    /// Index into `Page::segments()`; 0 shows every row.
    pub segment: usize,
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
    /// Live capture reads are paused, to hold the list still.
    pub packets_paused: bool,
    /// Open sandbox terminals by sandbox name, for the selected connection.
    pub terminals: HashMap<String, Entity<crate::terminal_view::TerminalView>>,
    /// Why the last attempt to open a sandbox's terminal failed, shown in
    /// that sandbox's Terminal tab: (sandbox, message).
    pub terminal_error: Option<(String, String)>,
    pub packets_reading: bool,
    pub packet_error: Option<String>,
    /// Packets per second since capture started, for the chart.
    pub capture_rate: gantry_desktop::capture::CaptureRate,
    pub(crate) packet_task: Option<Task<()>>,
    pub connector: Arc<Mutex<Connector>>,
    pub generation: u64,
    /// Rates derived from successive dashboard snapshots, for this window only.
    pub throughput: Throughput,
    pub detail_tab: detail::Tab,
    /// The last local startup found no Gantry CLI at all (not a failing one).
    pub cli_missing: bool,
    pub installing: bool,
    pub install_task: Option<Task<()>>,
    pub install_progress_task: Option<Task<()>>,
    _subscriptions: Vec<Subscription>,
    _poll_task: Option<Task<()>>,
    _packet_poll_task: Option<Task<()>>,
    _request_task: Option<Task<()>>,
    pub action_task: Option<Task<()>>,
    pub progress_task: Option<Task<()>>,
    pub activity: Vec<crate::activity::Entry>,
    pub activity_open: bool,
    pub inspector_open: bool,
    pub inspector_width: gpui_kit::Pixels,
    pub inspector_settings: bool,
    pub images_registries: bool,
    pub context_menu: Option<Entity<gpui_kit::component::menu::PopupMenu>>,
    pub context_position: gpui_kit::Point<gpui_kit::Pixels>,
    pub context_subscription: Option<Subscription>,
    /// The selected connection is an organization's policy service. It stays
    /// set while that connection is offline, so the workspace does not flip.
    pub org_mode: bool,
    /// The policy service's latest snapshot; cleared when a refresh fails.
    pub organization: Option<OrgSnapshot>,
    /// The profile shown on the Policy page.
    pub org_profile: String,
    /// The page changed without a window (a refresh entered or left an
    /// organization); the next render updates the search field for it.
    pub page_unsynced: bool,
}
impl Desktop {
    pub fn new(options: Options, window: &mut Window, cx: &mut Context<Self>) -> Self {
        theme::apply(options.appearance, window, cx);
        let search = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Search sandboxes")
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
            cx.subscribe_in(&table, window, |this, table, event, window, cx| {
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
                    // Double-clicking a sandbox opens its shell.
                    TableEvent::DoubleClickedRow(index) => {
                        let Some(name) = table
                            .read(cx)
                            .delegate()
                            .rows
                            .get(*index)
                            .map(|row| row.name.clone())
                        else {
                            return;
                        };
                        this.inventory.select(&name);
                        this.open_terminal(&name, window, cx);
                    }
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
                    segment: 0,
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
            packets_paused: false,
            terminals: HashMap::new(),
            terminal_error: None,
            packets_reading: false,
            packet_error: None,
            capture_rate: Default::default(),
            packet_task: None,
            generation: 0,
            throughput: Throughput::default(),
            detail_tab: detail::Tab::default(),
            cli_missing: false,
            installing: false,
            install_task: None,
            install_progress_task: None,
            _subscriptions: subscriptions,
            _poll_task: None,
            _packet_poll_task: None,
            _request_task: None,
            action_task: None,
            progress_task: None,
            activity: Vec::new(),
            activity_open: false,
            inspector_open: true,
            inspector_width: gpui_kit::px(theme::INSPECTOR_WIDTH),
            inspector_settings: false,
            images_registries: false,
            context_menu: None,
            context_position: Default::default(),
            context_subscription: None,
            org_mode: false,
            organization: None,
            org_profile: String::new(),
            page_unsynced: false,
        };
        if this.options.source == Source::Demo {
            this.inventory.replace(demo_sandboxes());
            this.inventory.select("dev");
            this.host = workspace::demo();
            this.throughput = Throughput::demo(&this.host.snapshot.sandboxes);
            this.packets = workspace::demo_packets();
            this.capture_rate
                .record(&this.packets.packets, gantry_desktop::clock::now_millis());
            this.packet_sandbox = Some("dev".into());
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
            // Packet Capture reads new frames while it is on screen.
            this._packet_poll_task = Some(cx.spawn(async move |this, cx| {
                loop {
                    cx.background_executor().timer(Duration::from_secs(1)).await;
                    if this.update(cx, |this, cx| this.read_packets(cx)).is_err() {
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
            && (self.dashboard_available || self.org_mode && self.organization.is_some())
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
                        this.cli_missing = false;
                        this.inventory.replace(snapshot.inventory.sandboxes);
                        this.connection = Connection::Connected(snapshot.inventory.version);
                        this.dashboard_available = snapshot.dashboard.is_some();
                        let organization = snapshot.organization.is_some();
                        this.control_available = organization
                            || snapshot
                                .inventory
                                .capabilities
                                .iter()
                                .any(|c| c == "dashboard-control-v1");
                        this.set_organization(snapshot.organization, cx);
                        this.host = snapshot.dashboard.unwrap_or_default();
                        this.throughput
                            .record(Instant::now(), &this.host.snapshot.sandboxes);
                        this.target = Some(snapshot.target);
                        this.last_updated = Some(Instant::now());
                    }
                    Err(error) => {
                        this.cli_missing = error.downcast_ref::<CliMissing>().is_some();
                        this.inventory.replace(vec![]);
                        this.host = HostSnapshot::default();
                        this.throughput.clear();
                        this.dashboard_available = false;
                        this.control_available = false;
                        this.target = None;
                        this.connection = Connection::Offline(error.to_string());
                        this.last_updated = None;
                        this.packets = PacketSnapshot::default();
                        this.capture_rate.clear();
                        this.organization = None;
                    }
                }
                this.sync_table(cx);
                this.sync_pages(cx);
            });
        }));
        cx.notify();
    }
    pub(crate) fn sync_table(&mut self, cx: &mut Context<Self>) {
        let rows = self
            .inventory
            .visible()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let selected = self.inventory.selected().map(|r| r.name.as_str());
        let index = rows.iter().position(|r| Some(r.name.as_str()) == selected);
        let target = self.target.clone();
        let extras = self.row_extras();
        self.table.update(cx, |table, cx| {
            table.delegate_mut().target = target;
            table.delegate_mut().extras = extras;
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
    /// Features and traffic trend per sandbox, joined by name from the
    /// dashboard snapshot. Managers without the dashboard API contribute none.
    fn row_extras(&self) -> HashMap<String, RowExtras> {
        self.host
            .snapshot
            .sandboxes
            .iter()
            .map(|s| {
                let traffic = if s.state != "running" {
                    TrafficTrend::Idle
                } else if s.traffic_available {
                    TrafficTrend::Tracked {
                        rates: self.throughput.rates(&s.name).to_vec(),
                    }
                } else {
                    TrafficTrend::Unreported
                };
                (
                    s.name.clone(),
                    RowExtras {
                        features: detail::features(s),
                        traffic,
                    },
                )
            })
            .collect()
    }
    pub fn sync_pages(&mut self, cx: &mut Context<Self>) {
        for page in Page::ALL {
            if page == Page::Sandboxes {
                continue;
            }
            let registries = self.images_registries;
            let scale = TableScale::new(page, &self.host);
            let all = self.page_rows(page);
            let state = &mut self.pages[page.index()];
            let query = state.query.to_lowercase();
            let segment = state.segment;
            let rows = all
                .into_iter()
                .filter(|r| {
                    (page != Page::Images || matches!(&r.record, Record::Registry(_)) == registries)
                        && workspace::segment_matches(page, segment, &r.record)
                        && (query.is_empty()
                            || r.cells.iter().any(|s| s.to_lowercase().contains(&query)))
                })
                .collect::<Vec<_>>();
            if (!state.selection_initialized || state.selected.is_some())
                && !rows.iter().any(|r| Some(&r.key) == state.selected.as_ref())
            {
                // The draft's inspector with nothing selected is its publish
                // panel, so the Policy page starts without a selection.
                state.selected = if page == Page::OrgPolicy {
                    None
                } else {
                    rows.first().map(|r| r.key.clone())
                };
            }
            if !rows.is_empty() {
                state.selection_initialized = true;
            }
            let index = rows
                .iter()
                .position(|r| Some(&r.key) == state.selected.as_ref());
            state.table.update(cx, |table, cx| {
                table.delegate_mut().rows = rows;
                table.delegate_mut().scale = scale;
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
    /// A page's records: the manager's dashboard, the client's profiles, or
    /// the organization's policy service.
    pub fn page_rows(&self, page: Page) -> Vec<workspace::Row> {
        match (page, &self.organization) {
            (Page::OrgHosts | Page::OrgRollouts, Some(o)) => org::host_rows(o, false),
            (Page::OrgEnrollment, Some(o)) => org::host_rows(o, true),
            (Page::OrgHistory, Some(o)) => org::generation_rows(o),
            (Page::OrgPolicy, Some(o)) => org::policy_rows(o, &self.org_profile),
            (page, _) if page.is_organization() => vec![],
            (page, _) => workspace::rows(page, &self.host, &self.profiles, &self.packets),
        }
    }
    /// Adopt a refreshed organization snapshot (or its absence) and keep the
    /// page within the workspace the connection offers.
    pub fn set_organization(&mut self, snapshot: Option<OrgSnapshot>, cx: &mut Context<Self>) {
        let entering = snapshot.is_some() && !self.org_mode;
        self.org_mode = snapshot.is_some();
        if let Some(snapshot) = &snapshot {
            let profiles = snapshot.profiles();
            if !profiles.contains(&self.org_profile) {
                self.org_profile = profiles
                    .iter()
                    .find(|p| p.as_str() == "developer")
                    .or(profiles.first())
                    .cloned()
                    .unwrap_or_default();
            }
        }
        self.organization = snapshot;
        // Connections stay reachable from either workspace.
        let foreign = if self.org_mode {
            !self.page.is_organization() && self.page != Page::Remotes
        } else {
            self.page.is_organization()
        };
        if entering || foreign {
            self.page = if self.org_mode {
                Page::OrgHosts
            } else {
                Page::Sandboxes
            };
            self.inspector_settings = false;
            self.page_unsynced = true;
        }
        cx.notify();
    }
    /// Demo mode's sample organization, beside its sample manager. It is
    /// read-only like the rest of demo mode.
    pub fn show_demo_organization(
        &mut self,
        show: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.options.source != Source::Demo || self.form.is_some() {
            return;
        }
        self.set_organization(show.then(org::demo), cx);
        self.sync_pages(cx);
        self.switch_page(self.page, window, cx);
    }
    pub fn set_org_profile(&mut self, profile: String, cx: &mut Context<Self>) {
        if self.org_profile != profile {
            self.org_profile = profile;
            let state = &mut self.pages[Page::OrgPolicy.index()];
            state.selected = None;
            state.selection_initialized = false;
        }
        self.sync_pages(cx);
    }
    /// Switch the Images page between cached images and registry logins.
    /// The two lists have their own segments and selection.
    pub fn set_images_registries(&mut self, registries: bool, cx: &mut Context<Self>) {
        if self.images_registries != registries {
            self.images_registries = registries;
            let state = &mut self.pages[Page::Images.index()];
            state.segment = 0;
            state.selected = None;
            state.selection_initialized = false;
        }
        self.sync_pages(cx);
    }
    /// Select a record by key on the current page (for drawn, non-table lists).
    pub fn select_page_row(&mut self, key: String, cx: &mut Context<Self>) {
        let state = &mut self.pages[self.page.index()];
        state.selected = Some(key);
        state.selection_initialized = true;
        self.sync_pages(cx);
    }
    /// Select a row, or clear the selection when it is already selected.
    pub fn toggle_page_row(&mut self, key: String, cx: &mut Context<Self>) {
        let state = &mut self.pages[self.page.index()];
        if state.selected.as_deref() == Some(key.as_str()) {
            state.selected = None;
            state.selection_initialized = true;
            self.sync_pages(cx);
        } else {
            self.select_page_row(key, cx);
        }
    }
    pub fn set_segment(&mut self, segment: usize, cx: &mut Context<Self>) {
        let state = &mut self.pages[self.page.index()];
        if state.segment != segment {
            state.segment = segment;
            state.selection_initialized = false;
            self.sync_pages(cx);
        }
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
        self.context_menu = None;
        self.context_subscription = None;
        self.page = page;
        self.page_unsynced = false;
        self.inspector_settings = false;
        let query = if page == Page::Sandboxes {
            self.inventory.query.clone()
        } else {
            self.pages[page.index()].query.clone()
        };
        self.search.update(cx, |s, cx| {
            s.set_placeholder(
                if page == Page::Sandboxes {
                    "Search sandboxes"
                } else {
                    "Search this screen…"
                },
                window,
                cx,
            );
            s.set_value(query, window, cx);
        });
        self.focus_inventory(window, cx);
        cx.notify();
    }
    pub fn switch_source(&mut self, options: Options, window: &mut Window, cx: &mut Context<Self>) {
        if self.writing || self.form.is_some() || self.options.source == Source::Demo {
            return;
        }
        self.context_menu = None;
        self.context_subscription = None;
        self.generation += 1;
        self._request_task = None;
        self.refreshing = false;
        self.options = options;
        self.connector = Arc::new(Mutex::new(Connector::new(&self.options)));
        self.inventory.replace(vec![]);
        self.host = HostSnapshot::default();
        self.throughput.clear();
        self.target = None;
        self.dashboard_available = false;
        self.control_available = false;
        self.connection = Connection::Connecting;
        self.cli_missing = false;
        self.last_updated = None;
        self.packets = PacketSnapshot::default();
        self.capture_rate.clear();
        self.packet_sandbox = None;
        self.org_mode = false;
        self.organization = None;
        if self.page.is_organization() {
            self.page = Page::Sandboxes;
        }
        // Terminals belong to the connection they were opened on.
        self.terminals.clear();
        self.terminal_error = None;
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
