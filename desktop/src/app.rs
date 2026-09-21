use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use gantry_desktop::{
    connector::Connector,
    inventory::{Filter, Inventory, demo_sandboxes},
    options::{Appearance, Options, Source},
};
use gpui_kit::component::{
    input::{InputEvent, InputState},
    table::{TableEvent, TableState},
};
use gpui_kit::{AppContext, Context, Entity, FocusHandle, Focusable, Subscription, Task, Window};

use crate::{sandbox_table::SandboxTable, theme};

gpui_kit::actions!(gantry_desktop, [Quit, Refresh, FocusSearch, FocusInventory]);

pub(crate) enum Connection {
    Connecting,
    Connected(String),
    Offline(String),
    Demo,
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
    connector: Arc<Mutex<Connector>>,
    _subscriptions: Vec<Subscription>,
    // Retained tasks are cancelled with the window. Blocking requests also have
    // a deadline; neither polling nor a response can retain the view forever.
    _poll_task: Option<Task<()>>,
    _request_task: Option<Task<()>>,
}

impl Desktop {
    pub fn new(options: Options, window: &mut Window, cx: &mut Context<Self>) -> Self {
        theme::apply(options.appearance, window, cx);
        let search = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Search name, image, or status…")
                .clean_on_escape()
        });
        let table = cx.new(|cx| {
            TableState::new(SandboxTable::new(), window, cx)
                .row_selectable(true)
                .col_selectable(false)
        });
        let subscriptions = vec![
            cx.subscribe_in(
                &search,
                window,
                |this, input, event, window, cx| match event {
                    InputEvent::Change => {
                        this.inventory.set_query(input.read(cx).value().to_string());
                        this.sync_table(cx);
                    }
                    InputEvent::PressEnter { .. } => this.focus_inventory(window, cx),
                    _ => {}
                },
            ),
            cx.subscribe(&table, |this, table, event, cx| {
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
            _subscriptions: subscriptions,
            _poll_task: None,
            _request_task: None,
        };
        if this.options.source == Source::Demo {
            this.inventory.replace(demo_sandboxes());
            this.inventory.select("dev");
            this.connection = Connection::Demo;
            this.sync_table(cx);
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

    pub fn refresh(&mut self, cx: &mut Context<Self>) {
        self.fetch(true, cx);
    }

    fn fetch(&mut self, retry_start: bool, cx: &mut Context<Self>) {
        if self.options.source == Source::Demo || self.refreshing {
            return;
        }
        self.refreshing = true;
        let connector = self.connector.clone();
        let request = cx.background_spawn(async move {
            connector
                .lock()
                .map_err(|_| anyhow::anyhow!("Manager connector failed"))?
                .snapshot(retry_start)
        });
        self._request_task = Some(cx.spawn(async move |this, cx| {
            let result = request.await;
            let _ = this.update(cx, |this, cx| {
                this.refreshing = false;
                match result {
                    Ok(snapshot) => {
                        this.inventory.replace(snapshot.sandboxes);
                        this.connection = Connection::Connected(snapshot.version);
                        this.last_updated = Some(Instant::now());
                    }
                    Err(err) => {
                        // Unavailable is not stopped, and stale running rows
                        // must not masquerade as current manager state.
                        this.inventory.replace(Vec::new());
                        this.connection = Connection::Offline(err.to_string());
                        this.last_updated = None;
                    }
                }
                this.sync_table(cx);
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
        let selected = self.inventory.selected().map(|row| row.name.as_str());
        let selected_index = rows
            .iter()
            .position(|row| Some(row.name.as_str()) == selected);
        self.table.update(cx, |table, cx| {
            let old_name = table
                .selected_row()
                .and_then(|index| table.delegate().rows.get(index))
                .map(|row| row.name.clone());
            table.delegate_mut().rows = rows;
            // Rows changed, not column definitions. Keep user column widths and
            // scroll offsets; only reveal a selection when its identity/index changes.
            match selected_index {
                Some(index)
                    if table.selected_row() != Some(index) || old_name.as_deref() != selected =>
                {
                    table.set_selected_row(index, cx)
                }
                None if table.selected_row().is_some() => table.clear_selection(cx),
                _ => {}
            }
            cx.notify();
        });
        cx.notify();
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
        self.search.focus_handle(cx).focus(window, cx);
    }

    pub fn focus_inventory(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.inventory.visible().is_empty() {
            self.focus.focus(window, cx);
        } else {
            self.table.focus_handle(cx).focus(window, cx);
        }
    }
}
