use crate::{app::*, row_actions, theme};
use gantry_desktop::{
    forms::Kind,
    options::{Appearance, Source},
    workspace::{self, Page},
};
use gpui_kit::assets::IconName;
use gpui_kit::component::{
    ActiveTheme, Disableable, Icon, Selectable, Sizable, TitleBar,
    button::{Button, ButtonVariants},
    input::Input,
    menu::DropdownMenu,
    scroll::ScrollableElement,
};
use gpui_kit::{
    App, Context, Div, FontWeight, InteractiveElement, IntoElement, ParentElement, Styled,
    TestSupportExt, Window, div, prelude::FluentBuilder, px, rgb,
};

pub fn page_icon(page: Page) -> IconName {
    match page {
        Page::Overview => IconName::LayoutDashboard,
        Page::Sandboxes => IconName::Box,
        Page::Traffic => IconName::ArrowLeftRight,
        Page::Rules => IconName::ShieldCheck,
        Page::Ports => IconName::Network,
        Page::Packets => IconName::Activity,
        Page::Mounts => IconName::Folder,
        Page::Secrets => IconName::Key,
        Page::Mcp => IconName::Plug,
        Page::Audit => IconName::ClipboardList,
        Page::Images => IconName::Layers,
        Page::Remotes => IconName::Server,
    }
}
impl Desktop {
    pub fn source_name(&self) -> String {
        match &self.options.source {
            Source::Demo => "Demo".into(),
            Source::Local(_) => if cfg!(target_os = "macos") {
                "This Mac"
            } else {
                "This Machine"
            }
            .into(),
            Source::Remote { name, .. } => workspace::text(name),
        }
    }
    /// The page's icon; Registries share the Images page.
    pub fn page_icon(&self) -> IconName {
        match self.page {
            Page::Images if self.images_registries => IconName::PanelsTopLeft,
            page => page_icon(page),
        }
    }
    pub fn page_name(&self) -> &'static str {
        match self.page {
            Page::Rules => "Network Rules",
            Page::Packets => "Packet Capture",
            Page::Images if self.images_registries => "Registries",
            Page::Images => "Local Images",
            Page::Remotes => "Connections",
            _ => self.page.label(),
        }
    }
    pub fn toolbar(&self, window: &Window, cx: &mut Context<Self>) -> impl IntoElement {
        let small = window.bounds().size.width < px(1180.);
        let row = self.inventory.selected();
        let owner = cx.weak_entity();
        let mut tools = div()
            .flex()
            .items_center()
            .flex_1()
            .min_w_0()
            .h_full()
            .px_4()
            .gap_2()
            .child(
                Icon::new(self.page_icon())
                    .size(px(21.))
                    .text_color(cx.theme().muted_foreground),
            )
            .child(
                div()
                    .w(px(if small { 88. } else { 116. }))
                    .min_w_0()
                    .truncate()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(self.page_name()),
            );
        if self.page == Page::Sandboxes {
            tools = tools
                .child(
                    Button::new("sandbox-create")
                        .small()
                        .h(px(27.))
                        .icon(IconName::Plus)
                        .when(!small, |b| b.w(px(66.)).label("New"))
                        .tooltip("New sandbox")
                        .disabled(!self.can_write() || self.form.is_some())
                        .on_click(cx.listener(|this, _, window, cx| {
                            this.open_form(Kind::Create, window, cx)
                        })),
                )
                .child(
                    Button::new("sandbox-start")
                        .ghost()
                        .small()
                        .w(px(32.))
                        .h(px(28.))
                        .icon(Icon::new(IconName::Play).size(px(20.)))
                        .accessibility_label("Start sandbox")
                        .tooltip("Start selected sandbox")
                        .disabled(
                            !self.can_write()
                                || self.form.is_some()
                                || row.is_none_or(|r| r.state != "stopped"),
                        )
                        .on_click(cx.listener(|this, _, window, cx| {
                            this.sandbox_action("start", window, cx)
                        })),
                )
                .child(
                    Button::new("sandbox-stop")
                        .ghost()
                        .small()
                        .w(px(32.))
                        .h(px(28.))
                        .icon(Icon::new(IconName::Square).size(px(20.)))
                        .accessibility_label("Stop sandbox")
                        .tooltip("Stop selected sandbox")
                        .disabled(
                            !self.can_write()
                                || self.form.is_some()
                                || row.is_none_or(|r| r.state != "running"),
                        )
                        .on_click(cx.listener(|this, _, window, cx| {
                            this.sandbox_action("stop", window, cx)
                        })),
                )
                .child(
                    Button::new("sandbox-more")
                        .ghost()
                        .small()
                        .w(px(32.))
                        .h(px(28.))
                        .icon(Icon::new(IconName::Ellipsis).size(px(20.)))
                        .accessibility_label("Sandbox actions")
                        .tooltip("Actions for selected sandbox")
                        .disabled(row.is_none() || self.form.is_some())
                        .dropdown_menu(move |menu, _, cx| {
                            let Some(view) = owner.upgrade() else {
                                return menu;
                            };
                            let desktop = view.read(cx);
                            match desktop.inventory.selected().cloned() {
                                Some(row) => row_actions::sandbox_menu(
                                    owner.clone(),
                                    row,
                                    desktop.target.clone(),
                                    desktop.can_write() && desktop.form.is_none(),
                                    desktop.source_name(),
                                    menu,
                                ),
                                None => menu,
                            }
                        }),
                );
        }
        tools = tools
            .child(
                Button::new("refresh")
                    .ghost()
                    .small()
                    .w(px(32.))
                    .h(px(28.))
                    .icon(Icon::new(IconName::RefreshCw).size(px(19.)))
                    .tooltip(self.fresh_label())
                    .accessibility_label("Refresh")
                    .disabled(
                        self.refreshing || self.writing || self.options.source == Source::Demo,
                    )
                    .on_click(cx.listener(|this, _, _, cx| this.refresh(cx))),
            )
            .child(div().flex_1())
            .child(
                div()
                    .w(px(if small { 142. } else { 268. }))
                    .min_w(px(110.))
                    .child(
                        Input::new(&self.search)
                            .id(if self.page == Page::Sandboxes {
                                "sandbox-search"
                            } else {
                                "dashboard-search"
                            })
                            .small()
                            .prefix(Icon::new(IconName::Search).size(px(15.)))
                            .cleanable(true),
                    ),
            );
        TitleBar::new()
            .h(px(theme::TOOLBAR_HEIGHT))
            .pl_0()
            .bg(cx.theme().title_bar)
            .child(
                div()
                    .w(px(theme::SIDEBAR_WIDTH))
                    .h_full()
                    .flex_shrink_0()
                    .flex()
                    .items_center()
                    .gap_2()
                    .pl(px(if cfg!(target_os = "macos") { 96. } else { 20. }))
                    .child(
                        Icon::default()
                            .data(include_bytes!("../assets/logo.svg"))
                            .size(px(24.))
                            .text_color(rgb(if cx.theme().is_dark() {
                                0xbde878
                            } else {
                                0x537933
                            })),
                    )
                    .child(
                        Button::new("app-menu")
                            .ghost()
                            .small()
                            .label("Gantry")
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_size(px(13.))
                            .tooltip("Application menu")
                            .dropdown_menu(|menu, _, _| {
                                menu.menu("Overview", Box::new(ShowOverview))
                                    .menu("Connections…", Box::new(ShowConnections))
                                    .separator()
                                    .menu("Toggle Inspector", Box::new(ToggleInspector))
                                    .menu("Toggle Activity", Box::new(ToggleActivity))
                                    .menu("Appearance", Box::new(CycleAppearance))
                                    .separator()
                                    .menu("Gantry Manual", Box::new(ShowManual))
                            }),
                    ),
            )
            .child(tools)
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .flex_shrink_0()
                    .w(if self.inspector_open && !small {
                        self.inspector_width
                    } else {
                        px(44.)
                    })
                    .px_3()
                    .when(self.inspector_open && !small, |d| {
                        d.child(
                            div()
                                .text_color(cx.theme().muted_foreground)
                                .child("Inspector"),
                        )
                    })
                    .child(
                        Button::new("inspector-toggle")
                            .ghost()
                            .small()
                            .icon(IconName::PanelRight)
                            .accessibility_label("Toggle inspector")
                            .tooltip("Toggle inspector")
                            .disabled(self.form.is_some())
                            .selected(self.inspector_open)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.inspector_open = !this.inspector_open;
                                cx.notify();
                            })),
                    ),
            )
    }
    pub fn nav_button(
        &self,
        page: Page,
        label: &str,
        icon: IconName,
        selected: bool,
        cx: &mut Context<Self>,
    ) -> Button {
        let mut content = div()
            .flex()
            .items_center()
            .gap_3()
            .w(px(168.))
            .text_size(px(13.))
            .child(
                Icon::new(icon)
                    .size(px(17.))
                    .text_color(cx.theme().muted_foreground),
            )
            .child(div().flex_1().min_w_0().truncate().child(label.to_owned()));
        if page == Page::Sandboxes {
            content = content.child(
                div()
                    .text_size(px(11.))
                    .text_color(cx.theme().muted_foreground)
                    .child(
                        if matches!(self.connection, Connection::Connected(_) | Connection::Demo) {
                            self.inventory.rows().len().to_string()
                        } else {
                            "—".into()
                        },
                    ),
            );
        }
        Button::new(("page-nav", page.index()))
            .ghost()
            .small()
            .h(px(30.))
            .w_full()
            .px_2()
            .selected(selected)
            .when(selected, |b| b.bg(cx.theme().sidebar_accent))
            .accessibility_label(label.to_owned())
            .child(content)
            .disabled(self.form.is_some())
            .on_click(cx.listener(move |this, _, window, cx| {
                if page == Page::Images {
                    this.set_images_registries(false, cx);
                }
                this.switch_page(page, window, cx);
            }))
    }
    pub fn sidebar(&self, cx: &mut Context<Self>) -> Div {
        let connected = matches!(self.connection, Connection::Connected(_));
        let local_selected = matches!(self.options.source, Source::Local(_) | Source::Demo);
        let mut connections =
            div()
                .flex()
                .flex_col()
                .gap_1()
                .child(section("CONNECTIONS", cx))
                .child(
                    Button::new("connection-local")
                        .ghost()
                        .small()
                        .w_full()
                        .h(px(31.))
                        .px_2()
                        .selected(local_selected)
                        .when(local_selected, |b| b.bg(cx.theme().sidebar_accent))
                        .disabled(self.form.is_some() || self.writing)
                        .accessibility_label("This Mac")
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_3()
                                .w(px(168.))
                                .text_size(px(13.))
                                .child(Icon::new(IconName::Monitor).size(px(17.)))
                                .child(div().flex_1().child(
                                    if self.options.source == Source::Demo {
                                        "Demo · This Mac"
                                    } else if cfg!(target_os = "macos") {
                                        "This Mac"
                                    } else {
                                        "This Machine"
                                    },
                                ))
                                .child(div().size(px(6.)).rounded_full().bg(
                                    if local_selected && connected {
                                        cx.theme().success
                                    } else {
                                        cx.theme().muted_foreground
                                    },
                                )),
                        )
                        .on_click(cx.listener(|this, _, window, cx| {
                            if let Some(mut options) = this.local_options.clone() {
                                options.appearance = this.options.appearance;
                                this.switch_source(options, window, cx);
                            }
                        })),
                );
        for (index, profile) in self.profiles.iter().enumerate() {
            let name = profile.name.clone();
            let selected = matches!(&self.options.source,Source::Remote{name:n,..} if n==&name);
            connections = connections.child(
                Button::new(("connection-remote", index))
                    .ghost()
                    .small()
                    .w_full()
                    .h(px(31.))
                    .px_2()
                    .selected(selected)
                    .when(selected, |b| b.bg(cx.theme().sidebar_accent))
                    .disabled(self.form.is_some() || self.writing)
                    .accessibility_label(name.clone())
                    .tooltip(profile.url.clone())
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .w(px(168.))
                            .text_size(px(13.))
                            .child(Icon::new(IconName::Server).size(px(17.)))
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .truncate()
                                    .child(workspace::text(&name)),
                            )
                            .child(div().size(px(6.)).rounded_full().bg(
                                if selected && connected {
                                    cx.theme().success
                                } else {
                                    cx.theme().muted_foreground
                                },
                            )),
                    )
                    .on_click(cx.listener(move |this, _, window, cx| {
                        if let Some(base) = &this.config_dir {
                            let mut options = this.options.clone();
                            options.source = Source::Remote {
                                name: name.clone(),
                                config_dir: base.clone(),
                            };
                            options.auto_start = false;
                            this.switch_source(options, window, cx);
                        }
                    })),
            );
        }
        connections = connections.child(
            Button::new("connection-add")
                .ghost()
                .small()
                .w_full()
                .h(px(30.))
                .px_2()
                .disabled(!self.can_edit_profiles() || self.form.is_some())
                .accessibility_label("Add Connection")
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_3()
                        .w(px(168.))
                        .child(Icon::new(IconName::Plus).size(px(16.)))
                        .child("Add Connection…"),
                )
                .on_click(
                    cx.listener(|this, _, window, cx| this.open_form(Kind::RemoteAdd, window, cx)),
                ),
        );
        let navigation = div()
            .flex()
            .flex_col()
            .gap_0()
            .child(section("WORKSPACE", cx).mt_3())
            .children(
                [
                    Page::Sandboxes,
                    Page::Traffic,
                    Page::Rules,
                    Page::Ports,
                    Page::Packets,
                    Page::Mounts,
                    Page::Secrets,
                    Page::Mcp,
                    Page::Audit,
                ]
                .into_iter()
                .map(|page| {
                    self.nav_button(
                        page,
                        match page {
                            Page::Rules => "Network Rules",
                            Page::Packets => "Packet Capture",
                            _ => page.label(),
                        },
                        page_icon(page),
                        self.page == page,
                        cx,
                    )
                }),
            )
            .child(section("IMAGES", cx).mt_4())
            .child(self.nav_button(
                Page::Images,
                "Local Images",
                IconName::Layers,
                self.page == Page::Images && !self.images_registries,
                cx,
            ))
            .child(
                Button::new("registries-nav")
                    .ghost()
                    .small()
                    .w_full()
                    .h(px(30.))
                    .px_2()
                    .selected(self.page == Page::Images && self.images_registries)
                    .when(self.page == Page::Images && self.images_registries, |b| {
                        b.bg(cx.theme().sidebar_accent)
                    })
                    .disabled(self.form.is_some())
                    .accessibility_label("Registries")
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .w(px(168.))
                            .child(Icon::new(IconName::PanelsTopLeft).size(px(17.)))
                            .child("Registries"),
                    )
                    .on_click(cx.listener(|this, _, window, cx| {
                        this.set_images_registries(true, cx);
                        this.switch_page(Page::Images, window, cx);
                    })),
            );
        div()
            .w(px(theme::SIDEBAR_WIDTH))
            .flex_shrink_0()
            .h_full()
            .flex()
            .flex_col()
            .bg(cx.theme().sidebar)
            .border_r_1()
            .border_color(cx.theme().border)
            .child(
                div()
                    .id("sidebar-region")
                    .test_support()
                    .flex_1()
                    .min_h_0()
                    .child(
                        div()
                            .id("sidebar-scroll")
                            .size_full()
                            .overflow_y_scrollbar()
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .px(px(10.))
                                    .py_3()
                                    .child(connections)
                                    .child(navigation),
                            ),
                    ),
            )
            .child(
                div()
                    .mx_3()
                    .py_2()
                    .border_t_1()
                    .border_color(cx.theme().border)
                    .child(self.nav_button(
                        Page::Remotes,
                        "Manage Connections…",
                        IconName::Settings,
                        self.page == Page::Remotes,
                        cx,
                    ))
                    .child(
                        div().flex().justify_end().child(
                            Button::new("appearance")
                                .ghost()
                                .xsmall()
                                .icon(match self.options.appearance {
                                    Appearance::Dark => IconName::Moon,
                                    Appearance::Light => IconName::Sun,
                                    Appearance::System => IconName::Monitor,
                                })
                                .tooltip("Cycle system, dark, light appearance")
                                .accessibility_label("Appearance")
                                .on_click(
                                    cx.listener(|this, _, window, cx| this.cycle_theme(window, cx)),
                                ),
                        ),
                    ),
            )
    }
    pub fn footer(&self, cx: &App) -> Div {
        let (color, label) = match &self.connection {
            Connection::Connecting => (
                cx.theme().warning,
                format!("Connecting to {}…", self.source_name()),
            ),
            Connection::Connected(v) => (
                cx.theme().success,
                format!(
                    "Connected to {}  ·  Manager API {v}{}",
                    self.source_name(),
                    if self.control_available || self.refreshing {
                        ""
                    } else {
                        " · Read-only: upgrade and restart this manager"
                    }
                ),
            ),
            Connection::Offline(_) => (
                cx.theme().danger,
                format!("{} unavailable · retrying", self.source_name()),
            ),
            Connection::Demo => (
                cx.theme().warning,
                "Demo · sample data only · writes disabled".into(),
            ),
        };
        let running = self
            .inventory
            .rows()
            .iter()
            .filter(|r| r.state == "running")
            .count();
        div()
            .flex()
            .items_center()
            .h(px(theme::STATUS_HEIGHT))
            .flex_shrink_0()
            .px_4()
            .gap_2()
            .bg(cx.theme().status_bar)
            .border_t_1()
            .border_color(cx.theme().border)
            .text_size(px(10.))
            .text_color(cx.theme().muted_foreground)
            .child(div().size(px(5.)).rounded_full().bg(color))
            .child(div().flex_1().min_w_0().truncate().child(label))
            .child(
                if matches!(self.connection, Connection::Connected(_) | Connection::Demo) {
                    format!(
                        "{} sandboxes · {running} running",
                        self.inventory.rows().len()
                    )
                } else {
                    "Inventory unavailable".into()
                },
            )
    }
}
fn section(label: &str, cx: &App) -> Div {
    div()
        .px_2()
        .pt_3()
        .pb_2()
        .text_size(px(10.))
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(cx.theme().muted_foreground)
        .child(label.to_owned())
}
