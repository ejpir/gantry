use gantry_desktop::{
    inventory::{BootSettings, Filter, memory_label},
    options::{Appearance, Source},
};
use gpui_kit::assets::IconName;
use gpui_kit::component::{
    ActiveTheme, Disableable, Icon, Root, Selectable, Sizable, WindowExt,
    button::{Button, ButtonVariants},
    input::Input,
    resizable::{h_resizable, resizable_panel},
    scroll::ScrollableElement,
    table::DataTable,
};
use gpui_kit::{
    App, ClipboardItem, Context, Div, FontWeight, InteractiveElement, IntoElement, ParentElement,
    Render, Styled, TestSupportExt, Window, div, prelude::FluentBuilder, px,
};

use crate::{
    app::{Connection, Desktop, FocusInventory, FocusSearch, Refresh},
    sandbox_table::status,
};

impl Render for Desktop {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .id("gantry-desktop")
            .key_context("GantryDesktop")
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .overflow_hidden()
            .font_family(cx.theme().font_family.clone())
            .text_size(px(14.))
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .on_action(cx.listener(|this, _: &Refresh, _, cx| this.refresh(cx)))
            .on_action(
                cx.listener(|this, _: &FocusSearch, window, cx| this.focus_search(window, cx)),
            )
            .on_action(
                cx.listener(|this, _: &FocusInventory, window, cx| {
                    this.focus_inventory(window, cx)
                }),
            )
            .child(self.header(cx))
            .child(
                div()
                    .flex()
                    .flex_1()
                    .min_h_0()
                    .child(self.sidebar(cx))
                    .child(
                        div().flex_1().min_w_0().h_full().child(
                            h_resizable("sandbox-workspace")
                                .child(
                                    resizable_panel().size_range(px(420.)..px(2400.)).child(
                                        div()
                                            .id("inventory-pane")
                                            .test_support()
                                            .size_full()
                                            .child(self.inventory_view(cx)),
                                    ),
                                )
                                .child(
                                    resizable_panel()
                                        .size(px(330.))
                                        .size_range(px(280.)..px(520.))
                                        .child(
                                            div()
                                                .id("inspector-pane")
                                                .test_support()
                                                .size_full()
                                                .child(self.inspector(cx)),
                                        ),
                                ),
                        ),
                    ),
            )
            .child(self.footer(cx))
            .children(Root::render_notification_layer(window, cx))
    }
}

impl Desktop {
    fn header(&self, cx: &mut Context<Self>) -> Div {
        let theme_icon = match self.options.appearance {
            Appearance::System => IconName::Monitor,
            Appearance::Dark => IconName::Moon,
            Appearance::Light => IconName::Sun,
        };
        div()
            .flex()
            .items_center()
            .h(px(64.))
            .flex_shrink_0()
            .border_b_1()
            .border_color(cx.theme().border)
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .w(px(184.))
                    .px_5()
                    .flex_shrink_0()
                    .child(
                        Icon::default()
                            .data(include_bytes!("../assets/logo.svg"))
                            .size(px(28.))
                            .text_color(cx.theme().primary),
                    )
                    .child(
                        div()
                            .flex()
                            .text_size(px(24.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .child("gantry")
                            .child(div().text_color(cx.theme().primary).child(".")),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .px_6()
                    .text_size(px(13.))
                    .child(
                        div()
                            .text_color(cx.theme().muted_foreground)
                            .child("Workspace"),
                    )
                    .child(
                        Icon::new(IconName::ChevronRight)
                            .xsmall()
                            .text_color(cx.theme().muted_foreground),
                    )
                    .child("Sandboxes"),
            )
            .child(div().flex_1())
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .pr_4()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .mr_3()
                            .text_size(px(12.))
                            .child(
                                Icon::new(
                                    if matches!(self.options.source, Source::Remote { .. }) {
                                        IconName::Server
                                    } else {
                                        IconName::Monitor
                                    },
                                )
                                .small()
                                .text_color(cx.theme().muted_foreground),
                            )
                            .child(self.options.source.label()),
                    )
                    .child(
                        Button::new("appearance")
                            .ghost()
                            .small()
                            .icon(theme_icon)
                            .label(self.options.appearance.label())
                            .tooltip("Cycle appearance: system, dark, light")
                            .on_click(
                                cx.listener(|this, _, window, cx| this.cycle_theme(window, cx)),
                            ),
                    )
                    .child(
                        Button::new("manual")
                            .ghost()
                            .small()
                            .icon(IconName::ExternalLink)
                            .accessibility_label("Open Gantry manual")
                            .tooltip("Open Gantry manual")
                            .on_click(|_, _, cx| {
                                cx.open_url("https://github.com/ejpir/gantry/tree/main/docs/gantry")
                            }),
                    ),
            )
    }

    fn sidebar(&self, cx: &mut Context<Self>) -> Div {
        let running = self
            .inventory
            .rows()
            .iter()
            .filter(|row| row.state == "running")
            .count();
        let stopped = self
            .inventory
            .rows()
            .iter()
            .filter(|row| row.state == "stopped")
            .count();
        let known = matches!(self.connection, Connection::Connected(_) | Connection::Demo);
        div()
            .flex()
            .flex_col()
            .w(px(184.))
            .flex_shrink_0()
            .p_3()
            .gap_2()
            .bg(cx.theme().sidebar)
            .border_r_1()
            .border_color(cx.theme().border)
            .child(eyebrow("WORKSPACE", cx).px_2().pt_3().pb_2())
            .child(
                Button::new("sandboxes-nav")
                    .ghost()
                    .selected(true)
                    .icon(IconName::Box)
                    .label("Sandboxes")
                    .w_full()
                    .justify_start()
                    .on_click(cx.listener(|this, _, window, cx| {
                        this.set_filter(Filter::All, cx);
                        this.focus_inventory(window, cx);
                    })),
            )
            .child(
                eyebrow(
                    match self.options.source {
                        Source::Demo => "DEMO INVENTORY",
                        Source::Local(_) => "THIS MACHINE",
                        Source::Remote { .. } => "REMOTE HOST",
                    },
                    cx,
                )
                .px_2()
                .pt_6()
                .pb_2(),
            )
            .child(sidebar_count("Running", known.then_some(running), cx))
            .child(sidebar_count("Stopped", known.then_some(stopped), cx))
            .child(div().flex_1())
            .child(
                div()
                    .flex()
                    .flex_col()
                    .p_2()
                    .gap_2()
                    .text_size(px(12.))
                    .text_color(cx.theme().muted_foreground)
                    .child(Icon::new(IconName::ShieldCheck).small())
                    .child(
                        div()
                            .text_color(cx.theme().foreground)
                            .child("Read-only preview"),
                    )
                    .child(
                        "Your sandboxes stay in Gantry’s hands. This window only inspects them.",
                    ),
            )
    }

    fn inventory_view(&self, cx: &mut Context<Self>) -> Div {
        let visible = self.inventory.visible().len();
        let count = match self.connection {
            Connection::Connecting => "Loading…".into(),
            Connection::Offline(_) => "Unavailable".into(),
            _ => format!("{visible} of {}", self.inventory.rows().len()),
        };
        let mut view = div()
            .flex()
            .flex_col()
            .size_full()
            .min_w_0()
            .min_h_0()
            .p_6()
            .gap_4()
            .child(
                div()
                    .flex()
                    .items_start()
                    .justify_between()
                    .gap_4()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .text_size(px(24.))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child("Sandboxes"),
                            )
                            .child(
                                div()
                                    .text_size(px(13.))
                                    .text_color(cx.theme().muted_foreground)
                                    .child("Your containers. Their own kernel."),
                            ),
                    )
                    .child(
                        Button::new("refresh")
                            .small()
                            .icon(IconName::RefreshCw)
                            .label(if self.refreshing {
                                "Refreshing…"
                            } else {
                                "Refresh"
                            })
                            .disabled(self.refreshing || self.options.source == Source::Demo)
                            .tooltip("Refresh inventory and retry the selected connection")
                            .on_click(cx.listener(|this, _, _, cx| this.refresh(cx))),
                    ),
            )
            .child(
                Input::new(&self.search)
                    .id("sandbox-search")
                    .prefix(Icon::new(IconName::Search).small())
                    .cleanable(true),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_1()
                    .children(
                        [Filter::All, Filter::Running, Filter::Stopped]
                            .into_iter()
                            .enumerate()
                            .map(|(index, filter)| {
                                Button::new(("filter", index))
                                    .ghost()
                                    .small()
                                    .label(filter.label())
                                    .selected(self.inventory.filter == filter)
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.set_filter(filter, cx)
                                    }))
                            }),
                    )
                    .child(div().flex_1())
                    .child(
                        div()
                            .text_size(px(12.))
                            .text_color(cx.theme().muted_foreground)
                            .child(count),
                    ),
            );
        if self.options.source == Source::Demo {
            view = view.child(
                div()
                    .px_3()
                    .py_2()
                    .rounded(cx.theme().radius)
                    .bg(cx.theme().accent)
                    .text_size(px(12.))
                    .child(
                        "Demo data · No manager is connected. Nothing here changes your machine.",
                    ),
            );
        }
        let connection_help = match &self.options.source {
            Source::Local(_) if self.options.auto_start => {
                "Refresh retries local startup. Existing endpoints and saved organization governance are never replaced."
            }
            Source::Local(_) => {
                "This socket is connect-only. Start its manager explicitly, or use the default local connection for automatic startup."
            }
            Source::Remote { .. } => {
                "Check this profile with gantry remote test. Verify its credentials and TLS trust. Remote failures never fall back to local execution."
            }
            Source::Demo => "Demo mode does not connect to a manager.",
        };
        let content = match &self.connection {
            Connection::Connecting => empty_state(
                IconName::RefreshCw,
                "Connecting to Gantry",
                if self.options.auto_start {
                    "Connecting to the private local API; starting its manager if needed…"
                } else {
                    "Connecting to the selected manager…"
                },
                cx,
            ),
            Connection::Offline(message) => {
                empty_state(IconName::CircleAlert, "Manager unavailable", message, cx).child(
                    div()
                        .max_w(px(420.))
                        .mt_2()
                        .text_size(px(12.))
                        .text_color(cx.theme().muted_foreground)
                        .child(connection_help),
                )
            }
            _ if self.inventory.rows().is_empty() => empty_state(
                IconName::Box,
                "A little room to build",
                "No sandboxes on this manager yet. Create one with the CLI or open gantry tui; it will appear here automatically.",
                cx,
            ),
            _ if visible == 0 => empty_state(
                IconName::Search,
                "No matching sandboxes",
                "Try another name or image, or change the status filter.",
                cx,
            ),
            _ => div()
                .size_full()
                .child(DataTable::new(&self.table).bordered(false)),
        };
        view.child(
            div()
                .flex_1()
                .min_h_0()
                .overflow_hidden()
                .border_1()
                .border_color(cx.theme().border)
                .rounded(cx.theme().radius)
                .child(content),
        )
        .child(
            div()
                .text_size(px(12.))
                .text_color(cx.theme().muted_foreground)
                .child("↑ ↓  Inspect rows     /  Search     Enter  Return to list"),
        )
    }

    fn inspector(&self, cx: &mut Context<Self>) -> Div {
        let panel = div()
            .flex()
            .flex_col()
            .size_full()
            .min_h_0()
            .bg(cx.theme().sidebar)
            .border_l_1()
            .border_color(cx.theme().border);
        let Some(row) = self.inventory.selected() else {
            return panel.child(empty_state(
                IconName::PanelLeft,
                "Sandbox inspector",
                "Select a sandbox to see its image, allocation, and saved configuration.",
                cx,
            ));
        };
        let image = row.image_label().to_owned();
        let mut details = div()
            .id("inspector-scroll")
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .overflow_y_scrollbar()
            .p_5()
            .gap_6()
            .child(allocation(
                row.resource_label(),
                row.displayed_resources(),
                cx,
            ))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(eyebrow("IMAGE", cx))
                    .child(
                        div()
                            .font_family(cx.theme().mono_font_family.clone())
                            .text_size(px(12.))
                            .truncate()
                            .child(image.clone()),
                    )
                    .child(
                        Button::new("copy-image")
                            .ghost()
                            .small()
                            .icon(IconName::Copy)
                            .label("Copy reference")
                            .on_click(move |_, window, cx| {
                                cx.write_to_clipboard(ClipboardItem::new_string(image.clone()));
                                window.push_notification("Image reference copied", cx);
                            }),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(eyebrow("CONFIGURATION", cx))
                    .child(property(
                        "Writable layer",
                        if row.writable { "Enabled" } else { "Read only" },
                        cx,
                    ))
                    .child(property(
                        "Isolation mode",
                        row.displayed_resources()
                            .map(|settings| settings.process_isolation.as_str())
                            .unwrap_or("Not reported"),
                        cx,
                    ))
                    .child(property(
                        "Dev Containers",
                        row.displayed_resources()
                            .map(|settings| {
                                if settings.dev_containers {
                                    "Enabled"
                                } else {
                                    "Disabled"
                                }
                            })
                            .unwrap_or("Not reported"),
                        cx,
                    ))
                    .when(row.pid != 0, |this| {
                        this.child(property("Host PID", &row.pid.to_string(), cx))
                    }),
            );
        if row.restart_required {
            details = details.child(div().flex().flex_col().gap_3().p_3().rounded(cx.theme().radius)
                .border_1().border_color(cx.theme().warning.opacity(0.4))
                .child(div().flex().items_center().gap_2().text_color(cx.theme().warning).text_size(px(12.))
                    .child(Icon::new(IconName::CircleAlert).small()).child("Restart required"))
                .child(allocation("Saved for next boot", Some(&row.desired), cx))
                .when(row.active.as_ref().map(|active| active.process_isolation.as_str()) != Some(row.desired.process_isolation.as_str()), |this|
                    this.child(property("Isolation mode", &row.desired.process_isolation, cx)))
                .when(row.active.as_ref().map(|active| active.dev_containers) != Some(row.desired.dev_containers), |this|
                    this.child(property("Dev Containers", if row.desired.dev_containers { "Enabled" } else { "Disabled" }, cx)))
                .child(div().text_size(px(12.)).text_color(cx.theme().muted_foreground)
                    .child("Saved settings differ from the running VM. Gantry will use them on its next start.")));
        }
        panel
            .child(
                div()
                    .flex()
                    .flex_col()
                    .p_5()
                    .gap_3()
                    .border_b_1()
                    .border_color(cx.theme().border)
                    .child(eyebrow("SANDBOX INSPECTOR", cx))
                    .child(
                        div()
                            .text_size(px(22.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .truncate()
                            .child(row.name.clone()),
                    )
                    .child(status(row, cx)),
            )
            .child(details)
    }

    fn footer(&self, cx: &App) -> Div {
        let (color, label) = match &self.connection {
            Connection::Connecting => (cx.theme().warning, "Connecting to manager".to_owned()),
            Connection::Connected(version) => {
                (cx.theme().success, format!("Connected · {version}"))
            }
            Connection::Offline(_) => (
                cx.theme().danger,
                "Manager unavailable · retrying".to_owned(),
            ),
            Connection::Demo => (cx.theme().warning, "Demo · sample data only".to_owned()),
        };
        let source = self.options.source.description();
        div()
            .flex()
            .items_center()
            .h(px(34.))
            .flex_shrink_0()
            .px_4()
            .gap_3()
            .border_t_1()
            .border_color(cx.theme().border)
            .bg(cx.theme().sidebar)
            .text_size(px(11.))
            .text_color(cx.theme().muted_foreground)
            .child(div().size(px(6.)).rounded_full().bg(color))
            .child(label)
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .truncate()
                    .font_family(cx.theme().mono_font_family.clone())
                    .child(source),
            )
            .when(self.last_updated.is_some(), |this| {
                this.child("Syncs every 3s")
            })
            .child("Desktop preview 0.1")
    }
}

fn eyebrow(label: &str, cx: &App) -> Div {
    div()
        .text_size(px(10.))
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(cx.theme().muted_foreground)
        .child(label.to_owned())
}

fn sidebar_count(label: &str, count: Option<usize>, cx: &App) -> Div {
    div()
        .flex()
        .items_center()
        .justify_between()
        .px_2()
        .py_1()
        .text_size(px(12.))
        .text_color(cx.theme().muted_foreground)
        .child(label.to_owned())
        .child(
            count
                .map(|count| count.to_string())
                .unwrap_or_else(|| "—".into()),
        )
}

fn empty_state(icon: IconName, title: &str, description: &str, cx: &App) -> Div {
    div()
        .flex()
        .flex_col()
        .size_full()
        .items_center()
        .justify_center()
        .p_6()
        .gap_3()
        .text_center()
        .child(
            Icon::new(icon)
                .size(px(32.))
                .text_color(cx.theme().muted_foreground),
        )
        .child(
            div()
                .text_size(px(16.))
                .font_weight(FontWeight::MEDIUM)
                .child(title.to_owned()),
        )
        .child(
            div()
                .max_w(px(420.))
                .text_size(px(13.))
                .text_color(cx.theme().muted_foreground)
                .child(description.to_owned()),
        )
}

fn property(label: &str, value: &str, cx: &App) -> Div {
    div()
        .flex()
        .w_full()
        .items_center()
        .gap_3()
        .text_size(px(12.))
        .child(
            div()
                .flex_shrink_0()
                .text_color(cx.theme().muted_foreground)
                .child(label.to_owned()),
        )
        .child(
            div()
                .flex_1()
                .min_w_0()
                .text_right()
                .truncate()
                .child(value.to_owned()),
        )
}

fn allocation(label: &str, settings: Option<&BootSettings>, cx: &App) -> Div {
    let cpu = settings
        .map(|settings| settings.cpus.to_string())
        .unwrap_or_else(|| "—".into());
    let memory = settings
        .map(|settings| memory_label(settings.memory_mib))
        .unwrap_or_else(|| "—".into());
    div()
        .flex()
        .flex_col()
        .gap_3()
        .child(eyebrow(label, cx))
        .child(
            div()
                .flex()
                .gap_6()
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .flex_1()
                        .child(
                            div()
                                .text_size(px(22.))
                                .font_weight(FontWeight::MEDIUM)
                                .child(cpu),
                        )
                        .child(
                            div()
                                .text_size(px(12.))
                                .text_color(cx.theme().muted_foreground)
                                .child("vCPU"),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .flex_1()
                        .child(
                            div()
                                .text_size(px(22.))
                                .font_weight(FontWeight::MEDIUM)
                                .child(memory),
                        )
                        .child(
                            div()
                                .text_size(px(12.))
                                .text_color(cx.theme().muted_foreground)
                                .child("Memory"),
                        ),
                ),
        )
        .when(settings.is_none(), |this| {
            this.child(
                div()
                    .text_size(px(12.))
                    .text_color(cx.theme().muted_foreground)
                    .child("The manager has not reported the active allocation."),
            )
        })
}
