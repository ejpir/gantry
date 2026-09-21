use crate::{app::*, sandbox_table::status, theme};
use gantry_desktop::{
    forms::Kind,
    inventory::{BootSettings, Filter, memory_label},
    workspace::Page,
};
use gpui_kit::assets::IconName;
use gpui_kit::component::{
    ActiveTheme, Disableable, Icon, Root, Selectable, Sizable,
    button::{Button, ButtonVariants},
    resizable::{h_resizable, resizable_panel},
    scroll::ScrollableElement,
    table::DataTable,
};
use gpui_kit::{
    App, ClipboardItem, Context, Div, FontWeight, InteractiveElement, IntoElement, ParentElement,
    Render, Styled, TestSupportExt, Window, div, prelude::FluentBuilder, px,
};

impl Render for Desktop {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .id("gantry-desktop")
            .relative()
            .key_context("GantryDesktop")
            .track_focus(&self.focus)
            .flex()
            .flex_col()
            .size_full()
            .overflow_hidden()
            .font_family(cx.theme().font_family.clone())
            .text_size(px(13.))
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .on_action(cx.listener(|this, _: &Refresh, _, cx| this.refresh(cx)))
            .on_action(cx.listener(|this, _: &CloseForm, window, cx| {
                if this.form.is_some() {
                    this.close_form(window, cx);
                }
            }))
            .on_action(
                cx.listener(|this, _: &FocusSearch, window, cx| this.focus_search(window, cx)),
            )
            .on_action(cx.listener(|this, _: &FocusInventory, window, cx| {
                this.switch_page(Page::Sandboxes, window, cx);
                this.focus_inventory(window, cx);
            }))
            .on_action(cx.listener(|this, _: &NewSandbox, window, cx| {
                this.open_form(Kind::Create, window, cx)
            }))
            .on_action(cx.listener(|this, _: &EditSandbox, window, cx| {
                if this.page == Page::Sandboxes {
                    this.edit_selected_sandbox(window, cx);
                }
            }))
            .on_action(cx.listener(|this, _: &StartSandbox, window, cx| {
                if this.page == Page::Sandboxes {
                    this.sandbox_action("start", window, cx);
                }
            }))
            .on_action(cx.listener(|this, _: &StopSandbox, window, cx| {
                if this.page == Page::Sandboxes {
                    this.sandbox_action("stop", window, cx);
                }
            }))
            .on_action(cx.listener(|this, _: &DeleteSandbox, window, cx| {
                if this.page == Page::Sandboxes {
                    this.sandbox_action("delete", window, cx);
                }
            }))
            .on_action(cx.listener(|this, _: &ToggleInspector, _, cx| {
                if this.form.is_none() {
                    this.inspector_open = !this.inspector_open;
                    cx.notify();
                }
            }))
            .on_action(cx.listener(|this, _: &ToggleActivity, _, cx| {
                this.activity_open = !this.activity_open;
                cx.notify();
            }))
            .on_action(
                cx.listener(|this, _: &CycleAppearance, window, cx| this.cycle_theme(window, cx)),
            )
            .on_action(cx.listener(|this, _: &ShowConnections, window, cx| {
                this.switch_page(Page::Remotes, window, cx)
            }))
            .on_action(cx.listener(|this, _: &ShowOverview, window, cx| {
                this.switch_page(Page::Overview, window, cx)
            }))
            .on_action(cx.listener(|this, _: &ShowImages, window, cx| {
                this.switch_page(Page::Images, window, cx)
            }))
            .on_action(|_: &ShowManual, _, cx| {
                cx.open_url("https://github.com/ejpir/gantry/tree/main/docs/gantry")
            })
            .on_action(|_: &MinimizeWindow, window, _| window.minimize_window())
            .on_action(|_: &ZoomWindow, window, _| window.zoom_window())
            .on_action(|_: &FullScreen, window, _| window.toggle_fullscreen())
            .child(self.toolbar(window, cx))
            .child(
                div()
                    .flex()
                    .flex_1()
                    .min_h_0()
                    .child(self.sidebar(cx))
                    .child(if self.page == Page::Sandboxes {
                        let inventory = div()
                            .id("inventory-pane")
                            .test_support()
                            .size_full()
                            .flex()
                            .flex_col()
                            .min_h_0()
                            .child(self.inventory_view(cx))
                            .child(self.activity_view(cx));
                        if self.inspector_open {
                            div().flex_1().min_w_0().h_full().child(
                                h_resizable("sandbox-workspace")
                                    .on_resize(cx.listener(
                                        |this,
                                         state: &gpui_kit::Entity<
                                            gpui_kit::component::resizable::ResizableState,
                                        >,
                                         _,
                                         cx| {
                                            if let Some(width) = state.read(cx).sizes().last() {
                                                this.inspector_width = *width;
                                                cx.notify();
                                            }
                                        },
                                    ))
                                    .child(
                                        resizable_panel()
                                            .size_range(px(420.)..px(2400.))
                                            .child(inventory),
                                    )
                                    .child(
                                        resizable_panel()
                                            .size(self.inspector_width)
                                            .size_range(px(280.)..px(520.))
                                            .child(
                                                div()
                                                    .id("inspector-pane")
                                                    .test_support()
                                                    .size_full()
                                                    .child(self.inspector(cx)),
                                            ),
                                    ),
                            )
                        } else {
                            div().flex_1().min_w_0().h_full().child(inventory)
                        }
                    } else {
                        div().flex_1().min_w_0().h_full().child(self.workbench(cx))
                    }),
            )
            .child(self.footer(cx))
            .children(Root::render_notification_layer(window, cx))
            .children(self.row_menu_layer())
            .child(self.form_layer(cx))
    }
}
impl Desktop {
    fn inventory_view(&self, cx: &mut Context<Self>) -> Div {
        let visible = self.inventory.visible().len();
        let count = match self.connection {
            Connection::Connecting => "Loading…".into(),
            Connection::Offline(_) => "Unavailable".into(),
            _ => format!("{visible} sandboxes"),
        };
        let running = self
            .inventory
            .rows()
            .iter()
            .filter(|s| s.state == "running")
            .count();
        let stopped = self
            .inventory
            .rows()
            .iter()
            .filter(|s| s.state == "stopped")
            .count();
        let filters = div()
            .flex()
            .gap_0()
            .rounded(px(5.))
            .p(px(2.))
            .bg(cx.theme().background)
            .border_1()
            .border_color(cx.theme().border)
            .children(
                [
                    (Filter::All, self.inventory.rows().len()),
                    (Filter::Running, running),
                    (Filter::Stopped, stopped),
                ]
                .into_iter()
                .enumerate()
                .map(|(index, (filter, n))| {
                    Button::new(("filter", index))
                        .ghost()
                        .xsmall()
                        .h(px(21.))
                        .px_3()
                        .label(format!("{}  {n}", filter.label()))
                        .selected(self.inventory.filter == filter)
                        .when(self.inventory.filter == filter, |b| {
                            b.bg(theme::selected_control(cx))
                        })
                        .disabled(self.form.is_some())
                        .on_click(cx.listener(move |this, _, _, cx| this.set_filter(filter, cx)))
                }),
            );
        let controls = div()
            .flex()
            .items_center()
            .h(px(43.))
            .flex_shrink_0()
            .px(px(20.))
            .bg(cx.theme().secondary)
            .child(filters)
            .child(div().flex_1())
            .child(
                div()
                    .text_size(px(11.))
                    .text_color(cx.theme().muted_foreground)
                    .child(count),
            );
        let content = match &self.connection {
            Connection::Connecting => empty_state(
                IconName::RefreshCw,
                "Connecting to Gantry",
                "Connecting to the selected manager…",
                cx,
            ),
            Connection::Offline(message) => {
                empty_state(IconName::CircleAlert, "Manager unavailable", message, cx).child(
                    div().mt_2().child(
                        Button::new("retry-connection")
                            .small()
                            .label("Retry connection")
                            .disabled(self.refreshing)
                            .on_click(cx.listener(|this, _, _, cx| this.refresh(cx))),
                    ),
                )
            }
            _ if self.inventory.rows().is_empty() => empty_state(
                IconName::Box,
                "No sandboxes",
                "Use New to create a sandbox, or pull an image from Local Images.",
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
                .capture_any_mouse_down(
                    cx.listener(|this, event, window, cx| this.open_row_menu(event, window, cx)),
                )
                .child(
                    DataTable::new(&self.table)
                        .bordered(false)
                        .stripe(false)
                        .with_size(px(34.)),
                ),
        };
        div()
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .min_w_0()
            .child(controls)
            .child(div().flex_1().min_h_0().overflow_hidden().child(content))
    }
    fn inspector(&self, cx: &mut Context<Self>) -> Div {
        let panel = div()
            .flex()
            .flex_col()
            .size_full()
            .min_h_0()
            .bg(cx.theme().secondary)
            .border_l_1()
            .border_color(cx.theme().border);
        if self.inline_form() {
            return panel.child(self.form_content(true, cx));
        }
        let Some(row) = self.inventory.selected() else {
            return panel.child(empty_state(
                IconName::PanelRight,
                "Inspector",
                "Select a sandbox to inspect its running and saved configuration.",
                cx,
            ));
        };
        let image = row.image_label().to_owned();
        let mut details = div().flex().flex_col().gap(px(13.));
        if !self.inspector_settings {
            details = details
                .child(allocation(
                    "RUNNING NOW",
                    if row.state == "running" {
                        row.active.as_ref()
                    } else {
                        None
                    },
                    if row.state == "running" {
                        "Not reported by the manager"
                    } else {
                        "Not running"
                    },
                    cx,
                ))
                .child(separator(cx));
        }
        details = details
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(eyebrow("NEXT BOOT", cx))
                    .child(
                        Button::new("sandbox-edit")
                            .ghost()
                            .xsmall()
                            .label("Edit…")
                            .text_color(cx.theme().primary)
                            .disabled(!self.can_write())
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.edit_selected_sandbox(window, cx)
                            })),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(property("CPU", &format!("{} vCPU", row.desired.cpus), cx))
                    .child(property(
                        "Memory",
                        &memory_label(row.desired.memory_mib),
                        cx,
                    )),
            )
            .when(row.restart_required, |d| {
                d.child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_2()
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .text_size(px(12.))
                                .text_color(cx.theme().warning)
                                .child(Icon::new(IconName::TriangleAlert).size(px(15.)))
                                .child("Restart required"),
                        )
                        .child(
                            div()
                                .text_size(px(11.))
                                .text_color(cx.theme().muted_foreground)
                                .child("Running allocation is unchanged."),
                        ),
                )
            })
            .child(separator(cx))
            .child(eyebrow("IMAGE", cx))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .truncate()
                            .font_family(cx.theme().mono_font_family.clone())
                            .text_size(px(12.))
                            .child(image.clone()),
                    )
                    .child(
                        Button::new("copy-image")
                            .ghost()
                            .xsmall()
                            .icon(IconName::Copy)
                            .accessibility_label("Copy image reference")
                            .tooltip("Copy image reference")
                            .on_click(move |_, _, cx| {
                                cx.write_to_clipboard(ClipboardItem::new_string(image.clone()))
                            }),
                    ),
            )
            .child(separator(cx))
            .child(eyebrow("SAVED CONFIGURATION", cx))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(property(
                        "Writable layer",
                        if row.writable { "On" } else { "Off" },
                        cx,
                    ))
                    .child(property(
                        "Process isolation",
                        match row.desired.process_isolation.as_str() {
                            "auto" => "Auto",
                            "required" => "Required",
                            "off" => "Off",
                            value => value,
                        },
                        cx,
                    ))
                    .child(property(
                        "SSH",
                        self.host
                            .snapshot
                            .sandboxes
                            .iter()
                            .find(|s| s.name == row.name)
                            .map(|s| if s.ssh { "Enabled" } else { "Off" })
                            .unwrap_or("Not reported"),
                        cx,
                    ))
                    .child(property(
                        "Dev Containers",
                        if row.desired.dev_containers {
                            "On"
                        } else {
                            "Off"
                        },
                        cx,
                    )),
            )
            .when(self.inspector_settings, |d| {
                d.child(
                    Button::new("sandbox-delete")
                        .small()
                        .label("Delete sandbox…")
                        .text_color(cx.theme().danger)
                        .disabled(!self.can_write() || row.state != "stopped")
                        .on_click(cx.listener(|this, _, window, cx| {
                            this.sandbox_action("delete", window, cx)
                        })),
                )
            });
        let header = div()
            .flex()
            .flex_col()
            .gap(px(8.))
            .px(px(20.))
            .pt(px(20.))
            .pb(px(14.))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        Icon::new(IconName::Box)
                            .size(px(24.))
                            .text_color(cx.theme().muted_foreground),
                    )
                    .child(
                        div()
                            .min_w_0()
                            .truncate()
                            .text_size(px(20.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(row.name.clone()),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(status(row, cx))
                    .child(
                        div()
                            .text_size(px(11.))
                            .text_color(cx.theme().muted_foreground)
                            .child(self.source_name()),
                    ),
            )
            .child(
                div()
                    .flex()
                    .p(px(2.))
                    .bg(cx.theme().background)
                    .border_1()
                    .border_color(cx.theme().border)
                    .rounded(px(5.))
                    .children(
                        [(false, "Overview"), (true, "Settings")]
                            .into_iter()
                            .enumerate()
                            .map(|(index, (settings, label))| {
                                Button::new(("inspector-tab", index))
                                    .ghost()
                                    .small()
                                    .h(px(22.))
                                    .flex_1()
                                    .label(label)
                                    .selected(self.inspector_settings == settings)
                                    .when(self.inspector_settings == settings, |b| {
                                        b.bg(theme::selected_control(cx))
                                    })
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.inspector_settings = settings;
                                        cx.notify();
                                    }))
                            }),
                    ),
            );
        panel
            .child(header)
            .child(
                div()
                    .id("inspector-scroll")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .child(div().px(px(20.)).py(px(8.)).child(details)),
            )
            .child(
                div()
                    .px(px(20.))
                    .py(px(16.))
                    .text_size(px(10.))
                    .text_color(cx.theme().muted_foreground)
                    .truncate()
                    .child(format!("Inspecting {} on {}", row.name, self.source_name())),
            )
    }
}
pub fn eyebrow(label: &str, cx: &App) -> Div {
    div()
        .text_size(px(10.))
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(cx.theme().muted_foreground)
        .child(label.to_owned())
}
fn separator(cx: &App) -> Div {
    div().h(px(1.)).w_full().bg(cx.theme().border)
}
pub fn empty_state(icon: IconName, title: &str, description: &str, cx: &App) -> Div {
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
                .size(px(28.))
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
                .text_size(px(12.))
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
fn allocation(label: &str, settings: Option<&BootSettings>, unknown: &str, cx: &App) -> Div {
    div()
        .flex()
        .flex_col()
        .gap(px(10.))
        .child(eyebrow(label, cx))
        .child(property(
            "CPU",
            &settings
                .map(|s| format!("{} vCPU", s.cpus))
                .unwrap_or_else(|| "—".into()),
            cx,
        ))
        .child(property(
            "Memory",
            &settings
                .map(|s| memory_label(s.memory_mib))
                .unwrap_or_else(|| "—".into()),
            cx,
        ))
        .when(settings.is_none(), |d| {
            d.child(
                div()
                    .text_size(px(11.))
                    .text_color(cx.theme().muted_foreground)
                    .child(unknown.to_owned()),
            )
        })
}
