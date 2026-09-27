use crate::app::{Connection, Desktop};
use crate::theme;
use gantry_desktop::{
    commands::Command,
    dashboard_wire::{
        ActionRequest, MCPRemoteRequest, MCPServer, Mount, PacketRequest, RuleRequest,
        ShareRequest, Traffic,
    },
    forms::Kind,
    options::Source,
    summary::RuleOrigin,
    workspace::{self, Page, Record},
};
use gpui_kit::component::{
    ActiveTheme, Disableable, Selectable, Sizable,
    button::{Button, ButtonVariants},
    scroll::ScrollableElement,
    table::DataTable,
};
use gpui_kit::{
    Context, Div, InteractiveElement, IntoElement, ParentElement, Styled, TestSupportExt, div,
    prelude::FluentBuilder, px,
};

impl Desktop {
    pub(crate) fn form_button(
        &self,
        id: &'static str,
        label: &'static str,
        kind: Kind,
        cx: &mut Context<Self>,
    ) -> Button {
        let local = matches!(kind, Kind::RemoteAdd | Kind::RemoteRemove(_));
        Button::new(id)
            .small()
            .label(label)
            .disabled(if local {
                !self.can_edit_profiles()
            } else {
                !self.can_write()
            })
            .on_click(
                cx.listener(move |this, _, window, cx| this.open_form(kind.clone(), window, cx)),
            )
    }
    /// Pre-filled rule form for one observed flow. DNS flows are allowed by
    /// name and cannot be denied here (the resolver must keep working).
    pub fn traffic_rule_button(
        &self,
        id: &'static str,
        label: &'static str,
        row: &Traffic,
        action: &str,
        cx: &mut Context<Self>,
    ) -> Button {
        let dns = row.protocol.eq_ignore_ascii_case("dns");
        let request = RuleRequest {
            sandbox: row.sandbox.clone(),
            action: action.into(),
            target: if dns {
                row.host.clone()
            } else {
                row.address.clone()
            },
            proto: if ["tcp", "udp", "icmp", "dns"].contains(&row.protocol.as_str()) {
                row.protocol.clone()
            } else {
                "any".into()
            },
            ports: if !dns && row.port != 0 {
                row.port.to_string()
            } else {
                String::new()
            },
        };
        self.form_button(id, label, Kind::Rule(Some(request)), cx)
            .disabled(!self.can_write() || (dns && action == "deny"))
    }
    fn segment_control(&self, page: Page, cx: &mut Context<Self>) -> Div {
        let rows = self.page_rows(page);
        let selected = self.pages[page.index()].segment;
        let registries = page == Page::Images && self.images_registries;
        let labels = if registries {
            workspace::REGISTRY_SEGMENTS
        } else {
            page.segments()
        };
        div()
            .flex()
            .p(px(2.))
            .rounded(px(5.))
            .bg(cx.theme().background)
            .border_1()
            .border_color(cx.theme().border)
            .children(labels.iter().enumerate().map(|(index, label)| {
                let count = rows
                    .iter()
                    .filter(|r| {
                        page != Page::Images
                            || matches!(r.record, Record::Registry(_)) == registries
                    })
                    .filter(|r| workspace::segment_matches(page, index, &r.record))
                    .count();
                Button::new(("segment", index))
                    .ghost()
                    .xsmall()
                    .h(px(21.))
                    .px_3()
                    .label(format!("{label}  {count}"))
                    .selected(selected == index)
                    .when(selected == index, |b| b.bg(theme::selected_control(cx)))
                    .on_click(cx.listener(move |this, _, _, cx| this.set_segment(index, cx)))
            }))
    }
    pub fn workbench(&self, cx: &mut Context<Self>) -> Div {
        let page = self.page;
        let state = &self.pages[page.index()];
        let selected = self.selected_record(cx);
        let mut toolbar = div()
            .flex()
            .items_center()
            .flex_wrap()
            .gap_2()
            .px_4()
            .py_2()
            .min_h(px(43.))
            .bg(cx.theme().secondary);
        if !page.segments().is_empty() {
            toolbar = toolbar.child(self.segment_control(page, cx));
        }
        // Redesigned screens carry per-record actions in the inspector.
        let record_actions = !(self.inspector_open
            && matches!(
                page,
                Page::Rules | Page::Ports | Page::Mounts | Page::Secrets | Page::Mcp | Page::Images
            ));
        match page {
            Page::Overview => {
                toolbar = toolbar.child(self.form_button(
                    "overview-create",
                    "Create sandbox",
                    Kind::Create,
                    cx,
                ))
            }
            Page::Rules => {
                toolbar = toolbar
                    .child(self.form_button("rule-add", "Add rule", Kind::Rule(None), cx))
                    .child(self.form_button(
                        "policy-edit",
                        "Network policy",
                        Kind::NetworkPolicy,
                        cx,
                    ))
            }
            Page::Traffic => {
                // With the inspector open, these actions live beside the flow.
                if let Some(Record::Traffic(row)) =
                    selected.as_ref().filter(|_| !self.inspector_open)
                {
                    for (id, action) in [("traffic-allow", "allow"), ("traffic-deny", "deny")] {
                        toolbar = toolbar.child(self.traffic_rule_button(
                            id,
                            if action == "allow" {
                                "Allow destination"
                            } else {
                                "Deny destination"
                            },
                            row,
                            action,
                            cx,
                        ));
                    }
                }
            }
            Page::Ports => {
                toolbar =
                    toolbar.child(self.form_button("port-add", "Publish port", Kind::Port, cx))
            }
            Page::Mounts => {
                toolbar = toolbar.child(self.form_button(
                    "mount-add",
                    "Add mount",
                    Kind::Share(None),
                    cx,
                ));
                if let Some(Record::Mount(r)) = selected.as_ref().filter(|_| record_actions) {
                    toolbar = toolbar.child(self.form_button(
                        "mount-edit",
                        "Edit mount",
                        mount_edit(r),
                        cx,
                    ));
                }
            }
            Page::Secrets => {
                toolbar = toolbar.child(self.form_button(
                    "secret-add",
                    "Add live secret",
                    Kind::Secret,
                    cx,
                ))
            }
            Page::Mcp => {
                toolbar = toolbar
                    .child(self.form_button("mcp-add", "Add remote server", Kind::Mcp(None), cx))
                    .child(self.form_button(
                        "mcp-filesystem",
                        "Filesystem server",
                        Kind::Filesystem,
                        cx,
                    ));
                if let Some(Record::Mcp(r)) = selected.as_ref().filter(|_| record_actions)
                    && let Some(kind) = mcp_edit(r)
                {
                    toolbar = toolbar.child(self.form_button("mcp-edit", "Edit server", kind, cx));
                }
            }
            Page::Images => {
                toolbar = toolbar
                    .child(self.form_button("image-pull", "Pull image", Kind::Pull, cx))
                    .child(self.form_button(
                        "registry-add",
                        "Registry login",
                        Kind::Registry(None),
                        cx,
                    ))
                    .child(self.form_button(
                        "image-prune",
                        "Prune unused",
                        Kind::Confirm(Command::Dashboard(Box::new(ActionRequest {
                            action: "prune-images".into(),
                            ..Default::default()
                        }))),
                        cx,
                    ))
            }
            Page::Packets => {
                toolbar = toolbar.child(self.form_button(
                    "capture-start",
                    "Start capture",
                    Kind::Capture,
                    cx,
                ));
                if let Some(name) = &self.packet_sandbox {
                    // Frames arrive live; pausing holds the list still.
                    toolbar = toolbar.child(
                        Button::new("capture-pause")
                            .small()
                            .label(if self.packets_paused {
                                "Resume"
                            } else {
                                "Pause"
                            })
                            .disabled(!self.packets.active)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.packets_paused = !this.packets_paused;
                                this.read_packets(cx);
                                cx.notify();
                            })),
                    );
                    toolbar = toolbar
                        .child(self.form_button(
                            "capture-clear",
                            "Clear",
                            Kind::Confirm(Command::Packets(
                                name.clone(),
                                PacketRequest {
                                    clear: true,
                                    ..Default::default()
                                },
                            )),
                            cx,
                        ))
                        .child(self.form_button(
                            "capture-stop",
                            "Stop and clear",
                            Kind::Confirm(Command::Packets(
                                name.clone(),
                                PacketRequest {
                                    stop: true,
                                    ..Default::default()
                                },
                            )),
                            cx,
                        ));
                }
            }
            page if page.is_organization() => toolbar = self.org_toolbar(page, toolbar, cx),
            Page::Remotes => {
                toolbar = toolbar.child(self.form_button(
                    "remote-add",
                    "Add profile",
                    Kind::RemoteAdd,
                    cx,
                ));
                if let Some(Record::Remote(profile)) = &selected {
                    let name = profile.name.clone();
                    toolbar = toolbar.child(
                        Button::new("remote-connect")
                            .small()
                            .label("Connect to selected")
                            .disabled(!self.can_edit_profiles())
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
                toolbar = toolbar.child(
                    Button::new("remote-local")
                        .small()
                        .label("Local machine")
                        .disabled(!self.can_edit_profiles() || self.local_options.is_none())
                        .on_click(cx.listener(|this, _, window, cx| {
                            if let Some(mut options) = this.local_options.clone() {
                                options.appearance = this.options.appearance;
                                this.switch_source(options, window, cx);
                            }
                        })),
                );
            }
            _ => {}
        }
        if record_actions
            && matches!(
                page,
                Page::Rules
                    | Page::Ports
                    | Page::Mounts
                    | Page::Secrets
                    | Page::Mcp
                    | Page::Images
                    | Page::Remotes
            )
        {
            toolbar = toolbar.child(
                Button::new("row-remove")
                    .small()
                    .label("Remove selected…")
                    .disabled(
                        selected.is_none()
                            // Organization, built-in, and default rules are not the sandbox's to remove.
                            || matches!(&selected, Some(Record::Rule(rule)) if !RuleOrigin::of(rule).editable())
                            || if page == Page::Remotes {
                                !self.can_edit_profiles()
                            } else {
                                !self.can_write()
                            },
                    )
                    .on_click(cx.listener(|this, _, window, cx| this.remove_selected(window, cx))),
            );
        }
        if let Some(status) = self.page_status(page) {
            toolbar = toolbar.child(div().flex_1()).child(
                div()
                    .text_size(px(11.))
                    .text_color(cx.theme().muted_foreground)
                    .child(status),
            );
        }
        let summary = self.page_summary(page, cx);
        let mut body = div()
            .flex()
            .flex_col()
            .size_full()
            .min_w_0()
            .min_h_0()
            .child(toolbar)
            // Redesigned screens explain themselves through their summary.
            .when(summary.is_none(), |d| {
                d.child(
                    div()
                        .px_4()
                        .py_2()
                        .text_size(px(11.))
                        .text_color(cx.theme().muted_foreground)
                        .child(page.help()),
                )
            });
        if let Some(notice) = &self.notice {
            body = body.child(
                div()
                    .px_4()
                    .py_2()
                    .text_size(px(12.))
                    .bg(cx.theme().accent)
                    .child(notice.clone()),
            );
        }
        if let Some(summary) = summary {
            body = body.child(summary);
        }
        if page == Page::Overview {
            body = body.child(
                div().flex().flex_wrap().px_4().py_2().gap_4().children(
                    [
                        ("Sandboxes", self.host.snapshot.sandboxes.len()),
                        (
                            "Running",
                            self.host
                                .snapshot
                                .sandboxes
                                .iter()
                                .filter(|s| s.state == "running")
                                .count(),
                        ),
                        ("Ports", self.host.snapshot.ports.len()),
                        ("Mounts", self.host.snapshot.mounts.len()),
                        ("Images", self.host.snapshot.images.len()),
                    ]
                    .into_iter()
                    .map(|(label, count)| {
                        div().text_size(px(12.)).child(format!("{label} · {count}"))
                    }),
                ),
            );
        }
        let unavailable = if page == Page::Remotes {
            self.profiles_error.clone()
        } else if page.is_organization() {
            match &self.connection {
                Connection::Offline(error) => Some(error.clone()),
                Connection::Connecting => Some("Connecting to the policy service…".into()),
                _ => self
                    .organization
                    .as_ref()
                    .filter(|o| o.document.is_none() && page == Page::OrgPolicy)
                    .map(|_| {
                        "This desktop cannot read the service's draft; editing is disabled.".into()
                    }),
            }
        } else {
            match &self.connection {
            Connection::Offline(error)=>Some(error.clone()),Connection::Connecting=>Some("Connecting to the selected manager…".into()),
            _ if !self.dashboard_available=>Some("This manager does not expose the dashboard API. Upgrade and restart it. Configuration writes are disabled.".into()),_=>None,
        }
        };
        if let Some(error) = unavailable {
            body = body.child(
                div()
                    .text_size(px(13.))
                    .text_color(cx.theme().warning)
                    .child(error),
            );
        }
        body = body.child(
            div()
                .id(("page-table", page.index()))
                .capture_any_mouse_down(|event, _, cx| {
                    if event.button == gpui_kit::MouseButton::Right {
                        cx.stop_propagation();
                    }
                })
                .test_support()
                .flex_1()
                .min_h_0()
                .overflow_hidden()
                .child(match self.page_list(page, cx) {
                    // Some screens draw their records instead of tabulating them;
                    // selection still flows through the page's table state.
                    Some(list) => div()
                        .id(("page-list", page.index()))
                        .size_full()
                        .overflow_y_scrollbar()
                        .child(list)
                        .into_any_element(),
                    None => DataTable::new(&state.table)
                        .bordered(false)
                        .stripe(false)
                        .with_size(px(34.))
                        .into_any_element(),
                }),
        );
        if self.inspector_open {
            // The inspector column shows the selected record.
        } else if let Some(record) = selected {
            body = body.child(
                div()
                    .id("record-details")
                    .test_support()
                    .h(px(156.))
                    .flex_shrink_0()
                    .border_t_1()
                    .border_color(cx.theme().border)
                    .px_4()
                    .py_3()
                    .bg(cx.theme().secondary)
                    .overflow_y_scrollbar()
                    .child(div().flex().flex_col().gap_1().children(
                        record.details().into_iter().map(|(key, value)| {
                            div()
                                .flex()
                                .gap_3()
                                .text_size(px(12.))
                                .child(
                                    div()
                                        .w(px(156.))
                                        .flex_shrink_0()
                                        .text_color(cx.theme().muted_foreground)
                                        .child(key),
                                )
                                .child(div().flex_1().min_w_0().child(value))
                        }),
                    )),
            );
        } else {
            body = body.child(
                div()
                    .text_size(px(12.))
                    .text_color(cx.theme().muted_foreground)
                    .child(if state.query.is_empty() {
                        "No rows. Select an action above or refresh this host."
                    } else {
                        "No matching rows. Clear the search to show all records."
                    }),
            );
        }
        body
    }
}

/// The share form pre-filled from an existing mount, replacing it in place.
pub fn mount_edit(r: &Mount) -> Kind {
    Kind::Share(Some(ShareRequest {
        sandbox: r.sandbox.clone(),
        tag: r.tag.clone(),
        path: r.host.clone(),
        mountpoint: r.guest.clone(),
        read_only: r.read_only,
        replace: true,
        current_guest: r.guest.clone(),
        owner: match (r.uid, r.gid) {
            (Some(uid), Some(gid)) => format!("{uid}:{gid}"),
            _ => String::new(),
        },
        ..Default::default()
    }))
}

/// The remote MCP form pre-filled from a server; local servers have none.
pub fn mcp_edit(r: &MCPServer) -> Option<Kind> {
    (r.r#type == "remote").then(|| {
        Kind::Mcp(Some(MCPRemoteRequest {
            sandbox: r.sandbox.clone(),
            name: r.name.clone(),
            url: r.url.clone(),
            auth_kind: r.auth_kind.clone(),
            auth_header: r.auth_header.clone(),
            auth_ref: r.auth_ref.clone(),
            allow: r.allow.clone(),
            deny: r.deny.clone(),
            redact: r.redact.clone(),
            replace: true,
        }))
    })
}
