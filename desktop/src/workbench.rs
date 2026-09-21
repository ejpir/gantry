use crate::app::{Connection, Desktop};
use gantry_desktop::{
    commands::Command,
    dashboard_wire::{ActionRequest, MCPRemoteRequest, PacketRequest, RuleRequest, ShareRequest},
    forms::{Intent, Kind},
    options::Source,
    workspace::{Page, Record},
};
use gpui_kit::component::{
    ActiveTheme, Disableable, Sizable, button::Button, input::Input, scroll::ScrollableElement,
    table::DataTable,
};
use gpui_kit::{Context, Div, InteractiveElement, ParentElement, Styled, TestSupportExt, div, px};

impl Desktop {
    fn form_button(
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
    pub fn workbench(&self, cx: &mut Context<Self>) -> Div {
        let page = self.page;
        let state = &self.pages[page.index()];
        let selected = self.selected_record(cx);
        let mut toolbar = div().flex().flex_wrap().gap_2();
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
                if let Some(Record::Traffic(row)) = &selected {
                    for (id, action) in [("traffic-allow", "allow"), ("traffic-deny", "deny")] {
                        let dns = row.protocol.eq_ignore_ascii_case("dns");
                        let request = RuleRequest {
                            sandbox: row.sandbox.clone(),
                            action: action.into(),
                            target: if dns {
                                row.host.clone()
                            } else {
                                row.address.clone()
                            },
                            proto: if ["tcp", "udp", "icmp", "dns"].contains(&row.protocol.as_str())
                            {
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
                        toolbar = toolbar.child(
                            self.form_button(
                                id,
                                if action == "allow" {
                                    "Allow destination"
                                } else {
                                    "Deny destination"
                                },
                                Kind::Rule(Some(request)),
                                cx,
                            )
                            .disabled(!self.can_write() || (dns && action == "deny")),
                        );
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
                if let Some(Record::Mount(r)) = &selected {
                    toolbar = toolbar.child(self.form_button(
                        "mount-edit",
                        "Edit mount",
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
                        })),
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
                if let Some(Record::Mcp(r)) = &selected
                    && r.r#type == "remote"
                {
                    toolbar = toolbar.child(self.form_button(
                        "mcp-edit",
                        "Edit server",
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
                        })),
                        cx,
                    ));
                }
            }
            Page::Images => {
                toolbar = toolbar
                    .child(self.form_button("image-pull", "Pull image", Kind::Pull, cx))
                    .child(self.form_button("registry-add", "Registry login", Kind::Registry, cx))
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
                    let name = name.clone();
                    toolbar = toolbar.child(
                        Button::new("capture-read")
                            .small()
                            .label("Read next batch")
                            .disabled(!self.can_write() || !self.packets.active)
                            .on_click(cx.listener(move |this, _, _, cx| {
                                let request = PacketRequest {
                                    after: this.packets.next,
                                    max_packets: 256,
                                    max_bytes: 262144,
                                    ..Default::default()
                                };
                                this.start_job(
                                    Intent::Manager(Command::Packets(name.clone(), request)),
                                    this.target.clone(),
                                    cx,
                                );
                            })),
                    );
                    let name = self.packet_sandbox.as_ref().unwrap();
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
        if matches!(
            page,
            Page::Rules
                | Page::Ports
                | Page::Mounts
                | Page::Secrets
                | Page::Mcp
                | Page::Images
                | Page::Remotes
        ) {
            toolbar = toolbar.child(
                Button::new("row-remove")
                    .small()
                    .label("Remove selected…")
                    .disabled(
                        selected.is_none()
                            || if page == Page::Remotes {
                                !self.can_edit_profiles()
                            } else {
                                !self.can_write()
                            },
                    )
                    .on_click(cx.listener(|this, _, window, cx| this.remove_selected(window, cx))),
            );
        }
        let mut body = div()
            .flex()
            .flex_col()
            .size_full()
            .min_w_0()
            .min_h_0()
            .p_6()
            .gap_3()
            .child(
                div()
                    .flex()
                    .justify_between()
                    .items_center()
                    .child(div().text_size(px(24.)).child(page.label()))
                    .child(
                        Button::new("page-refresh")
                            .small()
                            .label("Refresh")
                            .disabled(
                                self.refreshing
                                    || self.writing
                                    || self.options.source == Source::Demo,
                            )
                            .on_click(cx.listener(|this, _, _, cx| this.refresh(cx))),
                    ),
            )
            .child(
                div()
                    .text_size(px(12.))
                    .text_color(cx.theme().muted_foreground)
                    .child(page.help()),
            )
            .child(toolbar)
            .child(
                Input::new(&self.search)
                    .id("dashboard-search")
                    .cleanable(true),
            );
        if page == Page::Overview {
            body = body.child(
                div().flex().flex_wrap().gap_3().children(
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
                        div()
                            .px_4()
                            .py_2()
                            .rounded(cx.theme().radius)
                            .bg(cx.theme().accent)
                            .child(format!("{label} · {count}"))
                    }),
                ),
            );
        }
        if page == Page::Packets {
            body = body.child(div().text_size(px(12.)).child(format!(
                "Sandbox: {} · {} · through #{} · evicted {}",
                self.packet_sandbox.as_deref().unwrap_or("none"),
                if self.packets.active {
                    "recording"
                } else {
                    "inactive"
                },
                self.packets.next,
                self.packets.evicted
            )));
        }
        let unavailable = if page == Page::Remotes {
            self.profiles_error.clone()
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
                .test_support()
                .flex_1()
                .min_h_0()
                .border_1()
                .border_color(cx.theme().border)
                .rounded(cx.theme().radius)
                .overflow_hidden()
                .child(DataTable::new(&state.table).bordered(false)),
        );
        if let Some(record) = selected {
            body = body.child(
                div()
                    .id("record-details")
                    .test_support()
                    .h(px(156.))
                    .flex_shrink_0()
                    .border_t_1()
                    .border_color(cx.theme().border)
                    .pt_2()
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
