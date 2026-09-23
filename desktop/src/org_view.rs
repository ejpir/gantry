//! Organization: an administrator's view of a Gantry policy service. Hosts
//! and the generation each reports, the draft of the next generation, the
//! rollout ring by ring, the history of published generations, and host
//! enrollment. Hosts pull from the service; these screens only show what the
//! hosts themselves report, and every write goes to the service.

use crate::{
    app::*,
    charts,
    screens::InspectorView,
    theme,
    views::eyebrow,
    widgets::{self, TileAccent},
};
use gantry_desktop::{
    clock,
    commands::Command,
    forms::{Kind, OrgDraft, OrgPublishForm, OrgRuleForm},
    org::{
        self, Change, Edit, Generation, Host, ItemKind, OrgCommand, OrgRecord, OrgSnapshot,
        PolicyItem,
    },
    workspace::{Page, Record, text},
};
use gpui_kit::assets::IconName;
use gpui_kit::component::{
    ActiveTheme, Disableable, Icon, Selectable, Sizable,
    button::{Button, ButtonVariants},
};
use gpui_kit::{
    App, ClipboardItem, Context, Div, FontWeight, Hsla, InteractiveElement, IntoElement,
    ParentElement, Styled, TestSupportExt, div, prelude::FluentBuilder, px,
};

impl Desktop {
    // ------------------------------------------------------------ page hooks

    pub fn org_status(&self, page: Page) -> Option<String> {
        let o = self.organization.as_ref()?;
        Some(match page {
            Page::OrgHosts => "Generations as each host last reported them".into(),
            Page::OrgPolicy if o.draft.changes.is_empty() => {
                format!("No unpublished changes · {}", based_on(o.draft.base))
            }
            Page::OrgPolicy => format!(
                "Draft · {} · {}{}",
                based_on(o.draft.base),
                plural(o.draft.changes.len(), "change"),
                if o.draft.updated_by.is_empty() {
                    String::new()
                } else {
                    format!(" · last edit by {}", text(&o.draft.updated_by))
                }
            ),
            Page::OrgRollouts => match &o.overview.rollout {
                Some(r) => {
                    let started = clock::parse(&r.started_at)
                        .map(|t| format!("{} UTC", clock::clock(t)))
                        .unwrap_or_default();
                    format!(
                        "g{} · started {started} by {}",
                        r.generation,
                        text(&r.started_by)
                    )
                }
                None => "Nothing published yet".into(),
            },
            Page::OrgHistory => format!(
                "{} generation{} · numbers are never reused",
                o.generations.len(),
                if o.generations.len() == 1 { "" } else { "s" }
            ),
            Page::OrgEnrollment => format!(
                "Client certificates from the {} hosts CA",
                text(&o.overview.organization)
            ),
            _ => return None,
        })
    }

    pub fn org_summary(&self, page: Page, cx: &mut Context<Self>) -> Option<Div> {
        let o = self.organization.as_ref()?;
        let body = match page {
            Page::OrgHosts => self.hosts_summary(o, cx),
            Page::OrgPolicy => self.policy_summary(o, cx),
            Page::OrgRollouts => self.rollout_summary(o, cx),
            Page::OrgHistory => self.history_summary(o, cx),
            Page::OrgEnrollment => self.enrollment_summary(o, cx),
            _ => return None,
        };
        Some(div().px_4().pt(px(12.)).pb(px(14.)).child(body))
    }

    pub fn org_list(&self, page: Page, cx: &mut Context<Self>) -> Option<Div> {
        let o = self.organization.as_ref()?;
        let state = &self.pages[page.index()];
        let rows = state.table.read(cx).delegate().rows.clone();
        if rows.is_empty() {
            let message = match page {
                Page::OrgHosts | Page::OrgRollouts => {
                    "No enrolled hosts. Enroll one from Enrollment."
                }
                Page::OrgPolicy if state.segment == 1 => "No unpublished changes.",
                Page::OrgPolicy => "This profile has no rules: everything governed is denied.",
                Page::OrgHistory => "Nothing has been published yet.",
                _ => "No hosts match.",
            };
            return Some(widgets::note(message, cx).px_4());
        }
        let now = clock::now();
        let mut list = div().flex().flex_col().px_4().pb(px(14.));
        let mut group: Option<String> = None;
        for (index, row) in rows.iter().enumerate() {
            let Record::Org(record) = &row.record else {
                continue;
            };
            let selected = state.selected.as_deref() == Some(row.key.as_str());
            let key = row.key.clone();
            let (element, heading) = match (page, record) {
                (Page::OrgPolicy, OrgRecord::Item(item)) => (
                    item_row(item, selected, cx),
                    Some(item.kind.label().to_uppercase()),
                ),
                (Page::OrgPolicy, OrgRecord::Change(change)) => {
                    (change_row(change, selected, cx), None)
                }
                (Page::OrgHistory, OrgRecord::Generation(generation)) => {
                    (generation_row(o, generation, selected, now, cx), None)
                }
                (Page::OrgRollouts, OrgRecord::Host(host)) => (
                    rollout_row(host, selected, now, cx),
                    Some(format!("{} RING", host.ring.to_uppercase())),
                ),
                (Page::OrgEnrollment, OrgRecord::Host(host)) => {
                    (identity_row(host, selected, now, cx), None)
                }
                (_, OrgRecord::Host(host)) => (host_row(host, selected, now, cx), None),
                _ => continue,
            };
            if let Some(heading) = heading
                && group.as_deref() != Some(heading.as_str())
            {
                list = list.child(
                    eyebrow(&heading, cx)
                        .pt(px(if group.is_some() { 14. } else { 2. }))
                        .pb(px(6.)),
                );
                group = Some(heading);
            }
            list = list.child(
                element
                    .id(("org-row", index))
                    .test_support()
                    .cursor_pointer()
                    .on_mouse_down(
                        gpui_kit::MouseButton::Left,
                        cx.listener(move |this, _, _, cx| {
                            if this.page == Page::OrgPolicy {
                                this.toggle_page_row(key.clone(), cx)
                            } else {
                                this.select_page_row(key.clone(), cx)
                            }
                        }),
                    ),
            );
        }
        // Reviewing changes ends with the document itself, as it will be signed.
        if page == Page::OrgPolicy
            && state.segment == 1
            && let Some(lines) = o.diff()
        {
            list = list.child(div().mt(px(14.)).child(diff_card(&lines, o.draft.base, cx)));
        }
        Some(list)
    }

    pub fn org_inspector(&self, record: &OrgRecord, cx: &mut Context<Self>) -> InspectorView {
        match record {
            OrgRecord::Host(host) => self.host_inspector(host, cx),
            OrgRecord::Generation(generation) => self.generation_inspector(generation, cx),
            OrgRecord::Item(item) => self.item_inspector(item, cx),
            OrgRecord::Change(change) => self.change_inspector(change, cx),
        }
    }

    /// With nothing selected, the Policy page's inspector is the publish panel.
    pub fn org_empty_inspector(&self, page: Page, cx: &mut Context<Self>) -> Option<InspectorView> {
        (page == Page::OrgPolicy)
            .then(|| self.publish_panel(cx))
            .flatten()
    }

    pub fn org_toolbar(&self, page: Page, mut toolbar: Div, cx: &mut Context<Self>) -> Div {
        let Some(o) = self.organization.as_ref() else {
            return toolbar;
        };
        match page {
            Page::OrgHosts | Page::OrgEnrollment => {
                toolbar = toolbar.child(self.org_button(
                    "org-enroll",
                    "Enroll host…",
                    Some(Kind::OrgEnroll {
                        profiles: o.profiles(),
                        rings: o.rings(),
                    }),
                    cx,
                ));
            }
            Page::OrgPolicy => {
                toolbar =
                    toolbar.child(
                        div()
                            .flex()
                            .p(px(2.))
                            .rounded(px(5.))
                            .bg(cx.theme().background)
                            .border_1()
                            .border_color(cx.theme().border)
                            .children(o.profiles().into_iter().enumerate().map(
                                |(index, profile)| {
                                    let selected = profile == self.org_profile;
                                    let hosts =
                                        o.active_hosts().filter(|h| h.profile == profile).count();
                                    Button::new(("org-profile", index))
                                        .ghost()
                                        .xsmall()
                                        .h(px(21.))
                                        .px_3()
                                        .label(format!("{}  {hosts}", text(&profile)))
                                        .tooltip("Hosts using this profile")
                                        .selected(selected)
                                        .when(selected, |b| b.bg(theme::selected_control(cx)))
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.set_org_profile(profile.clone(), cx)
                                        }))
                                },
                            )),
                    );
                let draft = self.org_draft();
                toolbar = toolbar
                    .child(self.org_button(
                        "org-add-network",
                        "Network rule…",
                        draft.clone().map(|draft| {
                            Kind::OrgRule(Box::new(OrgRuleForm {
                                draft,
                                network: true,
                                existing: None,
                            }))
                        }),
                        cx,
                    ))
                    .child(self.org_button(
                        "org-add-rule",
                        "Access rule…",
                        draft.clone().map(|draft| {
                            Kind::OrgRule(Box::new(OrgRuleForm {
                                draft,
                                network: false,
                                existing: None,
                            }))
                        }),
                        cx,
                    ))
                    .child(self.org_button(
                        "org-add-dns",
                        "DNS name…",
                        draft.map(|draft| Kind::OrgDns(Box::new(draft))),
                        cx,
                    ))
                    .child(self.org_button(
                        "org-publish",
                        "Sign & Publish…",
                        self.publish_kind(),
                        cx,
                    ))
                    .child(
                        self.org_button(
                            "org-discard",
                            "Discard…",
                            o.draft
                                .saved
                                .then(|| Kind::Confirm(Command::Org(OrgCommand::DiscardDraft))),
                            cx,
                        ),
                    );
            }
            Page::OrgRollouts => {
                let promote = o
                    .overview
                    .rollout
                    .as_ref()
                    .zip(o.next_ring())
                    .map(|(r, ring)| {
                        (
                            format!("Promote to {ring}…"),
                            Kind::Confirm(Command::Org(OrgCommand::Promote {
                                generation: r.generation,
                                ring,
                            })),
                        )
                    });
                let (label, kind) = promote
                    .map(|(label, kind)| (label, Some(kind)))
                    .unwrap_or(("Promote…".into(), None));
                toolbar = toolbar.child(self.org_button_owned("org-promote", label, kind, cx));
                let rollback = o.previous_generation().map(|generation| {
                    (
                        format!("Roll back to g{generation}…"),
                        Kind::Confirm(Command::Org(OrgCommand::Republish {
                            generation,
                            first_ring: String::new(),
                        })),
                    )
                });
                let (label, kind) = rollback
                    .map(|(label, kind)| (label, Some(kind)))
                    .unwrap_or(("Roll back…".into(), None));
                toolbar = toolbar.child(self.org_button_owned("org-rollback", label, kind, cx));
            }
            Page::OrgHistory => {
                let selected = match self.selected_record(cx) {
                    Some(Record::Org(OrgRecord::Generation(g))) => Some(g.number),
                    _ => None,
                };
                toolbar = toolbar
                    .child(
                        self.org_button(
                            "org-republish",
                            "Republish selected…",
                            selected
                                .filter(|n| *n != o.overview.latest)
                                .map(|generation| {
                                    Kind::Confirm(Command::Org(OrgCommand::Republish {
                                        generation,
                                        first_ring: String::new(),
                                    }))
                                }),
                            cx,
                        ),
                    )
                    .child(self.org_button(
                        "org-download",
                        "Download bundle…",
                        selected.map(Kind::OrgDownload),
                        cx,
                    ));
            }
            _ => {}
        }
        toolbar
    }

    // ------------------------------------------------------------ helpers

    fn org_button(
        &self,
        id: &'static str,
        label: &'static str,
        kind: Option<Kind>,
        cx: &mut Context<Self>,
    ) -> Button {
        self.org_button_owned(id, label.into(), kind, cx)
    }

    fn org_button_owned(
        &self,
        id: &'static str,
        label: String,
        kind: Option<Kind>,
        cx: &mut Context<Self>,
    ) -> Button {
        let enabled = kind.is_some() && self.can_write() && self.form.is_none();
        Button::new(id)
            .small()
            .label(label)
            .disabled(!enabled)
            .on_click(cx.listener(move |this, _, window, cx| {
                if let Some(kind) = kind.clone() {
                    this.open_form(kind, window, cx)
                }
            }))
    }

    /// The draft being edited on the Policy page, as a form's starting point.
    fn org_draft(&self) -> Option<OrgDraft> {
        let o = self.organization.as_ref()?;
        Some(OrgDraft {
            base: o.draft.base,
            document: o.document.clone()?,
            profile: self.org_profile.clone(),
        })
    }

    fn publish_kind(&self) -> Option<Kind> {
        let o = self.organization.as_ref()?;
        if o.draft.changes.is_empty() && o.overview.latest > 0 || !o.draft.problem.is_empty() {
            return None;
        }
        let draft = self.org_draft()?;
        let profiles: Vec<&str> = o.draft.changes.iter().map(|c| c.profile.as_str()).collect();
        let hosts = o
            .active_hosts()
            .filter(|h| {
                profiles.is_empty()
                    || profiles.contains(&h.profile.as_str())
                    || profiles.contains(&"")
            })
            .count();
        Some(Kind::OrgPublish(Box::new(OrgPublishForm {
            draft,
            rings: o.rings(),
            key_fingerprint: o.overview.public_key_fingerprint.clone(),
            revision: org::next_revision(o, clock::now()),
            changes: o.draft.changes.len(),
            loosens: o
                .draft
                .changes
                .iter()
                .filter(|c| c.effect == "loosens")
                .count(),
            hosts,
            gantry: self.options.gantry.clone(),
            managed: self.options.managed_gantry.clone(),
        })))
    }

    // ------------------------------------------------------------ hosts

    fn hosts_summary(&self, o: &OrgSnapshot, cx: &App) -> Div {
        let active: Vec<&Host> = o.active_hosts().collect();
        let latest = o.overview.latest;
        let newest = active
            .iter()
            .filter(|h| {
                h.report
                    .as_ref()
                    .is_some_and(|r| r.applied == latest && latest > 0)
            })
            .count();
        // Current on a ring that has not been promoted yet is not behind.
        let held = active
            .iter()
            .filter(|h| h.status == "current" && h.target < latest)
            .count();
        let attention = active.iter().filter(|h| org::needs_attention(h)).count();
        let profiles = o.profiles().len();
        let now = clock::now();
        let expiry = o
            .overview
            .next_expiry
            .as_deref()
            .and_then(|e| org::days_until(e, now));
        let tiles = widgets::tiles([
            widgets::tile(
                "HOSTS",
                active.len().to_string(),
                format!("{profiles} profiles · {} rings", o.overview.rings.len()),
                TileAccent::None,
                cx,
            ),
            widgets::tile(
                &if latest == 0 {
                    "NEWEST".into()
                } else {
                    format!("ON g{latest}")
                },
                if latest == 0 {
                    "—".into()
                } else {
                    format!("{newest} of {}", active.len())
                },
                if latest == 0 {
                    "nothing published yet".into()
                } else if held > 0 {
                    format!("{held} more current on held rings")
                } else {
                    "applied the newest generation".into()
                },
                TileAccent::Ratio(ratio(newest, active.len()), cx.theme().success),
                cx,
            ),
            widgets::tile(
                "ATTENTION",
                attention.to_string(),
                "stalled, rejected, or mismatched".into(),
                if attention > 0 {
                    TileAccent::Tint(cx.theme().danger)
                } else {
                    TileAccent::None
                },
                cx,
            ),
            widgets::tile(
                "POLICY EXPIRES",
                expiry
                    .map(|d| format!("{d} days"))
                    .unwrap_or_else(|| "—".into()),
                o.overview
                    .next_expiry
                    .as_deref()
                    .map(|e| format!("soonest of what hosts run · {}", &e[..10.min(e.len())]))
                    .unwrap_or_else(|| "nothing applied yet".into()),
                if expiry.is_some_and(|d| d <= 14) {
                    TileAccent::Tint(cx.theme().warning)
                } else {
                    TileAccent::None
                },
                cx,
            ),
        ]);
        div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(tiles)
            .child(ring_strip(o, cx))
    }

    fn host_inspector(&self, host: &Host, cx: &mut Context<Self>) -> InspectorView {
        let o = self.organization.as_ref();
        let now = clock::now();
        let (label, color) = status_style(host, cx);
        let report = host.report.clone().unwrap_or_default();
        let when = |value: &Option<String>| {
            value
                .as_deref()
                .and_then(clock::parse)
                .map(|t| format!("{} UTC · {} ago", clock::clock(t), clock::age(t, now)))
                .unwrap_or_else(|| "—".into())
        };
        let mut feed = vec![
            ("Target", generation_label(host.target), false),
            (
                "Applied",
                if report.applied == 0 {
                    "nothing yet".into()
                } else if report.digest_matches {
                    format!("g{} · digest matches", report.applied)
                } else {
                    format!("g{} · digest differs", report.applied)
                },
                false,
            ),
        ];
        if report.pending != 0 {
            feed.push((
                "Pending",
                format!(
                    "g{} · {} attempt{}{}",
                    report.pending,
                    report.attempts,
                    if report.attempts == 1 { "" } else { "s" },
                    match report.failed {
                        Some(0) | None if report.attempts == 0 => String::new(),
                        Some(failed) => format!(
                            " · {failed} sandbox{} failed",
                            if failed == 1 { "" } else { "es" }
                        ),
                        None => " · sandboxes unreachable".into(),
                    }
                ),
                false,
            ));
        }
        if !report.rejected_reason.is_empty() {
            feed.push((
                "Refused",
                format!(
                    "{} · {}",
                    generation_label(report.rejected_generation),
                    report.rejected_reason
                ),
                false,
            ));
        }
        feed.extend([
            ("Offered", when(&host.served_at), false),
            ("Acknowledged", when(&host.acknowledged_at), false),
            (
                "Polls since offer",
                host.polls_since_served.to_string(),
                false,
            ),
            ("Last poll", when(&host.last_seen), false),
        ]);
        let mut identity = vec![
            ("Profile", host.profile.clone(), false),
            ("Ring", host.ring.clone(), false),
            (
                "Certificate",
                org::short_fingerprint(&host.certificate.fingerprint),
                true,
            ),
            (
                "Expires",
                org::days_until(&host.certificate.not_after, now)
                    .map(|d| {
                        format!(
                            "{} · {d} d",
                            &host.certificate.not_after[..10.min(host.certificate.not_after.len())]
                        )
                    })
                    .unwrap_or_else(|| "—".into()),
                false,
            ),
            ("Issued by", host.certificate.issued_by.clone(), false),
            (
                "Reports as",
                [report.agent.as_str(), report.address.as_str()]
                    .into_iter()
                    .filter(|v| !v.is_empty())
                    .collect::<Vec<_>>()
                    .join(" · "),
                false,
            ),
        ];
        for row in &mut identity {
            if row.1.is_empty() {
                row.1 = "—".into();
            }
        }
        let explanation = status_explanation(host, o);
        let fingerprint = host.certificate.fingerprint.clone();
        let rings = o.map(|o| o.rings()).unwrap_or_default();
        let body = div()
            .flex()
            .flex_col()
            .gap(px(14.))
            .child(widgets::inspector_section("FEED", feed, cx))
            .child(widgets::separator(cx))
            .child(widgets::inspector_section("IDENTITY", identity, cx))
            .child(widgets::separator(cx))
            .when_some(explanation, |d, (title, detail, tone)| {
                let color = match tone {
                    Tone::Danger => cx.theme().danger,
                    Tone::Warning => cx.theme().warning,
                    Tone::Quiet => cx.theme().muted_foreground,
                };
                d.child(widgets::inspector_note(
                    IconName::TriangleAlert,
                    color,
                    title,
                    &detail,
                    cx,
                ))
            })
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .child(self.org_button(
                        "org-move-host",
                        "Move to ring…",
                        (!host.revoked).then(|| Kind::OrgMoveHost {
                            name: host.name.clone(),
                            ring: host.ring.clone(),
                            rings,
                        }),
                        cx,
                    ))
                    .child(
                        self.org_button(
                            "org-revoke",
                            "Revoke…",
                            (!host.revoked).then(|| {
                                Kind::Confirm(Command::Org(OrgCommand::Revoke {
                                    name: host.name.clone(),
                                }))
                            }),
                            cx,
                        )
                        .when(!host.revoked && self.can_write(), |b| {
                            b.text_color(cx.theme().danger)
                        }),
                    )
                    .child(
                        Button::new("org-copy-fingerprint")
                            .small()
                            .label("Copy Fingerprint")
                            .on_click(move |_, _, cx| {
                                cx.write_to_clipboard(ClipboardItem::new_string(
                                    fingerprint.clone(),
                                ))
                            }),
                    ),
            );
        InspectorView {
            header: widgets::inspector_header(
                IconName::Server,
                &host.name,
                Some((&format!("{label} · {}", host.profile), color)),
                format!("{} ring", text(&host.ring)),
                cx,
            ),
            body,
            footer: format!("Inspecting a host enrolled in {}", self.source_name()),
        }
    }

    // ------------------------------------------------------------ policy

    fn policy_summary(&self, o: &OrgSnapshot, cx: &App) -> Div {
        let profile = o
            .document
            .as_ref()
            .and_then(|d| d.profiles.get(&self.org_profile));
        let hosts = o
            .active_hosts()
            .filter(|h| h.profile == self.org_profile)
            .count();
        let (allow, deny, dns) = profile
            .map(|p| {
                let allow = p.rules.iter().filter(|r| r.effect == "allow").count()
                    + p.network
                        .rules
                        .iter()
                        .filter(|r| r.effect == "allow")
                        .count();
                let deny = p.rules.len() + p.network.rules.len() - allow;
                (allow, deny, p.network.dns.len())
            })
            .unwrap_or_default();
        let loosens = o
            .draft
            .changes
            .iter()
            .filter(|c| c.effect == "loosens")
            .count();
        let now = clock::now();
        let expires = o
            .document
            .as_ref()
            .and_then(|d| org::days_until(&d.expires_at, now));
        widgets::tiles([
            widgets::tile(
                "HOSTS",
                hosts.to_string(),
                format!("use the {} profile", text(&self.org_profile)),
                TileAccent::None,
                cx,
            ),
            widgets::tile(
                "RULES",
                (allow + deny).to_string(),
                format!("{allow} allow · {deny} deny · {dns} DNS names"),
                TileAccent::None,
                cx,
            ),
            widgets::tile(
                "DRAFT",
                if o.draft.changes.is_empty() {
                    "no changes".into()
                } else {
                    plural(o.draft.changes.len(), "change")
                },
                if o.draft.problem.is_empty() {
                    format!("{loosens} loosen access · {}", based_on(o.draft.base))
                } else {
                    format!("does not validate: {}", text(&o.draft.problem))
                },
                if !o.draft.problem.is_empty() {
                    TileAccent::Tint(cx.theme().danger)
                } else if o.draft.changes.is_empty() {
                    TileAccent::None
                } else {
                    TileAccent::Tint(cx.theme().warning)
                },
                cx,
            ),
            widgets::tile(
                "EXPIRES",
                expires
                    .map(|d| format!("{d} days"))
                    .unwrap_or_else(|| "—".into()),
                "chosen again when you sign".into(),
                if expires.is_some_and(|d| d <= 14) {
                    TileAccent::Tint(cx.theme().warning)
                } else {
                    TileAccent::None
                },
                cx,
            ),
        ])
    }

    fn item_inspector(&self, item: &PolicyItem, cx: &mut Context<Self>) -> InspectorView {
        let (status, color) = match item.change.as_str() {
            "added" => ("Added in draft", cx.theme().success),
            "changed" => ("Changed in draft", cx.theme().warning),
            "removed" => ("Removed in draft", cx.theme().danger),
            _ => ("Published", cx.theme().muted_foreground),
        };
        let draft = self.org_draft();
        let edit = draft
            .clone()
            .filter(|_| !item.removed() && item.kind != ItemKind::Dns)
            .map(|draft| {
                Kind::OrgRule(Box::new(OrgRuleForm {
                    draft,
                    network: item.kind == ItemKind::Network,
                    existing: Some(item.clone()),
                }))
            });
        let remove = draft.filter(|_| !item.removed()).and_then(|draft| {
            let edit = Edit::Remove {
                kind: item.kind.clone(),
                id: item.id.clone(),
            };
            org::apply_edit(&draft.document, &draft.profile, &edit)
                .ok()
                .map(|document| {
                    Kind::Confirm(Command::Org(OrgCommand::SaveDraft {
                        base: draft.base,
                        document,
                        summary: edit.summary(&draft.profile),
                    }))
                })
        });
        let hosts = self
            .organization
            .as_ref()
            .map(|o| {
                o.active_hosts()
                    .filter(|h| h.profile == item.profile)
                    .count()
            })
            .unwrap_or_default();
        let mut rule = vec![("Effect", item.effect.clone(), false)];
        match item.kind {
            ItemKind::Network => {
                rule.push(("CIDR", item.selector.clone(), true));
                rule.push(("Protocol / ports", item.detail.clone(), true));
            }
            ItemKind::Dns => rule.push(("Name", item.selector.clone(), true)),
            _ => {
                rule.push(("Action", item.action.clone(), true));
                rule.push(("Target", item.selector.clone(), true));
            }
        }
        if item.kind != ItemKind::Dns {
            rule.push(("Rule ID", item.id.clone(), true));
        }
        let body = div()
            .flex()
            .flex_col()
            .gap(px(14.))
            .child(widgets::inspector_section("RULE", rule, cx))
            .child(widgets::separator(cx))
            .child(widgets::inspector_section(
                "WHO GETS IT",
                vec![
                    ("Profile", item.profile.clone(), false),
                    ("Hosts", hosts.to_string(), false),
                    (
                        "Takes effect",
                        "as each host applies the next generation".into(),
                        false,
                    ),
                ],
                cx,
            ))
            .child(widgets::separator(cx))
            .when(!item.change.is_empty(), |d| {
                d.child(widgets::inspector_note(
                    IconName::Info,
                    effect_color(&item.effect_of_change, cx),
                    &format!("This change {}", effect_words(&item.effect_of_change)),
                    "Nothing reaches hosts until the draft is signed and published.",
                    cx,
                ))
            })
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(self.org_button("org-edit-rule", "Edit…", edit, cx))
                    .child(
                        self.org_button("org-remove-rule", "Remove…", remove.clone(), cx)
                            .when(remove.is_some() && self.can_write(), |b| {
                                b.text_color(cx.theme().danger)
                            }),
                    ),
            );
        InspectorView {
            header: widgets::inspector_header(
                item_icon(&item.kind),
                if item.kind == ItemKind::Dns {
                    &item.selector
                } else {
                    &item.id
                },
                Some((&format!("{status} · {}", item.profile), color)),
                item.kind.label().into(),
                cx,
            ),
            body,
            footer: format!("Editing the {} draft", text(&item.profile)),
        }
    }

    fn change_inspector(&self, change: &Change, cx: &mut Context<Self>) -> InspectorView {
        let hosts = self
            .organization
            .as_ref()
            .map(|o| {
                o.active_hosts()
                    .filter(|h| change.profile.is_empty() || h.profile == change.profile)
                    .count()
            })
            .unwrap_or_default();
        let mut rows = vec![
            ("Change", change.change.clone(), false),
            ("Kind", change.kind.clone(), false),
            (
                "Profile",
                if change.profile.is_empty() {
                    "every profile".into()
                } else {
                    change.profile.clone()
                },
                false,
            ),
            ("Hosts affected", hosts.to_string(), false),
        ];
        if !change.before.is_empty() {
            rows.push(("Before", change.before.clone(), true));
        }
        if !change.after.is_empty() {
            rows.push(("After", change.after.clone(), true));
        }
        let body = div()
            .flex()
            .flex_col()
            .gap(px(14.))
            .child(widgets::inspector_section("CHANGE", rows, cx))
            .child(widgets::separator(cx))
            .child(widgets::inspector_note(
                IconName::Info,
                effect_color(&change.effect, cx),
                &format!("This change {}", effect_words(&change.effect)),
                match change.effect.as_str() {
                    "tightens" => "Running sandboxes lose that access live; open MCP sessions close and reconnect under the new policy.",
                    "loosens" => "Sandboxes on these hosts gain the access once their host applies the generation.",
                    _ => "Hosts apply it live; stopped sandboxes take it at their next start.",
                },
                cx,
            ));
        InspectorView {
            header: widgets::inspector_header(
                change_icon(&change.kind),
                if change.id.is_empty() {
                    &change.summary
                } else {
                    &change.id
                },
                Some((
                    &format!("{} · {}", change.change, change.effect),
                    effect_color(&change.effect, cx),
                )),
                if change.profile.is_empty() {
                    "organization".into()
                } else {
                    text(&change.profile)
                },
                cx,
            ),
            body,
            footer: "Reviewing the draft before signing".into(),
        }
    }

    fn publish_panel(&self, cx: &mut Context<Self>) -> Option<InspectorView> {
        let o = self.organization.as_ref()?;
        let next = o.overview.latest + 1;
        let loosens = o
            .draft
            .changes
            .iter()
            .filter(|c| c.effect == "loosens")
            .count();
        let tightens = o
            .draft
            .changes
            .iter()
            .filter(|c| c.effect == "tightens")
            .count();
        let checks = [
            (
                o.draft.problem.is_empty(),
                if o.draft.problem.is_empty() {
                    "The draft validates like policy sign".into()
                } else {
                    format!("Invalid: {}", text(&o.draft.problem))
                },
            ),
            (
                !o.draft.changes.is_empty() || o.overview.latest == 0,
                if o.draft.changes.is_empty() {
                    "No changes to publish yet".into()
                } else {
                    format!(
                        "{} · {}",
                        plural(o.draft.changes.len(), "change"),
                        based_on(o.draft.base)
                    )
                },
            ),
            (
                true,
                format!(
                    "Signed here; must match key {}",
                    org::short_fingerprint(&o.overview.public_key_fingerprint)
                ),
            ),
            (true, format!("Generation {next} has never been served")),
        ];
        let body = div()
            .flex()
            .flex_col()
            .gap(px(14.))
            .child(widgets::inspector_section(
                "NEXT GENERATION",
                vec![
                    ("Loosens access", loosens.to_string(), false),
                    ("Tightens access", tightens.to_string(), false),
                    ("First offered to", o.rings().first().cloned().unwrap_or_default(), false),
                    ("Signing key", format!("RSA-{} · {}", o.overview.public_key_bits, org::short_fingerprint(&o.overview.public_key_fingerprint)), true),
                ],
                cx,
            ))
            .child(widgets::separator(cx))
            .child(eyebrow("CHECKS", cx))
            .children(checks.into_iter().map(|(ok, label)| {
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .text_size(px(12.))
                    .child(
                        Icon::new(if ok { IconName::Check } else { IconName::CircleAlert })
                            .size(px(13.))
                            .text_color(if ok { cx.theme().success } else { cx.theme().danger }),
                    )
                    .child(div().flex_1().min_w(px(0.)).child(label))
            }))
            .child(div().flex().gap_2().child(
                self.org_button("org-publish-panel", "Sign & Publish…", self.publish_kind(), cx),
            ))
            .child(
                div()
                    .text_size(px(11.))
                    .text_color(cx.theme().muted_foreground)
                    .child("The private key is read only by the Gantry CLI on this machine; only the signed bundle is uploaded."),
            );
        Some(InspectorView {
            header: widgets::inspector_header(
                IconName::BadgeCheck,
                &format!("Generation {next}"),
                Some((
                    if o.draft.changes.is_empty() {
                        "No changes to publish"
                    } else {
                        "Draft · not signed yet"
                    },
                    if o.draft.changes.is_empty() {
                        cx.theme().muted_foreground
                    } else {
                        cx.theme().warning
                    },
                )),
                text(&o.overview.organization),
                cx,
            ),
            body,
            footer: "Select a rule to edit it".into(),
        })
    }

    // ------------------------------------------------------------ rollouts

    fn rollout_summary(&self, o: &OrgSnapshot, cx: &App) -> Div {
        let Some(rollout) = &o.overview.rollout else {
            return widgets::note(
                "Nothing has been published. Draft a policy on the Policy page, then sign and publish it.",
                cx,
            );
        };
        let total: u32 = rollout.rings.iter().map(|r| r.hosts).sum();
        let acknowledged: u32 = rollout.rings.iter().map(|r| r.acknowledged).sum();
        let offered: u32 = rollout.rings.iter().map(|r| r.offered).sum();
        let attention: u32 = rollout.rings.iter().map(|r| r.stalled + r.rejected).sum();
        let held: u32 = rollout
            .rings
            .iter()
            .filter(|r| r.promoted_at.is_none())
            .map(|r| r.hosts)
            .sum();
        let tiles = widgets::tiles([
            widgets::tile(
                "ACKNOWLEDGED",
                format!("{acknowledged} of {total}"),
                format!("hosts enforcing g{}", rollout.generation),
                TileAccent::Ratio(
                    ratio(acknowledged as usize, total as usize),
                    cx.theme().success,
                ),
                cx,
            ),
            widgets::tile(
                "IN PROGRESS",
                offered.to_string(),
                "offered, not yet acknowledged".into(),
                TileAccent::None,
                cx,
            ),
            widgets::tile(
                "ATTENTION",
                attention.to_string(),
                "stalled or refused".into(),
                if attention > 0 {
                    TileAccent::Tint(cx.theme().danger)
                } else {
                    TileAccent::None
                },
                cx,
            ),
            widgets::tile(
                "HELD",
                held.to_string(),
                if held > 0 {
                    "wait for you to promote".into()
                } else {
                    "every ring promoted".into()
                },
                TileAccent::None,
                cx,
            ),
        ]);
        let pipeline = div().flex().items_center().gap(px(6.)).children(
            rollout.rings.iter().enumerate().flat_map(|(index, ring)| {
                let promoted = ring.promoted_at.is_some();
                let current = promoted && ring.acknowledged < ring.hosts;
                let status = if !promoted {
                    ("held", cx.theme().muted_foreground)
                } else if ring.stalled + ring.rejected > 0 {
                    ("attention", cx.theme().danger)
                } else if ring.acknowledged == ring.hosts {
                    ("done", cx.theme().success)
                } else {
                    ("in progress", cx.theme().primary)
                };
                let total = ring.hosts.max(1) as f32;
                let parts = [
                    (ring.acknowledged as f32 / total, cx.theme().success),
                    (ring.offered as f32 / total, cx.theme().warning),
                    (
                        (ring.stalled + ring.rejected) as f32 / total,
                        cx.theme().danger,
                    ),
                    (
                        // Counts come from the service; never underflow.
                        ring.hosts.saturating_sub(
                            ring.acknowledged + ring.offered + ring.stalled + ring.rejected,
                        ) as f32
                            / total,
                        theme::track(cx),
                    ),
                ];
                let card = widgets::card(cx)
                    .flex_1()
                    .min_w(px(0.))
                    .gap(px(6.))
                    .when(current, |d| d.border_color(cx.theme().primary))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .child(eyebrow(&ring.name.to_uppercase(), cx))
                            .child(div().flex_1())
                            .child(
                                div()
                                    .text_size(px(10.))
                                    .text_color(status.1)
                                    .child(status.0),
                            ),
                    )
                    .child(
                        div()
                            .text_size(px(18.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(format!("{} / {}", ring.acknowledged, ring.hosts)),
                    )
                    .child(widgets::stacked_bar(&parts, cx).h(px(6.)))
                    .child(
                        div()
                            .truncate()
                            .text_size(px(10.))
                            .text_color(cx.theme().muted_foreground)
                            .child(match &ring.promoted_at {
                                Some(at) => format!(
                                    "promoted {} by {}",
                                    clock::parse(at).map(clock::clock).unwrap_or_default(),
                                    text(&ring.promoted_by)
                                ),
                                None => "held until you promote it".into(),
                            }),
                    );
                let arrow = (index + 1 < rollout.rings.len()).then(|| {
                    Icon::new(IconName::ArrowRight)
                        .size(px(16.))
                        .text_color(cx.theme().muted_foreground)
                        .into_any_element()
                });
                std::iter::once(card.into_any_element()).chain(arrow)
            }),
        );
        div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(tiles)
            .child(pipeline)
            .children(acknowledgement_chart(o, cx))
    }

    // ------------------------------------------------------------ history

    fn history_summary(&self, o: &OrgSnapshot, cx: &App) -> Div {
        let mut serving: Vec<(u64, u32)> = o
            .generations
            .iter()
            .filter(|g| g.hosts > 0)
            .map(|g| (g.number, g.hosts))
            .collect();
        serving.sort_by_key(|g| std::cmp::Reverse(g.0));
        let rollbacks = o.generations.iter().filter(|g| g.republish_of != 0).count();
        let now = clock::now();
        let expiry = o
            .overview
            .next_expiry
            .as_deref()
            .and_then(|e| org::days_until(e, now));
        let tiles = widgets::tiles([
            widgets::tile(
                "GENERATIONS",
                o.generations.len().to_string(),
                o.generations
                    .last()
                    .map(|g| format!("since {}", &g.published_at[..10.min(g.published_at.len())]))
                    .unwrap_or_else(|| "none yet".into()),
                TileAccent::None,
                cx,
            ),
            widgets::tile(
                "SERVING",
                if serving.is_empty() {
                    "—".into()
                } else {
                    serving
                        .iter()
                        .map(|(g, _)| format!("g{g}"))
                        .collect::<Vec<_>>()
                        .join(" · ")
                },
                format!(
                    "{} host{}",
                    serving
                        .iter()
                        .map(|(_, h)| h.to_string())
                        .collect::<Vec<_>>()
                        .join(" and "),
                    if serving.iter().map(|(_, h)| h).sum::<u32>() == 1 {
                        ""
                    } else {
                        "s"
                    }
                ),
                TileAccent::None,
                cx,
            ),
            widgets::tile(
                "ROLLBACKS",
                rollbacks.to_string(),
                "republished, never rewound".into(),
                TileAccent::None,
                cx,
            ),
            widgets::tile(
                "NEXT EXPIRY",
                expiry
                    .map(|d| format!("{d} days"))
                    .unwrap_or_else(|| "—".into()),
                "of generations hosts still run".into(),
                if expiry.is_some_and(|d| d <= 14) {
                    TileAccent::Tint(cx.theme().warning)
                } else {
                    TileAccent::None
                },
                cx,
            ),
        ]);
        let parts: Vec<(f32, Hsla)> = serving
            .iter()
            .enumerate()
            .map(|(slot, (_, hosts))| (*hosts as f32, theme::series(cx, slot)))
            .collect();
        div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(tiles)
            .when(!parts.is_empty(), |d| {
                d.child(widgets::section_title(
                    "HOSTS BY GENERATION",
                    format!("{} enrolled", o.active_hosts().count()),
                    cx,
                ))
                .child(widgets::stacked_bar(&parts, cx))
                .child(widgets::legend(
                    serving.iter().enumerate().map(|(slot, (g, hosts))| {
                        (format!("g{g}"), hosts.to_string(), theme::series(cx, slot))
                    }),
                    cx,
                ))
            })
    }

    fn generation_inspector(
        &self,
        generation: &Generation,
        cx: &mut Context<Self>,
    ) -> InspectorView {
        let o = self.organization.as_ref();
        let latest = o.map(|o| o.overview.latest).unwrap_or_default();
        let (status, color) = generation_status(o, generation, cx);
        let now = clock::now();
        let body = div()
            .flex()
            .flex_col()
            .gap(px(14.))
            .child(widgets::inspector_section(
                "SIGNED BUNDLE",
                vec![
                    ("Revision", generation.revision.clone(), false),
                    (
                        "Published",
                        clock::parse(&generation.published_at)
                            .map(|t| {
                                format!("{} · {}", &generation.published_at[..10], clock::clock(t))
                            })
                            .unwrap_or_default(),
                        false,
                    ),
                    ("By", generation.published_by.clone(), false),
                    (
                        "SHA-256",
                        org::short_fingerprint(&generation.bundle_sha256),
                        true,
                    ),
                    (
                        "Size",
                        format!("{:.1} KiB", generation.size as f32 / 1024.),
                        false,
                    ),
                    (
                        "Expires",
                        org::days_until(&generation.expires_at, now)
                            .map(|d| {
                                format!(
                                    "{} · {}",
                                    &generation.expires_at[..10.min(generation.expires_at.len())],
                                    if d < 0 {
                                        "expired".into()
                                    } else {
                                        format!("{d} d")
                                    }
                                )
                            })
                            .unwrap_or_default(),
                        false,
                    ),
                ],
                cx,
            ))
            .child(widgets::separator(cx))
            .child(widgets::inspector_section(
                "CONTENTS",
                vec![
                    ("Profiles", generation.profiles.join(" · "), false),
                    ("Rules", generation.rules.to_string(), false),
                    ("DNS names", generation.dns_names.to_string(), false),
                    ("Hosts on it", generation.hosts.to_string(), false),
                ],
                cx,
            ))
            .child(widgets::separator(cx))
            .child(eyebrow("CHANGES", cx))
            .children(if generation.changes.is_empty() {
                vec![widgets::note(
                    if generation.republish_of != 0 {
                        "Same signed bundle as an earlier generation."
                    } else {
                        "No rule changes."
                    },
                    cx,
                )]
            } else {
                generation
                    .changes
                    .iter()
                    .map(|change| {
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .text_size(px(11.))
                            .child(widgets::chip(
                                &change.effect,
                                effect_color(&change.effect, cx),
                                cx,
                            ))
                            .child(widgets::mono(
                                &format!("{} {}", sign(&change.change), change.summary),
                                cx,
                            ))
                    })
                    .collect()
            })
            .when(generation.number != latest, |d| {
                d.child(widgets::inspector_note(
                    IconName::Undo2,
                    cx.theme().muted_foreground,
                    &format!("Republishing serves this exact bundle as g{}", latest + 1),
                    "Hosts never go back to a used number, and its expiry is kept.",
                    cx,
                ))
            })
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(self.org_button(
                        "org-republish-selected",
                        "Republish…",
                        (generation.number != latest).then(|| {
                            Kind::Confirm(Command::Org(OrgCommand::Republish {
                                generation: generation.number,
                                first_ring: String::new(),
                            }))
                        }),
                        cx,
                    ))
                    .child(self.org_button(
                        "org-download-selected",
                        "Download…",
                        Some(Kind::OrgDownload(generation.number)),
                        cx,
                    )),
            );
        InspectorView {
            header: widgets::inspector_header(
                IconName::BadgeCheck,
                &format!("Generation {}", generation.number),
                Some((&status, color)),
                o.map(|o| text(&o.overview.organization))
                    .unwrap_or_default(),
                cx,
            ),
            body,
            footer: format!("Inspecting generation {}", generation.number),
        }
    }

    // ------------------------------------------------------------ enrollment

    fn enrollment_summary(&self, o: &OrgSnapshot, cx: &App) -> Div {
        let now = clock::now();
        let active: Vec<&Host> = o.active_hosts().collect();
        let expiring = active
            .iter()
            .filter(|h| org::days_until(&h.certificate.not_after, now).is_some_and(|d| d <= 30))
            .count();
        let revoked = o.hosts.len() - active.len();
        let tiles = widgets::tiles([
            widgets::tile(
                "ENROLLED",
                active.len().to_string(),
                format!(
                    "{} profiles · {} rings",
                    o.profiles().len(),
                    o.overview.rings.len()
                ),
                TileAccent::None,
                cx,
            ),
            widgets::tile(
                "EXPIRING",
                expiring.to_string(),
                "certificates within 30 days".into(),
                if expiring > 0 {
                    TileAccent::Tint(cx.theme().warning)
                } else {
                    TileAccent::None
                },
                cx,
            ),
            widgets::tile(
                "REVOKED",
                revoked.to_string(),
                "refused by the feed".into(),
                TileAccent::None,
                cx,
            ),
            widgets::tile(
                "CA EXPIRES",
                org::days_until(&o.overview.ca_expires_at, now)
                    .map(|d| format!("{} days", d))
                    .unwrap_or_else(|| "—".into()),
                o.overview
                    .ca_expires_at
                    .get(..10)
                    .unwrap_or_default()
                    .to_owned(),
                TileAccent::None,
                cx,
            ),
        ]);
        let pin = |icon: IconName, title: String, detail: String| {
            div()
                .flex()
                .items_center()
                .gap_2()
                .flex_1()
                .min_w(px(0.))
                .child(
                    Icon::new(icon)
                        .size(px(16.))
                        .text_color(cx.theme().muted_foreground),
                )
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .min_w(px(0.))
                        .child(widgets::mono(&title, cx))
                        .child(
                            div()
                                .truncate()
                                .text_size(px(10.))
                                .text_color(cx.theme().muted_foreground)
                                .child(detail),
                        ),
                )
        };
        let trust = widgets::card(cx)
            .gap(px(10.))
            .child(widgets::section_title(
                "WHAT EVERY HOST PINS",
                "changing these means enrolling hosts again".into(),
                cx,
            ))
            .child(
                div()
                    .flex()
                    .gap(px(16.))
                    .child(pin(
                        IconName::KeyRound,
                        org::short_fingerprint(&o.overview.public_key_fingerprint),
                        format!("policy signing key · RSA-{}", o.overview.public_key_bits),
                    ))
                    .child(pin(
                        IconName::Lock,
                        org::short_fingerprint(&o.overview.ca_fingerprint),
                        "hosts CA · verifies the service".into(),
                    ))
                    .child(pin(
                        IconName::RadioTower,
                        o.overview.feed_url.clone(),
                        "feed · mTLS long poll".into(),
                    )),
            );
        div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(tiles)
            .child(trust)
    }
}

// ---------------------------------------------------------------- rows

enum Tone {
    Danger,
    Warning,
    Quiet,
}

fn ratio(part: usize, whole: usize) -> f32 {
    if whole == 0 {
        0.
    } else {
        part as f32 / whole as f32
    }
}

fn plural(count: usize, noun: &str) -> String {
    format!("{count} {noun}{}", if count == 1 { "" } else { "s" })
}

fn based_on(base: u64) -> String {
    if base == 0 {
        "first generation".into()
    } else {
        format!("based on g{base}")
    }
}

fn generation_label(generation: u64) -> String {
    if generation == 0 {
        "nothing yet".into()
    } else {
        format!("g{generation}")
    }
}

fn status_style(host: &Host, cx: &App) -> (&'static str, Hsla) {
    let color = match host.status.as_str() {
        "current" => cx.theme().success,
        "stalled" | "rejected" | "mismatch" | "revoked" => cx.theme().danger,
        "offered" | "pending" | "waiting" => cx.theme().warning,
        _ => cx.theme().muted_foreground,
    };
    (org::status_label(host), color)
}

/// What a host's status means and what, if anything, to do about it.
fn status_explanation(
    host: &Host,
    organization: Option<&OrgSnapshot>,
) -> Option<(&'static str, String, Tone)> {
    let report = host.report.as_ref();
    Some(match host.status.as_str() {
        "stalled" => (
            "A sandbox on this host cannot accept its target.",
            format!(
                "The host acknowledges a generation only when every sandbox accepts it. {} It stays stopped and the host retries on each poll; the sandbox and cause are in that host's Audit. Publishing a fix reaches it without waiting.",
                match report.and_then(|r| r.failed) {
                    Some(n) => format!("{n} sandbox{} refused g{}.", if n == 1 { "" } else { "es" }, host.target),
                    None => "Its sandboxes could not be reached.".into(),
                }
            ),
            Tone::Danger,
        ),
        "rejected" => (
            "The host refused the generation it was offered.",
            match report.map(|r| r.rejected_reason.as_str()) {
                Some("verification") => "Its signature or profile did not verify with the key this host pins, or it expired.".into(),
                Some("organization") => "It was signed for another organization.".into(),
                Some("rollback") => "It was older than one the host already has.".into(),
                _ => "The response was invalid for this host.".into(),
            },
            Tone::Danger,
        ),
        "mismatch" => (
            "The applied digest is not the one expected.",
            "The host applied its target with a different profile or public key than it was enrolled with. Check its feed.json.".into(),
            Tone::Warning,
        ),
        "silent" => (
            "No poll for over 10 minutes.",
            "Hosts that are asleep or offline catch up on their next poll. Nothing is lost.".into(),
            Tone::Quiet,
        ),
        "never" => (
            "This host has never polled.",
            "Place its enrollment files beside host-key.pem and start gantry serve -policy-feed feed.json.".into(),
            Tone::Quiet,
        ),
        "offered" | "waiting" => (
            "Waiting for the host's next report.",
            format!(
                "Connected hosts acknowledge within seconds.{}",
                organization
                    .and_then(|o| o.overview.rollout.as_ref())
                    .map(|r| format!(" Generation {} is rolling out.", r.generation))
                    .unwrap_or_default()
            ),
            Tone::Quiet,
        ),
        _ => return None,
    })
}

fn host_row(host: &Host, selected: bool, now: i64, cx: &App) -> Div {
    let (label, color) = status_style(host, cx);
    let seen = host
        .last_seen
        .as_deref()
        .and_then(clock::parse)
        .map(|t| format!("{} ago", clock::age(t, now)));
    let cert_days = org::days_until(&host.certificate.not_after, now);
    row(selected, cx)
        .child(
            Icon::new(IconName::Server)
                .size(px(14.))
                .text_color(cx.theme().muted_foreground),
        )
        .child(
            div()
                .w(px(150.))
                .flex_shrink_0()
                .truncate()
                .child(text(&host.name)),
        )
        .child(div().w(px(96.)).flex_shrink_0().flex().child(widgets::chip(
            &host.profile,
            cx.theme().muted_foreground,
            cx,
        )))
        .child(
            div()
                .w(px(76.))
                .flex_shrink_0()
                .text_size(px(11.))
                .text_color(cx.theme().muted_foreground)
                .child(text(&host.ring)),
        )
        .child(div().flex_1().min_w(px(0.)).flex().child(widgets::pill(
            &if host.target == 0 {
                label.to_string()
            } else {
                format!("{} · {label}", generation_label(host.target))
            },
            color,
            cx,
        )))
        .child(
            div()
                .w(px(70.))
                .flex_shrink_0()
                .text_right()
                .text_size(px(11.))
                .text_color(cx.theme().muted_foreground)
                .child(seen.unwrap_or_else(|| "—".into())),
        )
        .child(
            div()
                .w(px(52.))
                .flex_shrink_0()
                .text_right()
                .text_size(px(11.))
                .text_color(if cert_days.is_some_and(|d| d <= 30) {
                    cx.theme().warning
                } else {
                    cx.theme().muted_foreground
                })
                .child(
                    cert_days
                        .map(|d| format!("{d} d"))
                        .unwrap_or_else(|| "—".into()),
                ),
        )
}

fn rollout_row(host: &Host, selected: bool, now: i64, cx: &App) -> Div {
    let (label, color) = status_style(host, cx);
    let time = |value: &Option<String>| value.as_deref().and_then(clock::parse).map(clock::clock);
    let offered = time(&host.served_at);
    let acknowledged = time(&host.acknowledged_at);
    let _ = now;
    row(selected, cx)
        .child(
            Icon::new(IconName::Server)
                .size(px(14.))
                .text_color(cx.theme().muted_foreground),
        )
        .child(
            div()
                .w(px(150.))
                .flex_shrink_0()
                .truncate()
                .child(text(&host.name)),
        )
        .child(
            widgets::mono(&offered.clone().unwrap_or_else(|| "—".into()), cx)
                .w(px(64.))
                .flex_shrink_0()
                .text_size(px(11.)),
        )
        .child(
            // Offered, then acknowledged: a track that fills as the host reports.
            div()
                .relative()
                .flex()
                .items_center()
                .w(px(120.))
                .flex_shrink_0()
                .h(px(12.))
                .child(div().absolute().left(px(4.)).right(px(4.)).h(px(2.)).bg(
                    if acknowledged.is_some() {
                        cx.theme().success
                    } else {
                        theme::track(cx)
                    },
                ))
                .child(div().absolute().left_0().size(px(8.)).rounded_full().bg(
                    if offered.is_some() {
                        cx.theme().primary
                    } else {
                        theme::track(cx)
                    },
                ))
                .child(div().absolute().right_0().size(px(8.)).rounded_full().bg(
                    if acknowledged.is_some() {
                        cx.theme().success
                    } else {
                        theme::track(cx)
                    },
                )),
        )
        .child(
            widgets::mono(&acknowledged.unwrap_or_else(|| "—".into()), cx)
                .w(px(64.))
                .flex_shrink_0()
                .text_size(px(11.)),
        )
        .child(
            div()
                .flex_1()
                .min_w(px(0.))
                .text_size(px(11.))
                .text_color(cx.theme().muted_foreground)
                .child(format!(
                    "{} poll{}",
                    host.polls_since_served,
                    if host.polls_since_served == 1 {
                        ""
                    } else {
                        "s"
                    }
                )),
        )
        .child(widgets::pill(label, color, cx))
}

fn identity_row(host: &Host, selected: bool, now: i64, cx: &App) -> Div {
    let cert_days = org::days_until(&host.certificate.not_after, now);
    row(selected, cx)
        .child(
            Icon::new(IconName::IdCard)
                .size(px(14.))
                .text_color(cx.theme().muted_foreground),
        )
        .child(
            div()
                .w(px(150.))
                .flex_shrink_0()
                .truncate()
                .when(host.revoked, |d| d.text_color(cx.theme().muted_foreground))
                .child(text(&host.name)),
        )
        .child(div().w(px(96.)).flex_shrink_0().flex().child(widgets::chip(
            &host.profile,
            cx.theme().muted_foreground,
            cx,
        )))
        .child(
            div()
                .w(px(76.))
                .flex_shrink_0()
                .text_size(px(11.))
                .text_color(cx.theme().muted_foreground)
                .child(text(&host.ring)),
        )
        .child(
            widgets::mono(&org::short_fingerprint(&host.certificate.fingerprint), cx)
                .flex_1()
                .text_size(px(11.)),
        )
        .child(if host.revoked {
            widgets::pill("revoked", cx.theme().danger, cx)
        } else {
            widgets::pill(
                &format!(
                    "{} · {}",
                    host.certificate.not_after.get(..10).unwrap_or_default(),
                    cert_days.map(|d| format!("{d} d")).unwrap_or_default()
                ),
                if cert_days.is_some_and(|d| d <= 30) {
                    cx.theme().warning
                } else {
                    cx.theme().muted_foreground
                },
                cx,
            )
        })
}

fn generation_row(
    o: &OrgSnapshot,
    generation: &Generation,
    selected: bool,
    now: i64,
    cx: &App,
) -> Div {
    let (status, color) = generation_status(Some(o), generation, cx);
    let published = clock::parse(&generation.published_at);
    let summary = if generation.changes.is_empty() {
        if generation.republish_of != 0 {
            format!("Republished g{}", generation.republish_of)
        } else {
            "No rule changes".into()
        }
    } else {
        generation
            .changes
            .iter()
            .map(|c| {
                format!(
                    "{} {}",
                    sign(&c.change),
                    if c.id.is_empty() {
                        c.summary.clone()
                    } else {
                        c.id.clone()
                    }
                )
            })
            .collect::<Vec<_>>()
            .join("  ·  ")
    };
    div()
        .flex()
        .items_center()
        .gap(px(12.))
        .min_h(px(50.))
        .px(px(6.))
        .rounded(px(6.))
        .when(selected, |d| d.bg(cx.theme().table_active))
        .child(
            div()
                .relative()
                .flex()
                .items_center()
                .justify_center()
                .w(px(12.))
                .h(px(50.))
                .flex_shrink_0()
                .child(
                    div()
                        .absolute()
                        .top_0()
                        .bottom_0()
                        .left(px(5.))
                        .w(px(2.))
                        .bg(cx.theme().border),
                )
                .child(
                    div()
                        .size(px(12.))
                        .rounded_full()
                        .border_2()
                        .border_color(cx.theme().background)
                        .bg(color),
                ),
        )
        .child(
            widgets::mono(&format!("g{}", generation.number), cx)
                .w(px(44.))
                .flex_shrink_0()
                .font_weight(FontWeight::SEMIBOLD),
        )
        .child(
            div()
                .w(px(70.))
                .flex_shrink_0()
                .flex()
                .flex_col()
                .text_size(px(11.))
                .text_color(cx.theme().muted_foreground)
                .child(
                    generation
                        .published_at
                        .get(5..10)
                        .unwrap_or_default()
                        .to_owned(),
                )
                .when_some(published, |d, t| {
                    d.child(
                        div()
                            .text_size(px(10.))
                            .child(format!("{} ago", clock::age(t, now))),
                    )
                }),
        )
        .child(
            div()
                .w(px(96.))
                .flex_shrink_0()
                .flex()
                .child(widgets::pill(&status, color, cx)),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .min_w(px(0.))
                .gap(px(2.))
                .child(div().truncate().child(text(&summary)))
                .child(
                    div()
                        .truncate()
                        .text_size(px(11.))
                        .text_color(cx.theme().muted_foreground)
                        .child(format!(
                            "rev {} · {}",
                            text(&generation.revision),
                            text(&generation.published_by)
                        )),
                ),
        )
        .child(
            div()
                .w(px(60.))
                .flex_shrink_0()
                .text_right()
                .text_size(px(11.))
                .text_color(cx.theme().muted_foreground)
                .child(if generation.hosts > 0 {
                    format!("{} hosts", generation.hosts)
                } else {
                    String::new()
                }),
        )
}

fn generation_status(o: Option<&OrgSnapshot>, generation: &Generation, cx: &App) -> (String, Hsla) {
    let rolling = o
        .and_then(|o| o.overview.rollout.as_ref())
        .is_some_and(|r| r.generation == generation.number && !r.complete);
    if rolling {
        ("rolling out".into(), cx.theme().primary)
    } else if generation.republish_of != 0 {
        ("rollback".into(), cx.theme().warning)
    } else if generation.hosts > 0 {
        ("serving".into(), cx.theme().success)
    } else {
        ("superseded".into(), cx.theme().muted_foreground)
    }
}

fn item_row(item: &PolicyItem, selected: bool, cx: &App) -> Div {
    let change = match item.change.as_str() {
        "added" => Some(cx.theme().success),
        "changed" => Some(cx.theme().warning),
        "removed" => Some(cx.theme().danger),
        _ => None,
    };
    let muted = item.removed();
    row(selected, cx)
        .child(
            div()
                .w(px(3.))
                .h(px(18.))
                .rounded(px(2.))
                .flex_shrink_0()
                .when_some(change, |d, color| d.bg(color)),
        )
        .child(
            div()
                .w(px(52.))
                .flex_shrink_0()
                .flex()
                .child(widgets::action_chip(&item.effect, cx)),
        )
        .child(widgets::mono(&item.selector, cx).flex_1().when(muted, |d| {
            d.line_through().text_color(cx.theme().muted_foreground)
        }))
        .child(
            widgets::mono(&item.detail, cx)
                .w(px(120.))
                .flex_shrink_0()
                .text_size(px(11.))
                .text_color(cx.theme().muted_foreground),
        )
        .when(item.kind != ItemKind::Dns, |d| {
            d.child(
                div()
                    .w(px(120.))
                    .flex_shrink_0()
                    .flex()
                    .child(widgets::chip(&item.id, cx.theme().muted_foreground, cx)),
            )
        })
        .child(
            div()
                .w(px(60.))
                .flex_shrink_0()
                .text_right()
                .text_size(px(10.))
                .text_color(change.unwrap_or(cx.theme().muted_foreground))
                .child(item.change.clone()),
        )
}

fn change_row(change: &Change, selected: bool, cx: &App) -> Div {
    let color = effect_color(&change.effect, cx);
    row(selected, cx)
        .min_h(px(46.))
        .child(
            Icon::new(change_icon(&change.kind))
                .size(px(14.))
                .text_color(cx.theme().muted_foreground),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .min_w(px(0.))
                .gap(px(2.))
                .child(
                    div()
                        .truncate()
                        .font_weight(FontWeight::MEDIUM)
                        .child(format!(
                            "{} {} · {}",
                            sign(&change.change),
                            change.kind,
                            if change.id.is_empty() {
                                change.summary.clone()
                            } else {
                                change.id.clone()
                            }
                        )),
                )
                .child(
                    widgets::mono(&change.summary, cx)
                        .text_size(px(11.))
                        .text_color(cx.theme().muted_foreground),
                ),
        )
        .child(div().w(px(90.)).flex_shrink_0().flex().child(widgets::chip(
            if change.profile.is_empty() {
                "all profiles"
            } else {
                &change.profile
            },
            cx.theme().muted_foreground,
            cx,
        )))
        .child(widgets::pill(&change.effect, color, cx))
}

/// Hosts acknowledging the rollout generation over time, as a step line
/// against the hosts offered it and all enrolled hosts, with a marker where
/// each later ring was promoted.
fn acknowledgement_chart(o: &OrgSnapshot, cx: &App) -> Option<Div> {
    let series = org::acknowledgements(o, clock::now())?;
    let steps = series
        .steps
        .iter()
        .map(|(time, count)| (series.x(*time), series.y(*count)))
        .collect();
    let mut guides = vec![1.0];
    if series.offered < series.total {
        guides.push(series.y(series.offered));
    }
    let markers = series
        .promotions
        .iter()
        .map(|(time, _)| series.x(*time))
        .collect();
    let muted = cx.theme().muted_foreground;
    let label = |text: String| div().text_size(px(10.)).text_color(muted).child(text);
    let plot = div()
        .id("org-ack-chart")
        .test_support()
        .relative()
        .h(px(96.))
        .w_full()
        .child(
            charts::step_chart(steps, guides, markers, theme::bar(cx), muted.opacity(0.55))
                .size_full(),
        )
        .children(series.promotions.iter().map(|(time, ring)| {
            label(format!("{} promoted", text(ring)))
                .absolute()
                .top(px(2.))
                .left(gpui_kit::relative(series.x(*time)))
                .ml(px(5.))
        }))
        .when(series.offered < series.total, |d| {
            d.child(
                label(format!("{} offered", series.offered))
                    .absolute()
                    .right(px(4.))
                    .top(gpui_kit::relative(1.0 - series.y(series.offered)))
                    .mt(px(-14.)),
            )
        });
    let ticks = div().flex().justify_between().children((0..5).map(|i| {
        let time = series.start + (series.end - series.start) * i / 4;
        label(clock::clock(time)[..5].to_owned())
    }));
    let acknowledged = series.steps.last().map(|(_, count)| *count).unwrap_or(0);
    Some(
        div()
            .flex()
            .flex_col()
            .gap(px(6.))
            .child(widgets::section_title(
                "HOSTS ACKNOWLEDGED",
                format!(
                    "g{} · {acknowledged} of {} offered · {} enrolled",
                    series.generation, series.offered, series.total
                ),
                cx,
            ))
            .child(plot)
            .child(ticks),
    )
}

/// The draft's data.json against its base: changed parts expanded, the rest
/// collapsed, additions and removals marked in the gutter.
fn diff_card(lines: &[org::DiffLine], base: u64, cx: &App) -> impl IntoElement {
    let added = lines.iter().filter(|l| l.mark == org::Mark::Added).count();
    let removed = lines
        .iter()
        .filter(|l| l.mark == org::Mark::Removed)
        .count();
    widgets::card(cx)
        .id("org-diff")
        .test_support()
        .p_0()
        .overflow_hidden()
        .child(
            div()
                .flex()
                .items_center()
                .gap_2()
                .px(px(12.))
                .py(px(8.))
                .border_b_1()
                .border_color(theme::card_border(cx))
                .text_size(px(11.))
                .child(
                    div()
                        .flex_1()
                        .text_color(cx.theme().muted_foreground)
                        .child(if base == 0 {
                            "data.json · first generation".to_string()
                        } else {
                            format!("data.json · compared with signed g{base}")
                        }),
                )
                .child(
                    div()
                        .text_color(cx.theme().success)
                        .child(format!("+{added}")),
                )
                .child(
                    div()
                        .text_color(cx.theme().danger)
                        .child(format!("−{removed}")),
                ),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .py(px(6.))
                .font_family(cx.theme().mono_font_family.clone())
                .text_size(px(11.))
                .children(lines.iter().map(|line| {
                    let (sign, color, tint) = match line.mark {
                        org::Mark::Added => (
                            "+",
                            cx.theme().success,
                            Some(theme::tint(cx.theme().success, cx)),
                        ),
                        org::Mark::Removed => (
                            "−",
                            cx.theme().danger,
                            Some(theme::tint(cx.theme().danger, cx)),
                        ),
                        org::Mark::Same => (" ", cx.theme().muted_foreground, None),
                    };
                    div()
                        .flex()
                        .min_h(px(17.))
                        .when_some(tint, |d, tint| d.bg(tint))
                        .child(
                            div()
                                .w(px(22.))
                                .flex_shrink_0()
                                .text_center()
                                .text_color(color)
                                .child(sign),
                        )
                        .child(
                            div()
                                .pl(px(line.depth as f32 * 14.))
                                .min_w(px(0.))
                                .truncate()
                                .text_color(if line.mark == org::Mark::Same {
                                    cx.theme().muted_foreground
                                } else {
                                    color
                                })
                                .child(text(&line.text)),
                        )
                })),
        )
}

fn row(selected: bool, cx: &App) -> Div {
    div()
        .flex()
        .items_center()
        .gap(px(12.))
        .min_h(px(34.))
        .px(px(8.))
        .rounded(px(6.))
        .text_size(px(12.))
        .when(selected, |d| d.bg(cx.theme().table_active))
}

/// One square per host, grouped by ring and coloured by status.
fn ring_strip(o: &OrgSnapshot, cx: &App) -> Div {
    let counts = |ring: &str| o.active_hosts().filter(|h| h.ring == ring).count();
    div()
        .flex()
        .flex_col()
        .gap(px(6.))
        .child(widgets::section_title(
            "HOSTS BY RING",
            format!(
                "{} current · {} behind · {} attention · {} silent",
                o.active_hosts().filter(|h| h.status == "current").count(),
                o.active_hosts().filter(|h| org::behind(h)).count(),
                o.active_hosts().filter(|h| org::needs_attention(h)).count(),
                o.active_hosts().filter(|h| org::silent(h)).count()
            ),
            cx,
        ))
        .child(
            div()
                .flex()
                .flex_wrap()
                .gap(px(18.))
                .children(o.overview.rings.iter().map(|ring| {
                    div()
                        .flex()
                        .flex_col()
                        .gap(px(4.))
                        .child(
                            div()
                                .flex()
                                .flex_wrap()
                                .gap(px(4.))
                                .min_h(px(14.))
                                .children(o.active_hosts().filter(|h| h.ring == ring.name).map(
                                    |host| {
                                        div()
                                            .w(px(22.))
                                            .h(px(14.))
                                            .rounded(px(3.))
                                            .bg(status_style(host, cx).1)
                                    },
                                )),
                        )
                        .child(
                            div()
                                .text_size(px(11.))
                                .text_color(cx.theme().muted_foreground)
                                .child(format!(
                                    "{} · {} · {}",
                                    text(&ring.name),
                                    counts(&ring.name),
                                    generation_label(ring.generation)
                                )),
                        )
                })),
        )
}

fn effect_color(effect: &str, cx: &App) -> Hsla {
    match effect {
        "loosens" => cx.theme().warning,
        "tightens" => cx.theme().primary,
        _ => cx.theme().muted_foreground,
    }
}

fn effect_words(effect: &str) -> &'static str {
    match effect {
        "loosens" => "loosens access",
        "tightens" => "tightens access",
        _ => "leaves access unchanged",
    }
}

fn sign(change: &str) -> &'static str {
    match change {
        "added" => "+",
        "removed" => "−",
        _ => "~",
    }
}

fn item_icon(kind: &ItemKind) -> IconName {
    match kind {
        ItemKind::Network | ItemKind::Dns => IconName::ArrowLeftRight,
        ItemKind::Mount => IconName::Folder,
        ItemKind::Mcp => IconName::Plug,
        ItemKind::Credential => IconName::Key,
    }
}

fn change_icon(kind: &str) -> IconName {
    match kind {
        "network" | "dns" => IconName::ArrowLeftRight,
        "profile" => IconName::FileText,
        "expiry" => IconName::Clock,
        _ => IconName::ShieldCheck,
    }
}
