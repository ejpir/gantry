//! Audit: a timeline of decisions. Allow and deny on one rail, with the action,
//! reason, and rule for each, the recorded time, and repeats counted.

use crate::{
    app::*,
    dashboard_table::sandbox_slots,
    screens::InspectorView,
    theme,
    widgets::{self, TileAccent},
};
use gantry_desktop::{
    clock,
    dashboard_wire::AuditEvent,
    summary,
    workspace::{Page, Record, text},
};
use gpui_kit::assets::IconName;
use gpui_kit::component::{ActiveTheme, Sizable, button::Button};
use gpui_kit::{
    App, ClipboardItem, Context, Div, FontWeight, Hsla, InteractiveElement, ParentElement, Styled,
    TestSupportExt, div, prelude::FluentBuilder, px,
};
use std::collections::HashMap;

impl Desktop {
    pub fn audit_status(&self) -> String {
        match summary::audit(&self.host).policy {
            Some((organization, revision, _)) => {
                format!("Organization {organization} · policy {revision}")
            }
            None => "No organization policy in the trail".into(),
        }
    }

    pub fn audit_summary(&self, cx: &mut Context<Self>) -> Div {
        let summary = summary::audit(&self.host);
        let decided = summary.allowed + summary.denied;
        let tiles = widgets::tiles([
            widgets::tile(
                "EVENTS",
                summary.events.to_string(),
                format!(
                    "from {} sandbox{}",
                    summary.sandboxes,
                    if summary.sandboxes == 1 { "" } else { "es" }
                ),
                TileAccent::None,
                cx,
            ),
            widgets::tile(
                "DENIED",
                summary.denied.to_string(),
                if decided == 0 {
                    "no policy decisions".into()
                } else {
                    format!(
                        "{:.0}% of decisions",
                        summary.denied as f32 * 100. / decided as f32
                    )
                },
                TileAccent::Ratio(
                    if decided == 0 {
                        0.
                    } else {
                        summary.denied as f32 / decided as f32
                    },
                    cx.theme().danger,
                ),
                cx,
            ),
            match &summary.top_deny_rule {
                Some((rule, count)) => widgets::tile(
                    "TOP DENY RULE",
                    format!("×{count}"),
                    rule.clone(),
                    TileAccent::Tint(cx.theme().danger),
                    cx,
                ),
                None => widgets::tile(
                    "TOP DENY RULE",
                    "—".into(),
                    "no denials by rule".into(),
                    TileAccent::None,
                    cx,
                ),
            },
            match &summary.policy {
                Some((organization, revision, profile)) => widgets::tile(
                    "POLICY",
                    revision.clone(),
                    if profile.is_empty() {
                        organization.clone()
                    } else {
                        format!("{organization} · profile {profile}")
                    },
                    TileAccent::None,
                    cx,
                ),
                None => widgets::tile(
                    "POLICY",
                    "—".into(),
                    "no organization policy".into(),
                    TileAccent::None,
                    cx,
                ),
            },
        ]);
        div().px_4().pt(px(12.)).pb(px(14.)).child(tiles)
    }

    pub fn audit_list(&self, cx: &mut Context<Self>) -> Div {
        let state = &self.pages[Page::Audit.index()];
        let rows = state.table.read(cx).delegate().rows.clone();
        if rows.is_empty() {
            return widgets::note("No audit events recorded.", cx).px_4();
        }
        let mut repeats: HashMap<&str, usize> = HashMap::new();
        for event in &self.host.snapshot.audit {
            *repeats.entry(event.line.as_str()).or_default() += 1;
        }
        let slots = sandbox_slots(&self.host);
        let now = clock::now();
        div()
            .flex()
            .flex_col()
            .px_4()
            .pb(px(14.))
            .children(rows.iter().enumerate().filter_map(|(index, row)| {
                let Record::Audit(event) = &row.record else {
                    return None;
                };
                let selected = state.selected.as_deref() == Some(row.key.as_str());
                let key = row.key.clone();
                let repeat = repeats.get(event.line.as_str()).copied().unwrap_or(1);
                let slot = slots.get(&event.sandbox).copied().unwrap_or(0);
                Some(
                    event_row(event, selected, repeat, slot, now, cx)
                        .id(("audit-event", index))
                        .test_support()
                        .cursor_pointer()
                        .on_mouse_down(
                            gpui_kit::MouseButton::Left,
                            cx.listener(move |this, _, _, cx| {
                                this.select_page_row(key.clone(), cx)
                            }),
                        ),
                )
            }))
    }

    pub fn audit_inspector(&self, event: &AuditEvent, cx: &mut Context<Self>) -> InspectorView {
        let (label, color) = effect(event, cx);
        let when = clock::parse(&event.time)
            .map(|then| {
                format!(
                    "{} UTC · {} ago",
                    clock::clock(then),
                    clock::age(then, clock::now())
                )
            })
            .unwrap_or_else(|| "not recorded".into());
        let line = event.line.clone();
        let mut body = div().flex().flex_col().gap(px(14.));
        body = match &event.decision {
            Some(decision) => body
                .child(widgets::inspector_section(
                    "DECISION",
                    vec![
                        ("Effect", decision.effect.clone(), false),
                        ("Action", decision.action.clone(), true),
                        ("Reason", decision.reason.replace('_', " "), false),
                        (
                            "Rules",
                            if decision.rules.is_empty() {
                                "none matched".into()
                            } else {
                                decision.rules.join(", ")
                            },
                            true,
                        ),
                        ("Recorded", when, false),
                    ],
                    cx,
                ))
                .child(widgets::separator(cx))
                .when(!decision.organization.is_empty(), |d| {
                    d.child(widgets::inspector_section(
                        "POLICY",
                        vec![
                            ("Organization", decision.organization.clone(), false),
                            ("Revision", decision.revision.clone(), true),
                            (
                                "Profile",
                                if decision.profile.is_empty() {
                                    "—".into()
                                } else {
                                    decision.profile.clone()
                                },
                                false,
                            ),
                        ],
                        cx,
                    ))
                    .child(widgets::separator(cx))
                }),
            None => body
                .child(widgets::inspector_section(
                    "EVENT",
                    vec![
                        ("Sandbox", event.sandbox.clone(), false),
                        ("Recorded", when, false),
                    ],
                    cx,
                ))
                .child(widgets::separator(cx)),
        };
        body = body
            .when(!event.error.is_empty(), |d| {
                d.child(widgets::inspector_note(
                    IconName::CircleAlert,
                    cx.theme().danger,
                    "The audit trail could not be read.",
                    &text(&event.error),
                    cx,
                ))
            })
            .when(!event.line.is_empty(), |d| {
                d.child(crate::views::eyebrow("RAW EVENT", cx)).child(
                    div()
                        .id("audit-raw")
                        .test_support()
                        .p(px(10.))
                        .rounded(px(6.))
                        .bg(cx.theme().background)
                        .border_1()
                        .border_color(cx.theme().border)
                        .font_family(cx.theme().mono_font_family.clone())
                        .text_size(px(11.))
                        .child(text(&event.line)),
                )
            })
            .child(
                div().flex().child(
                    Button::new("audit-copy")
                        .small()
                        .label("Copy Event")
                        .on_click(move |_, _, cx| {
                            cx.write_to_clipboard(ClipboardItem::new_string(line.clone()))
                        }),
                ),
            );
        InspectorView {
            header: widgets::inspector_header(
                IconName::ClipboardList,
                &event
                    .decision
                    .as_ref()
                    .map(|d| d.action.clone())
                    .unwrap_or_else(|| "Audit event".into()),
                Some((&format!("{label} · {}", event.sandbox), color)),
                self.source_name(),
                cx,
            ),
            body,
            footer: format!(
                "Inspecting an audit event from {} on {}",
                event.sandbox,
                self.source_name()
            ),
        }
    }
}

fn effect(event: &AuditEvent, cx: &App) -> (&'static str, Hsla) {
    if !event.error.is_empty() {
        return ("Error", cx.theme().danger);
    }
    match event.decision.as_ref().map(|d| d.effect.as_str()) {
        Some("allow") => ("Allow", cx.theme().success),
        Some("deny") => ("Deny", cx.theme().danger),
        _ => ("Event", cx.theme().muted_foreground),
    }
}

fn event_row(
    event: &AuditEvent,
    selected: bool,
    repeat: usize,
    slot: usize,
    now: i64,
    cx: &App,
) -> Div {
    let (label, color) = effect(event, cx);
    let time = clock::parse(&event.time);
    let (title, detail) = match &event.decision {
        Some(decision) => (
            decision.action.clone(),
            match (decision.reason.as_str(), decision.rules.as_slice()) {
                (reason, []) => reason.replace('_', " "),
                (reason, rules) => format!("{} · {}", reason.replace('_', " "), rules.join(", ")),
            },
        ),
        None if !event.error.is_empty() => ("audit unavailable".into(), event.error.clone()),
        None => (event.line.clone(), String::new()),
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
            // Each row draws its piece of the rail, with the marker on top.
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
            div()
                .w(px(62.))
                .flex_shrink_0()
                .flex()
                .flex_col()
                .font_family(cx.theme().mono_font_family.clone())
                .text_size(px(11.))
                .text_color(cx.theme().muted_foreground)
                .child(time.map(clock::clock).unwrap_or_else(|| "—".into()))
                .when_some(time, |d, then| {
                    d.child(
                        div()
                            .text_size(px(10.))
                            .child(format!("{} ago", clock::age(then, now))),
                    )
                }),
        )
        .child(div().w(px(52.)).flex_shrink_0().child(widgets::chip(
            &label.to_uppercase(),
            color,
            cx,
        )))
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .min_w(px(0.))
                .gap(px(2.))
                .child(widgets::mono(&title, cx).font_weight(FontWeight::MEDIUM))
                .when(!detail.is_empty(), |d| {
                    d.child(
                        div()
                            .truncate()
                            .text_size(px(11.))
                            .text_color(cx.theme().muted_foreground)
                            .child(text(&detail)),
                    )
                }),
        )
        .child(
            div()
                .flex()
                .items_center()
                .gap(px(6.))
                .w(px(96.))
                .flex_shrink_0()
                .text_size(px(11.))
                .child(
                    div()
                        .size(px(7.))
                        .rounded_full()
                        .bg(theme::series(cx, slot)),
                )
                .child(div().truncate().child(text(&event.sandbox))),
        )
        .child(
            div()
                .w(px(34.))
                .flex_shrink_0()
                .text_right()
                .text_size(px(11.))
                .text_color(cx.theme().muted_foreground)
                .when(repeat > 1, |d| d.child(format!("×{repeat}"))),
        )
}
