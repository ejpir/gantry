//! Network Rules: each sandbox's policy at a glance, then its rules in
//! evaluation order. Organization rules are visibly read-only.

use crate::{
    app::*,
    screens::InspectorView,
    widgets::{self, TileAccent},
};
use gantry_desktop::{
    dashboard_wire::Rule,
    summary::{self, RuleOrigin, SandboxPolicy},
    telemetry::bytes_label,
    workspace::text,
};
use gpui_kit::assets::IconName;
use gpui_kit::component::{ActiveTheme, Disableable, Icon, Sizable, button::Button};
use gpui_kit::{
    App, Context, Div, FontWeight, Hsla, InteractiveElement, ParentElement, Styled, TestSupportExt,
    div, prelude::FluentBuilder, px,
};

impl Desktop {
    pub fn rules_status(&self) -> String {
        let summary = summary::rules(&self.host);
        match summary.organizations.as_slice() {
            [] => "Policies set per sandbox".into(),
            names => format!("Organization policy · {}", names.join(", ")),
        }
    }

    pub fn rules_summary(&self, cx: &mut Context<Self>) -> Div {
        let summary = summary::rules(&self.host);
        let sandboxes = summary.sandboxes.len();
        let deny = summary.default_deny();
        let tiles = widgets::tiles([
            widgets::tile(
                "RULES",
                summary.rules.to_string(),
                format!("{} allow · {} deny", summary.allow, summary.deny),
                TileAccent::None,
                cx,
            ),
            widgets::tile(
                "DEFAULT DENY",
                format!("{deny} of {sandboxes}"),
                "unlisted egress is blocked".into(),
                TileAccent::Ratio(
                    if sandboxes == 0 {
                        0.
                    } else {
                        deny as f32 / sandboxes as f32
                    },
                    cx.theme().danger,
                ),
                cx,
            ),
            widgets::tile(
                "ORGANIZATION",
                summary.organization.to_string(),
                if summary.organization == 0 {
                    "no organization policy".into()
                } else {
                    "managed · read-only here".into()
                },
                TileAccent::None,
                cx,
            ),
            widgets::tile(
                "ERRORS",
                summary.errors.to_string(),
                if summary.errors == 0 {
                    "every policy loaded".into()
                } else {
                    "a policy failed to load".into()
                },
                if summary.errors > 0 {
                    TileAccent::Tint(cx.theme().danger)
                } else {
                    TileAccent::None
                },
                cx,
            ),
        ]);
        div()
            .flex()
            .flex_col()
            .gap(px(10.))
            .px_4()
            .pt(px(12.))
            .pb(px(14.))
            .child(tiles)
            .when(!summary.sandboxes.is_empty(), |d| {
                d.child(widgets::section_title(
                    "POLICIES",
                    "default for unlisted public destinations".into(),
                    cx,
                ))
                .child(div().flex().flex_wrap().gap(px(10.)).children(
                    summary.sandboxes.iter().enumerate().map(|(i, policy)| {
                        policy_card(policy, cx)
                            .id(("policy-card", i))
                            .test_support()
                    }),
                ))
            })
    }

    pub fn rule_inspector(&self, rule: &Rule, cx: &mut Context<Self>) -> InspectorView {
        let origin = RuleOrigin::of(rule);
        let color = action_color(&rule.action, cx);
        let ports = if rule.ports.is_empty() {
            "all".into()
        } else {
            rule.ports.clone()
        };
        let mut details = vec![
            ("Action", capitalized(&rule.action), false),
            ("Target", rule.target.clone(), true),
            ("Protocol", rule.proto.to_uppercase(), false),
            ("Ports", ports, false),
            ("Source", origin.label(), false),
        ];
        if !rule.policy.is_empty() {
            details.push(("Policy", rule.policy.clone(), true));
        }
        let matching: Vec<_> = self
            .host
            .snapshot
            .traffic
            .iter()
            .filter(|flow| summary::rule_covers(rule, flow))
            .collect();
        let editable = origin.editable();
        let body = div()
            .flex()
            .flex_col()
            .gap(px(14.))
            .child(widgets::inspector_section("RULE", details, cx))
            .child(widgets::separator(cx))
            .when_some(
                match &origin {
                    RuleOrigin::Organization { organization, rule } => {
                        Some((organization.clone(), rule.clone()))
                    }
                    _ => None,
                },
                |d, (organization, id)| {
                    d.child(widgets::inspector_section(
                        "ORGANIZATION",
                        vec![
                            ("Organization", organization, false),
                            (
                                "Rule",
                                if id.is_empty() { "—".into() } else { id },
                                true,
                            ),
                        ],
                        cx,
                    ))
                    .child(widgets::inspector_note(
                        IconName::ShieldCheck,
                        cx.theme().warning,
                        "Managed by your organization.",
                        "Organization policy is authoritative and read-only on this desktop.",
                        cx,
                    ))
                    .child(widgets::separator(cx))
                },
            )
            .when(!matching.is_empty(), |d| {
                d.child(widgets::inspector_section(
                    "MATCHING TRAFFIC",
                    matching
                        .iter()
                        .take(4)
                        .map(|flow| {
                            (
                                if flow.host.is_empty() {
                                    flow.address.as_str()
                                } else {
                                    flow.host.as_str()
                                },
                                format!(
                                    "{} · {}",
                                    bytes_label(flow.tx_bytes.saturating_add(flow.rx_bytes)),
                                    if flow.allowed { "allowed" } else { "denied" }
                                ),
                                false,
                            )
                        })
                        .collect(),
                    cx,
                ))
                .child(widgets::separator(cx))
            })
            .when(!editable && !matches!(origin, RuleOrigin::Organization { .. }), |d| {
                d.child(widgets::inspector_note(
                    IconName::Info,
                    cx.theme().muted_foreground,
                    "Always present.",
                    "Built-in, default, and proxy rows follow the sandbox's configuration. Change the network policy instead.",
                    cx,
                ))
            })
            .child(
                div().flex().flex_wrap().gap_2().child(
                    Button::new("inspector-remove-rule")
                        .small()
                        .label("Remove rule…")
                        .when(editable && self.can_write(), |b| {
                            b.text_color(cx.theme().danger)
                        })
                        .disabled(!editable || !self.can_write())
                        .on_click(cx.listener(|this, _, window, cx| {
                            this.remove_selected(window, cx)
                        })),
                ),
            );
        InspectorView {
            header: widgets::inspector_header(
                IconName::ShieldCheck,
                &rule.target,
                Some((
                    &format!("{} · {}", capitalized(&rule.action), rule.sandbox),
                    color,
                )),
                self.source_name(),
                cx,
            ),
            body,
            footer: format!(
                "Inspecting a rule of {} on {}",
                rule.sandbox,
                self.source_name()
            ),
        }
    }
}

fn action_color(action: &str, cx: &App) -> Hsla {
    match action {
        "allow" => cx.theme().success,
        "deny" | "error" => cx.theme().danger,
        "resolve" => cx.theme().primary,
        _ => cx.theme().muted_foreground,
    }
}

fn capitalized(value: &str) -> String {
    let mut chars = value.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

fn policy_card(policy: &SandboxPolicy, cx: &App) -> Div {
    let (label, color) = match policy.default.as_str() {
        "deny" => ("default deny", cx.theme().danger),
        "allow" => ("default allow", cx.theme().success),
        "off" => ("network off", cx.theme().muted_foreground),
        "gvproxy" => ("external gvproxy", cx.theme().primary),
        "error" => ("policy error", cx.theme().danger),
        _ => ("unknown", cx.theme().muted_foreground),
    };
    let file = policy
        .policy
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("no policy file");
    widgets::card(cx)
        .flex_1()
        .min_w(px(170.))
        .gap(px(6.))
        .py(px(9.))
        .child(
            div()
                .flex()
                .items_center()
                .gap(px(7.))
                .child(
                    Icon::new(IconName::Box)
                        .size(px(13.))
                        .text_color(cx.theme().muted_foreground),
                )
                .child(
                    div()
                        .flex_1()
                        .min_w(px(0.))
                        .truncate()
                        .text_size(px(12.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(text(&policy.sandbox)),
                )
                .child(widgets::pill(label, color, cx)),
        )
        .child(
            div()
                .truncate()
                .text_size(px(10.))
                .text_color(cx.theme().muted_foreground)
                .child(format!(
                    "{} rule{} · {}{}",
                    policy.rules,
                    if policy.rules == 1 { "" } else { "s" },
                    text(file),
                    if policy.organization > 0 {
                        format!(" · {} org", policy.organization)
                    } else {
                        String::new()
                    }
                )),
        )
}
