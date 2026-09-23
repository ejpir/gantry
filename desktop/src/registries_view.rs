//! Registries: accounts, not rows. One card per registry the manager knows,
//! with the login it pulls as, where that login comes from, and the cached
//! images it serves. Secrets are reported as stored, never shown.

use crate::{
    app::*,
    screens::InspectorView,
    theme,
    widgets::{self, TileAccent},
};
use gantry_desktop::{
    dashboard_wire::RegistryAuth,
    forms::Kind,
    summary::{self, CredentialSource, credential_helper, registry_images, registry_user},
    telemetry::bytes_label,
    workspace::{self, Page, Record, text},
};
use gpui_kit::assets::IconName;
use gpui_kit::component::{ActiveTheme, Disableable, Icon, Sizable, button::Button};
use gpui_kit::{
    App, Context, Div, FontWeight, Hsla, InteractiveElement, ParentElement, Styled, TestSupportExt,
    div, prelude::FluentBuilder, px,
};

impl Desktop {
    pub fn registries_summary(&self, cx: &mut Context<Self>) -> Div {
        let summary = summary::registries(&self.host);
        let breakdown = summary
            .by_registry
            .iter()
            .take(2)
            .map(|(registry, count)| format!("{registry} {count}"))
            .collect::<Vec<_>>()
            .join(" · ");
        let tiles = widgets::tiles([
            widgets::tile(
                "REGISTRIES",
                summary.registries.to_string(),
                format!("{} with a login", summary.logged_in),
                TileAccent::None,
                cx,
            ),
            widgets::tile(
                "LOGGED IN",
                format!("{} of {}", summary.logged_in, summary.registries),
                "secrets never shown here".into(),
                TileAccent::Ratio(
                    if summary.registries == 0 {
                        0.
                    } else {
                        summary.logged_in as f32 / summary.registries as f32
                    },
                    cx.theme().success,
                ),
                cx,
            ),
            widgets::tile(
                "CACHED IMAGES",
                summary.images.to_string(),
                if breakdown.is_empty() {
                    "none pulled yet".into()
                } else {
                    breakdown
                },
                TileAccent::None,
                cx,
            ),
            widgets::tile(
                "OUTSIDE GANTRY",
                summary.external.to_string(),
                "Docker, Podman or env".into(),
                TileAccent::None,
                cx,
            ),
        ]);
        div().px_4().pt(px(12.)).pb(px(14.)).child(tiles)
    }

    pub fn registries_list(&self, cx: &mut Context<Self>) -> Div {
        let state = &self.pages[Page::Images.index()];
        let rows = state.table.read(cx).delegate().rows.clone();
        let mut list = div().flex().flex_col().gap(px(8.)).px_4().pb(px(14.));
        if rows.is_empty() {
            list = list.child(widgets::note("No registries match.", cx));
        }
        list = list.children(rows.iter().enumerate().filter_map(|(index, row)| {
            let Record::Registry(registry) = &row.record else {
                return None;
            };
            let selected = state.selected.as_deref() == Some(row.key.as_str());
            let images = registry_images(&self.host, &registry.registry).len();
            let key = row.key.clone();
            Some(
                registry_card(registry, selected, images, cx)
                    .id(("registry-card", index))
                    .test_support()
                    .cursor_pointer()
                    .on_mouse_down(
                        gpui_kit::MouseButton::Left,
                        cx.listener(move |this, _, _, cx| this.select_page_row(key.clone(), cx)),
                    ),
            )
        }));
        let can_add = self.can_write();
        list.child(
            div()
                .id("registry-login-zone")
                .test_support()
                .mt(px(8.))
                .flex()
                .items_center()
                .gap(px(14.))
                .px(px(18.))
                .py(px(14.))
                .rounded(px(8.))
                .border_1()
                .border_dashed()
                .border_color(cx.theme().border)
                .when(can_add, |d| {
                    d.cursor_pointer().on_mouse_down(
                        gpui_kit::MouseButton::Left,
                        cx.listener(|this, _, window, cx| {
                            this.open_form(Kind::Registry(None), window, cx)
                        }),
                    )
                })
                .child(
                    Icon::new(IconName::PanelsTopLeft)
                        .size(px(22.))
                        .text_color(cx.theme().muted_foreground),
                )
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .flex_1()
                        .min_w(px(0.))
                        .gap(px(3.))
                        .child(
                            div()
                                .text_size(px(13.))
                                .font_weight(FontWeight::MEDIUM)
                                .child("Log in to a registry…"),
                        )
                        .child(
                            div()
                                .text_size(px(11.))
                                .text_color(cx.theme().muted_foreground)
                                .child(
                                    "The password or token goes to the manager and is never shown again. Pulls authenticate there; credentials never enter a sandbox.",
                                ),
                        ),
                ),
        )
    }

    pub fn registry_inspector(
        &self,
        registry: &RegistryAuth,
        cx: &mut Context<Self>,
    ) -> InspectorView {
        let source = CredentialSource::of(registry);
        let user = registry_user(registry);
        let host = registry.registry.clone();
        let (status, color) = if registry.has_secret {
            (format!("Logged in · {user}"), cx.theme().success)
        } else {
            ("Anonymous".to_owned(), cx.theme().muted_foreground)
        };
        let mut login = vec![
            ("Registry", host.clone(), true),
            ("Username", user.clone(), false),
            ("Source", source.label().to_owned(), false),
        ];
        if registry.has_secret {
            login.push(("Resolved from", registry.source.clone(), true));
        }
        login.push((
            "Secret",
            if registry.has_secret {
                "Stored · hidden"
            } else {
                "None"
            }
            .to_owned(),
            false,
        ));
        let (icon, tone, title, detail) = source_note(registry, source, cx);
        let images = registry_images(&self.host, &host);
        let body = div()
            .flex()
            .flex_col()
            .gap(px(14.))
            .child(widgets::inspector_section("LOGIN", login, cx))
            .child(widgets::separator(cx))
            .child(widgets::inspector_note(icon, tone, &title, &detail, cx))
            .child(widgets::inspector_note(
                IconName::ShieldCheck,
                cx.theme().success,
                "Credentials stay on the manager.",
                "Pulls authenticate there. The secret never enters a sandbox, and the manager never sends it back to this desktop.",
                cx,
            ))
            .child(widgets::separator(cx))
            .child(crate::views::eyebrow("IMAGES FROM THIS REGISTRY", cx))
            .child(if images.is_empty() {
                widgets::note(&format!("No cached images from {host}."), cx)
            } else {
                div()
                    .flex()
                    .flex_col()
                    .gap(px(4.))
                    .children(images.iter().enumerate().map(|(index, image)| {
                        let reference = image.r#ref.clone();
                        let digest = image.digest.clone();
                        div()
                            .id(("registry-image", index))
                            .test_support()
                            .flex()
                            .items_center()
                            .gap(px(8.))
                            .px(px(8.))
                            .py(px(5.))
                            .rounded(px(5.))
                            .cursor_pointer()
                            .hover(|d| d.bg(cx.theme().table_active))
                            .on_mouse_down(
                                gpui_kit::MouseButton::Left,
                                cx.listener(move |this, _, _, cx| {
                                    this.show_image(&reference, &digest, cx)
                                }),
                            )
                            .child(
                                Icon::new(IconName::Layers)
                                    .size(px(13.))
                                    .text_color(cx.theme().muted_foreground),
                            )
                            .child(widgets::mono(&image.r#ref, cx).flex_1())
                            .child(
                                div()
                                    .flex_shrink_0()
                                    .text_size(px(11.))
                                    .text_color(cx.theme().muted_foreground)
                                    .child(bytes_label(image.size.max(0) as u64)),
                            )
                    }))
            })
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .child(self.form_button(
                        "registry-login-again",
                        if registry.has_secret {
                            "Log In Again…"
                        } else {
                            "Log In…"
                        },
                        Kind::Registry(Some(registry.clone())),
                        cx,
                    ))
                    .child(
                        Button::new("registry-logout")
                            .small()
                            .label("Log Out…")
                            .when(self.can_write() && source.removable(), |b| {
                                b.text_color(cx.theme().danger)
                            })
                            // The manager erases only its own store and the
                            // configured helper; other logins would survive.
                            .disabled(!self.can_write() || !source.removable())
                            .on_click(
                                cx.listener(|this, _, window, cx| this.remove_selected(window, cx)),
                            ),
                    ),
            );
        InspectorView {
            header: widgets::inspector_header(
                IconName::PanelsTopLeft,
                &host,
                Some((&status, color)),
                self.source_name(),
                cx,
            ),
            body,
            footer: format!("Inspecting a registry login on {}", self.source_name()),
        }
    }

    /// Open Local Images with one image selected.
    pub fn show_image(&mut self, reference: &str, digest: &str, cx: &mut Context<Self>) {
        self.set_images_registries(false, cx);
        let key = workspace::rows(Page::Images, &self.host, &self.profiles, &self.packets)
            .into_iter()
            .find(|row| {
                matches!(&row.record, Record::Image(image)
                    if image.r#ref == reference && image.digest == digest)
            })
            .map(|row| row.key);
        let state = &mut self.pages[Page::Images.index()];
        state.selected = key;
        state.selection_initialized = true;
        self.sync_pages(cx);
    }
}

/// What logging out would do, given where the login comes from.
fn source_note(
    registry: &RegistryAuth,
    source: CredentialSource,
    cx: &App,
) -> (IconName, Hsla, String, String) {
    let host = &registry.registry;
    match source {
        CredentialSource::Anonymous => (
            IconName::Info,
            cx.theme().muted_foreground,
            "Pulls are anonymous.".into(),
            format!("Log in to pull private images from {host}."),
        ),
        CredentialSource::Gantry => (
            IconName::KeyRound,
            cx.theme().primary,
            "Saved by a Gantry login.".into(),
            "Log Out erases it from the manager.".into(),
        ),
        CredentialSource::Helper => (
            IconName::Waypoints,
            cx.theme().warning,
            "Shared with Docker.".into(),
            format!(
                "Held by {} on the manager. Log Out erases it there, so Docker loses this login too.",
                credential_helper(&registry.source)
                    .map(|helper| format!("docker-credential-{helper}"))
                    .unwrap_or_else(|| "Docker's credential helper".into())
            ),
        ),
        CredentialSource::Docker => (
            IconName::Info,
            cx.theme().muted_foreground,
            "Managed by Docker.".into(),
            format!(
                "Saved in the Docker config on the manager. Run docker logout {host} there to remove it."
            ),
        ),
        CredentialSource::Podman => (
            IconName::Info,
            cx.theme().muted_foreground,
            "Managed by Podman.".into(),
            format!("Run podman logout {host} on the manager to remove it."),
        ),
        CredentialSource::Environment => (
            IconName::TriangleAlert,
            cx.theme().warning,
            "Set by GANTRY_REGISTRY_AUTH.".into(),
            "The manager's environment takes precedence over any login saved here. Change it where the manager is started."
                .into(),
        ),
        CredentialSource::Other => (
            IconName::Info,
            cx.theme().muted_foreground,
            "Managed outside Gantry.".into(),
            text(&registry.source),
        ),
    }
}

fn registry_card(registry: &RegistryAuth, selected: bool, images: usize, cx: &App) -> Div {
    let source = CredentialSource::of(registry);
    // A stable colour per registry, whatever the filter shows.
    let slot = registry.registry.bytes().map(usize::from).sum();
    let accent = if registry.has_secret {
        theme::series(cx, slot)
    } else {
        cx.theme().muted_foreground
    };
    let initial = registry
        .registry
        .chars()
        .next()
        .map(|c| c.to_ascii_uppercase().to_string())
        .unwrap_or_default();
    div()
        .flex()
        .items_center()
        .gap(px(12.))
        .px(px(14.))
        .py(px(10.))
        .rounded(px(8.))
        .bg(if selected {
            theme::tint(cx.theme().primary, cx)
        } else {
            theme::card(cx)
        })
        .border_1()
        .border_color(if selected {
            cx.theme().primary
        } else {
            theme::card_border(cx)
        })
        .child(
            div()
                .flex()
                .items_center()
                .justify_center()
                .size(px(32.))
                .flex_shrink_0()
                .rounded(px(7.))
                .bg(theme::tint(accent, cx))
                .text_color(accent)
                .text_size(px(14.))
                .font_weight(FontWeight::SEMIBOLD)
                .child(initial),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(2.))
                .flex_1()
                .min_w(px(0.))
                .child(
                    div()
                        .truncate()
                        .text_size(px(14.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(text(&registry.registry)),
                )
                .child(
                    div()
                        .truncate()
                        .text_size(px(11.))
                        .text_color(cx.theme().muted_foreground)
                        .child(text(&registry_user(registry))),
                ),
        )
        .when(source != CredentialSource::Anonymous, |d| {
            d.child(widgets::chip(
                source.label(),
                if source.removable() {
                    cx.theme().primary
                } else {
                    cx.theme().muted_foreground
                },
                cx,
            ))
        })
        .child(
            div()
                .w(px(104.))
                .flex()
                .flex_shrink_0()
                .child(widgets::pill(
                    if registry.has_secret {
                        "secret stored"
                    } else {
                        "no login"
                    },
                    if registry.has_secret {
                        cx.theme().success
                    } else {
                        cx.theme().muted_foreground
                    },
                    cx,
                )),
        )
        .child(
            div()
                .w(px(70.))
                .flex_shrink_0()
                .text_right()
                .text_size(px(11.))
                .text_color(cx.theme().muted_foreground)
                .child(format!(
                    "{images} image{}",
                    if images == 1 { "" } else { "s" }
                )),
        )
}
