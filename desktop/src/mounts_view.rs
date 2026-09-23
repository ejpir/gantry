//! Mounts: shared folders as mappings from a host path to a guest path,
//! grouped by sandbox, with access and owner visible and a clear place to add
//! one. Read-only is the default; read-write is called out.

use crate::{
    app::*,
    screens::InspectorView,
    theme,
    widgets::{self, TileAccent},
    workbench::mount_edit,
};
use gantry_desktop::{
    dashboard_wire::Mount,
    forms::Kind,
    options::Source,
    summary,
    workspace::{Page, Record, text},
};
use gpui_kit::assets::IconName;
use gpui_kit::component::{ActiveTheme, Disableable, Icon, Sizable, button::Button};
use gpui_kit::{
    App, Context, Div, FontWeight, InteractiveElement, ParentElement, Styled, TestSupportExt, div,
    prelude::FluentBuilder, px,
};
use std::path::PathBuf;

impl Desktop {
    pub fn mounts_summary(&self, cx: &mut Context<Self>) -> Div {
        let summary = summary::mounts(&self.host);
        let tiles = widgets::tiles([
            widgets::tile(
                "SHARES",
                summary.shares.to_string(),
                format!(
                    "for {} sandbox{}",
                    summary.sandboxes,
                    if summary.sandboxes == 1 { "" } else { "es" }
                ),
                TileAccent::None,
                cx,
            ),
            widgets::tile(
                "READ-ONLY",
                summary.read_only.to_string(),
                "the default for new mounts".into(),
                TileAccent::Ratio(
                    if summary.shares == 0 {
                        0.
                    } else {
                        summary.read_only as f32 / summary.shares as f32
                    },
                    theme::bar(cx),
                ),
                cx,
            ),
            widgets::tile(
                "READ-WRITE",
                summary.read_write.to_string(),
                "sandbox can change the files".into(),
                if summary.read_write > 0 {
                    TileAccent::Tint(cx.theme().warning)
                } else {
                    TileAccent::None
                },
                cx,
            ),
            widgets::tile(
                if summary.errors > 0 {
                    "ERRORS"
                } else {
                    "PENDING"
                },
                if summary.errors > 0 {
                    summary.errors
                } else {
                    summary.pending
                }
                .to_string(),
                if summary.errors > 0 {
                    "a share could not be mounted".into()
                } else {
                    "changes applied at next boot".into()
                },
                if summary.errors > 0 {
                    TileAccent::Tint(cx.theme().danger)
                } else {
                    TileAccent::None
                },
                cx,
            ),
        ]);
        div().px_4().pt(px(12.)).pb(px(14.)).child(tiles)
    }

    pub fn mounts_list(&self, cx: &mut Context<Self>) -> Div {
        let state = &self.pages[Page::Mounts.index()];
        let rows = state.table.read(cx).delegate().rows.clone();
        let mut list = div().flex().flex_col().gap(px(8.)).px_4().pb(px(14.));
        let mut previous: Option<String> = None;
        for (index, row) in rows.iter().enumerate() {
            let Record::Mount(mount) = &row.record else {
                continue;
            };
            if previous.as_deref() != Some(mount.sandbox.as_str()) {
                let count = rows
                    .iter()
                    .filter(|r| matches!(&r.record, Record::Mount(m) if m.sandbox == mount.sandbox))
                    .count();
                list = list.child(group_header(&mount.sandbox, count, previous.is_some(), cx));
                previous = Some(mount.sandbox.clone());
            }
            let selected = state.selected.as_deref() == Some(row.key.as_str());
            let key = row.key.clone();
            list = list.child(
                mount_card(mount, selected, cx)
                    .id(("mount-card", index))
                    .test_support()
                    .cursor_pointer()
                    .on_mouse_down(
                        gpui_kit::MouseButton::Left,
                        cx.listener(move |this, _, _, cx| this.select_page_row(key.clone(), cx)),
                    ),
            );
        }
        let can_add = self.can_write();
        list.child(
            div()
                .id("mount-add-zone")
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
                            this.open_form(Kind::Share(None), window, cx)
                        }),
                    )
                })
                .child(
                    Icon::new(IconName::FolderPlus)
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
                                .child("Share a folder…"),
                        )
                        .child(
                            div()
                                .text_size(px(11.))
                                .text_color(cx.theme().muted_foreground)
                                .child(
                                    "Choose a host folder, then a sandbox and guest path. Read-only unless you change it.",
                                ),
                        ),
                ),
        )
    }

    pub fn mount_inspector(&self, mount: &Mount, cx: &mut Context<Self>) -> InspectorView {
        let failed = !mount.error.is_empty() || mount.state == "error";
        let (status, color) = if failed {
            ("Error", cx.theme().danger)
        } else if mount.state == "active" {
            ("Mounted", cx.theme().success)
        } else if mount.state == "restart" {
            ("Pending restart", cx.theme().warning)
        } else {
            ("Saved", cx.theme().muted_foreground)
        };
        let owner = match (mount.uid, mount.gid) {
            (Some(uid), Some(gid)) => format!("{uid}:{gid}"),
            _ => "image default".into(),
        };
        let local = matches!(self.options.source, Source::Local(_));
        let host = PathBuf::from(&mount.host);
        let body = div()
            .flex()
            .flex_col()
            .gap(px(14.))
            .child(widgets::inspector_section(
                "SHARE",
                vec![
                    ("Host path", mount.host.clone(), true),
                    ("Guest path", mount.guest.clone(), true),
                    ("VM path", mount.vm.clone(), true),
                    ("Tag", mount.tag.clone(), true),
                    (
                        "Access",
                        if mount.read_only {
                            "Read-only"
                        } else {
                            "Read-write"
                        }
                        .into(),
                        false,
                    ),
                    ("Owner", owner, true),
                    ("State", mount.state.clone(), false),
                ],
                cx,
            ))
            .child(widgets::separator(cx))
            .when(failed, |d| {
                d.child(widgets::inspector_note(
                    IconName::CircleAlert,
                    cx.theme().danger,
                    "The share is not mounted.",
                    &text(if mount.error.is_empty() {
                        "The manager reported an error for this share."
                    } else {
                        &mount.error
                    }),
                    cx,
                ))
            })
            .when(!mount.read_only, |d| {
                d.child(widgets::inspector_note(
                    IconName::TriangleAlert,
                    cx.theme().warning,
                    "Read-write share.",
                    "The sandbox can modify and delete these files.",
                    cx,
                ))
            })
            .when(mount.state == "restart", |d| {
                d.child(widgets::inspector_note(
                    IconName::RefreshCw,
                    cx.theme().warning,
                    "Applies at the next boot.",
                    "The running sandbox still uses its previous shares.",
                    cx,
                ))
            })
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .child(
                        // Host paths belong to the manager's machine; only a
                        // local manager's folders exist on this desktop.
                        Button::new("mount-reveal")
                            .small()
                            .label(if cfg!(target_os = "macos") {
                                "Reveal in Finder"
                            } else {
                                "Reveal in Files"
                            })
                            .disabled(!local)
                            .on_click(move |_, _, cx| cx.reveal_path(&host)),
                    )
                    .child(self.form_button("mount-inspector-edit", "Edit…", mount_edit(mount), cx))
                    .child(
                        Button::new("mount-remove")
                            .small()
                            .label("Remove…")
                            .when(self.can_write(), |b| b.text_color(cx.theme().danger))
                            .disabled(!self.can_write())
                            .on_click(
                                cx.listener(|this, _, window, cx| this.remove_selected(window, cx)),
                            ),
                    ),
            );
        InspectorView {
            header: widgets::inspector_header(
                IconName::Folder,
                &mount.guest,
                Some((&format!("{status} · {}", mount.sandbox), color)),
                self.source_name(),
                cx,
            ),
            body,
            footer: format!(
                "Inspecting a share of {} on {}",
                mount.sandbox,
                self.source_name()
            ),
        }
    }
}

fn group_header(sandbox: &str, count: usize, spaced: bool, cx: &App) -> Div {
    div()
        .flex()
        .items_center()
        .gap(px(7.))
        .when(spaced, |d| d.mt(px(8.)))
        .child(
            Icon::new(IconName::Box)
                .size(px(13.))
                .text_color(cx.theme().success.opacity(0.85)),
        )
        .child(
            div()
                .text_size(px(12.))
                .font_weight(FontWeight::SEMIBOLD)
                .child(text(sandbox)),
        )
        .child(
            div()
                .text_size(px(11.))
                .text_color(cx.theme().muted_foreground)
                .child(format!(
                    "· {count} share{}",
                    if count == 1 { "" } else { "s" }
                )),
        )
}

fn mount_card(mount: &Mount, selected: bool, cx: &App) -> Div {
    let failed = !mount.error.is_empty() || mount.state == "error";
    div()
        .flex()
        .items_center()
        .gap(px(12.))
        .h(px(40.))
        .px(px(14.))
        .rounded(px(7.))
        .bg(if selected {
            theme::tint(cx.theme().primary, cx)
        } else {
            theme::card(cx)
        })
        .border_1()
        .border_color(if selected {
            cx.theme().primary
        } else if failed {
            cx.theme().danger.opacity(0.5)
        } else {
            theme::card_border(cx)
        })
        .child(
            Icon::new(IconName::Folder)
                .size(px(15.))
                .text_color(cx.theme().muted_foreground),
        )
        .child(widgets::mono(&mount.host, cx).flex_1())
        .child(
            Icon::new(IconName::MoveRight)
                .size(px(16.))
                .text_color(theme::download(cx)),
        )
        .child(widgets::mono(&mount.guest, cx).flex_1())
        .child(widgets::chip(
            if mount.read_only {
                "read-only"
            } else {
                "read-write"
            },
            if mount.read_only {
                cx.theme().muted_foreground
            } else {
                cx.theme().warning
            },
            cx,
        ))
        .child(
            div()
                .w(px(72.))
                .flex_shrink_0()
                .text_right()
                .font_family(cx.theme().mono_font_family.clone())
                .text_size(px(11.))
                .text_color(cx.theme().muted_foreground)
                .child(match (mount.uid, mount.gid) {
                    (Some(uid), Some(gid)) => format!("{uid}:{gid}"),
                    _ => "default".into(),
                }),
        )
        .child(widgets::state_label(&mount.state, &mount.error, cx))
}
