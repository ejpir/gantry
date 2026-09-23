//! Bounded, memory-only activity for this window. Never store request bodies,
//! credentials, or pretend this is the manager's persistent audit log.
use crate::app::Desktop;
use gantry_desktop::{connector::Target, options::Source, workspace};
use gpui_kit::assets::IconName;
use gpui_kit::component::{
    ActiveTheme, Icon, Sizable,
    button::{Button, ButtonVariants},
    scroll::ScrollableElement,
};
use gpui_kit::{
    App, Context, Div, InteractiveElement, ParentElement, Styled, TestSupportExt, div, px,
};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Working,
    Complete,
    Failed,
}
pub struct Entry {
    pub id: u64,
    pub source: Source,
    pub target: Option<Target>,
    pub timestamp: String,
    pub title: String,
    pub message: String,
    pub phase: Phase,
}
impl Entry {
    pub fn new(id: u64, source: Source, target: Option<Target>, title: String) -> Self {
        // UTC avoids adding locale/time-zone dependencies to the control plane.
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            % 86400;
        Self {
            id,
            source,
            target,
            timestamp: format!("{:02}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60),
            title: workspace::text(&title),
            message: "Submitting once; awaiting manager confirmation…".into(),
            phase: Phase::Working,
        }
    }
    pub fn visible(&self, source: &Source, target: Option<&Target>) -> bool {
        &self.source == source
            && match (&self.target, target) {
                (Some(old), Some(now)) => old == now,
                _ => true,
            }
    }
}
impl Desktop {
    pub fn begin_activity(&mut self, id: u64, target: Option<Target>, title: String) {
        if self.activity.len() >= 100 {
            self.activity.remove(0);
        }
        self.activity
            .push(Entry::new(id, self.options.source.clone(), target, title));
        self.activity_open = true;
    }
    pub fn record_activity(&mut self, id: u64, phase: Phase, message: &str) {
        if let Some(entry) = self.activity.iter_mut().find(|entry| entry.id == id) {
            entry.phase = phase;
            entry.message = workspace::text(message);
        }
    }
    pub fn activity_view(&self, cx: &mut Context<Self>) -> Div {
        let entries = self
            .activity
            .iter()
            .rev()
            .filter(|e| e.visible(&self.options.source, self.target.as_ref()))
            .take(100);
        let header = div()
            .flex()
            .items_center()
            .h(px(32.))
            .flex_shrink_0()
            .px_4()
            .gap_2()
            .bg(cx.theme().sidebar)
            .child(Icon::new(IconName::Clock).size(px(15.)))
            .child("Activity")
            .children(
                // Collapsed, the drawer still shows the newest entry.
                self.activity
                    .iter()
                    .rev()
                    .find(|e| e.visible(&self.options.source, self.target.as_ref()))
                    .filter(|_| !self.activity_open)
                    .map(|entry| {
                        let (icon, color) = phase_icon(entry.phase, cx);
                        div()
                            .id("activity-latest")
                            .test_support()
                            .flex()
                            .items_center()
                            .gap_2()
                            .ml_3()
                            .min_w_0()
                            .text_size(px(12.))
                            .child(
                                div()
                                    .flex_shrink_0()
                                    .text_size(px(10.))
                                    .font_family(cx.theme().mono_font_family.clone())
                                    .text_color(cx.theme().muted_foreground)
                                    .child(entry.timestamp.clone()),
                            )
                            .child(Icon::new(icon).size(px(14.)).text_color(color))
                            .child(div().min_w_0().truncate().child(entry.title.clone()))
                    }),
            )
            .child(div().flex_1())
            .child(
                div()
                    .text_size(px(11.))
                    .text_color(cx.theme().muted_foreground)
                    .child(format!("{} · this window · UTC", self.source_name())),
            )
            .child(
                Button::new("activity-toggle")
                    .ghost()
                    .xsmall()
                    .icon(if self.activity_open {
                        IconName::ChevronDown
                    } else {
                        IconName::ChevronUp
                    })
                    .accessibility_label("Toggle activity")
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.activity_open = !this.activity_open;
                        cx.notify();
                    })),
            );
        let show_notice = self.activity.last().is_some_and(|e| {
            e.source == self.options.source
                && !e.visible(&self.options.source, self.target.as_ref())
        });
        let mut view = div()
            .flex()
            .flex_col()
            .flex_shrink_0()
            .border_t_1()
            .border_color(cx.theme().border)
            .bg(cx.theme().background)
            .child(header);
        if show_notice && let Some(notice) = &self.notice {
            view = view.child(
                div()
                    .px_4()
                    .py_2()
                    .text_size(px(12.))
                    .text_color(cx.theme().warning)
                    .child(notice.clone()),
            );
        }
        if self.activity_open {
            let mut content = div().flex().flex_col();
            let mut count = 0;
            for entry in entries {
                count += 1;
                let (icon, color) = phase_icon(entry.phase, cx);
                content = content.child(
                    div()
                        .flex()
                        .items_start()
                        .gap_3()
                        .mx_4()
                        .py_2()
                        .border_b_1()
                        .border_color(cx.theme().border)
                        .child(
                            div()
                                .w(px(64.))
                                .flex_shrink_0()
                                .text_size(px(10.))
                                .font_family(cx.theme().mono_font_family.clone())
                                .text_color(cx.theme().muted_foreground)
                                .child(entry.timestamp.clone()),
                        )
                        .child(Icon::new(icon).size(px(16.)).text_color(color))
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .flex_1()
                                .min_w_0()
                                .gap_1()
                                .child(div().text_size(px(12.)).child(entry.title.clone()))
                                .child(
                                    div()
                                        .text_size(px(11.))
                                        .text_color(cx.theme().muted_foreground)
                                        .child(entry.message.clone()),
                                ),
                        ),
                );
            }
            if count == 0 {
                content=content.child(div().px_5().py_5().text_size(px(12.)).text_color(cx.theme().muted_foreground).child(if self.options.source==Source::Demo {"Demo · sample inventory only. No operations have been executed."}else{"Operations from this window appear here. Manager-wide history is available in Audit."}));
            }
            view = view.child(
                div()
                    .id("activity-scroll")
                    .h(px(164.))
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .child(content),
            );
        }
        view
    }
    pub fn fresh_label(&self) -> String {
        self.last_updated
            .map(|t| {
                format!(
                    "Last refreshed {}s ago",
                    Instant::now().duration_since(t).as_secs()
                )
            })
            .unwrap_or_else(|| "Awaiting manager snapshot".into())
    }
}

fn phase_icon(phase: Phase, cx: &App) -> (IconName, gpui_kit::Hsla) {
    match phase {
        Phase::Working => (IconName::Loader, cx.theme().warning),
        Phase::Complete => (IconName::Check, cx.theme().success),
        Phase::Failed => (IconName::CircleAlert, cx.theme().danger),
    }
}
