//! Per-screen pieces of the workbench: the status beside a page's filters, the
//! summary above its table, and the inspector for its selected record.
//! Screens not yet redesigned fall back to the generic record details.

use crate::{app::*, views::empty_state, widgets};
use gantry_desktop::{
    options::Source,
    workspace::{Page, Record},
};
use gpui_kit::component::{ActiveTheme, scroll::ScrollableElement};
use gpui_kit::{Context, Div, InteractiveElement, ParentElement, Styled, div, px};

/// The inspector's parts; `page_inspector` frames them consistently.
pub struct InspectorView {
    pub header: Div,
    pub body: Div,
    pub footer: String,
}

impl Desktop {
    pub fn page_status(&self, page: Page) -> Option<String> {
        let demo = self.options.source == Source::Demo;
        match page {
            Page::Traffic => Some(if demo {
                "Demo · sample traffic".into()
            } else {
                "Live · updates every 3 s".into()
            }),
            Page::Rules => Some(self.rules_status()),
            Page::Packets => Some(self.packets_status()),
            Page::Secrets => Some("Values are write-only".into()),
            Page::Mcp => Some("Tools pass through the gateway's filters".into()),
            Page::Audit => Some(self.audit_status()),
            Page::Images if self.images_registries => {
                Some("Credentials are stored by the manager, not this desktop".into())
            }
            Page::Images => Some(self.images_status()),
            Page::Mounts => Some(match self.options.source {
                Source::Remote { .. } => "Host paths are on the remote manager".into(),
                _ => format!("Host paths are on {}", self.source_name()),
            }),
            Page::Ports => Some(match self.options.source {
                Source::Remote { .. } => "Host ports on the remote manager".into(),
                _ => format!("Host ports on {}", self.source_name()),
            }),
            page if page.is_organization() => self.org_status(page),
            _ => None,
        }
    }

    pub fn page_summary(&self, page: Page, cx: &mut Context<Self>) -> Option<Div> {
        match page {
            Page::Traffic => Some(self.traffic_summary(cx)),
            Page::Rules => Some(self.rules_summary(cx)),
            Page::Ports => Some(self.ports_summary(cx)),
            Page::Packets => Some(self.packets_summary(cx)),
            Page::Mounts => Some(self.mounts_summary(cx)),
            Page::Secrets => Some(self.secrets_summary(cx)),
            Page::Mcp => Some(self.mcp_summary(cx)),
            Page::Audit => Some(self.audit_summary(cx)),
            Page::Images if self.images_registries => Some(self.registries_summary(cx)),
            Page::Images => Some(self.images_summary(cx)),
            page if page.is_organization() => self.org_summary(page, cx),
            _ => None,
        }
    }

    /// Records drawn as cards instead of table rows.
    pub fn page_list(&self, page: Page, cx: &mut Context<Self>) -> Option<Div> {
        match page {
            Page::Ports => Some(self.ports_list(cx)),
            Page::Mounts => Some(self.mounts_list(cx)),
            Page::Secrets => Some(self.secrets_list(cx)),
            Page::Mcp => Some(self.mcp_list(cx)),
            Page::Audit => Some(self.audit_list(cx)),
            Page::Images if self.images_registries => Some(self.registries_list(cx)),
            Page::Images => Some(self.images_list(cx)),
            page if page.is_organization() => self.org_list(page, cx),
            _ => None,
        }
    }

    pub fn page_inspector(&self, cx: &mut Context<Self>) -> Div {
        let page = self.page;
        let panel = div()
            .flex()
            .flex_col()
            .size_full()
            .min_h_0()
            .bg(cx.theme().secondary)
            .border_l_1()
            .border_color(cx.theme().border);
        let Some(record) = self.selected_record(cx) else {
            if let Some(view) = self.org_empty_inspector(page, cx) {
                return panel.child(view.header).child(
                    div()
                        .id("page-inspector-scroll")
                        .flex_1()
                        .min_h_0()
                        .overflow_y_scrollbar()
                        .child(div().px(px(20.)).py(px(8.)).child(view.body)),
                );
            }
            return panel.child(empty_state(
                self.page_icon(),
                page.label(),
                "Select a row to inspect it.",
                cx,
            ));
        };
        let view = match &record {
            Record::Traffic(flow) => self.traffic_inspector(flow, cx),
            Record::Rule(rule) => self.rule_inspector(rule, cx),
            Record::Port(port) => self.port_inspector(port, cx),
            Record::Packet(packet) => self.packet_inspector(packet, cx),
            Record::Mount(mount) => self.mount_inspector(mount, cx),
            Record::Secret(secret) => self.secret_inspector(secret, cx),
            Record::Mcp(server) => self.mcp_inspector(server, cx),
            Record::Audit(event) => self.audit_inspector(event, cx),
            Record::Image(image) => self.image_inspector(image, cx),
            Record::Registry(registry) => self.registry_inspector(registry, cx),
            Record::Org(record) => self.org_inspector(record, cx),
            record => self.generic_inspector(record, cx),
        };
        panel
            .child(view.header)
            .child(
                div()
                    .id("page-inspector-scroll")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .child(div().px(px(20.)).py(px(8.)).child(view.body)),
            )
            .child(
                div()
                    .px(px(20.))
                    .py(px(16.))
                    .text_size(px(10.))
                    .text_color(cx.theme().muted_foreground)
                    .truncate()
                    .child(view.footer),
            )
    }

    fn generic_inspector(&self, record: &Record, cx: &Context<Self>) -> InspectorView {
        let details = record.details();
        let title = details
            .iter()
            .find(|(key, _)| {
                matches!(
                    key.as_str(),
                    "Name" | "Target" | "Ref" | "Registry" | "Profile"
                )
            })
            .or(details.first())
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| self.page.label().into());
        InspectorView {
            header: widgets::inspector_header(
                self.page_icon(),
                &title,
                None,
                self.source_name(),
                cx,
            ),
            body: widgets::inspector_section(
                "DETAILS",
                details
                    .iter()
                    .map(|(key, value)| (key.as_str(), value.clone(), false))
                    .collect(),
                cx,
            ),
            footer: format!("Inspecting {} on {}", self.page.label(), self.source_name()),
        }
    }
}
