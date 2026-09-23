//! Packet Capture: a recorder, not a log file. Packets per second with denied
//! bursts in red, the loaded frames, and an inspector that decodes one frame.
//! Payloads never leave memory.

use crate::{
    app::*,
    screens::InspectorView,
    theme,
    widgets::{self, TileAccent},
};
use gantry_desktop::{
    capture, clock,
    dashboard_wire::Packet,
    options::Source,
    telemetry::{bytes_label, count_label},
    workspace::{Page, text},
};
use gpui_kit::assets::IconName;
use gpui_kit::component::{ActiveTheme, Sizable, button::Button};
use gpui_kit::{
    AppContext, ClipboardItem, Context, Div, InteractiveElement, ParentElement, Styled,
    TestSupportExt, div, prelude::FluentBuilder, px,
};

const HISTOGRAM_SECONDS: usize = 60;

impl Desktop {
    /// Read the frames recorded since the last read, while the Packet Capture
    /// screen shows an active capture. Reads never change capture state, stay
    /// out of the activity log, and follow at once while the recorder holds
    /// more than one read returns.
    pub fn read_packets(&mut self, cx: &mut Context<Self>) {
        let (Some(name), Some(target)) = (self.packet_sandbox.clone(), self.target.clone()) else {
            return;
        };
        if self.page != Page::Packets
            || !self.packets.active
            || self.packets_paused
            || self.packets_reading
            || self.writing
            || !matches!(self.connection, Connection::Connected(_))
            || target.source != self.options.source
        {
            return;
        }
        self.packets_reading = true;
        let after = self.packets.next;
        let generation = self.generation;
        let connector = self.connector.clone();
        let reader = name.clone();
        let request = cx.background_spawn(async move {
            connector
                .lock()
                .map_err(|_| anyhow::anyhow!("Manager connector failed"))?
                .read_packets(&target, &reader, after)
        });
        self.packet_task = Some(cx.spawn(async move |this, cx| {
            let result = request.await;
            let _ = this.update(cx, |this, cx| {
                this.packets_reading = false;
                // An action, a new capture or a lost connection since the read
                // started makes its result stale.
                if this.generation != generation
                    || this.packet_sandbox.as_deref() != Some(name.as_str())
                    || this.packets.next != after
                    || !matches!(this.connection, Connection::Connected(_))
                {
                    return;
                }
                match result {
                    Ok(read) => {
                        this.capture_rate.record(
                            read.packets.iter().filter(|p| p.sequence > after),
                            clock::now_millis(),
                        );
                        capture::merge(&mut this.packets, read, after);
                        this.packet_error = None;
                        this.sync_pages(cx);
                        if capture::behind(&this.packets) {
                            this.read_packets(cx);
                        }
                    }
                    Err(error) => this.packet_error = Some(error.to_string()),
                }
                cx.notify();
            });
        }));
    }

    pub fn packets_status(&self) -> String {
        let sandbox = self.packet_sandbox.as_deref().unwrap_or("no sandbox");
        if let Some(error) = self.packet_error.as_deref().filter(|_| self.packets.active) {
            format!("Reading {sandbox} failed · {}", text(error))
        } else if self.packets.active && self.packets_paused {
            format!("Paused · {sandbox} · latest #{}", self.packets.latest)
        } else if self.packets.active && self.options.source == Source::Demo {
            format!(
                "Sample capture · {sandbox} · latest #{}",
                self.packets.latest
            )
        } else if self.packets.active {
            format!(
                "Live · {sandbox} · latest #{} · {} evicted",
                self.packets.latest, self.packets.evicted
            )
        } else if self.packet_sandbox.is_some() {
            format!("Stopped · {sandbox}")
        } else {
            "Not recording · start a capture to inspect frames".into()
        }
    }

    pub fn packets_summary(&self, cx: &mut Context<Self>) -> Div {
        // Read live, the chart ends now and scrolls; otherwise it ends at the
        // newest frame.
        let live = self.packets.active
            && !self.packets_paused
            && matches!(self.connection, Connection::Connected(_));
        let summary = capture::summary(&self.packets);
        let share = |part: usize| {
            if summary.packets == 0 {
                0.
            } else {
                part as f32 / summary.packets as f32
            }
        };
        let span = match (summary.first, summary.last) {
            (Some(first), Some(last)) => {
                let seconds = (last - first) / 1000;
                if seconds >= 60 {
                    format!("{} min {} s of capture", seconds / 60, seconds % 60)
                } else {
                    format!("{seconds} s of capture")
                }
            }
            _ => "none loaded yet".into(),
        };
        // The desktop holds the newest frames only; the chart keeps counting.
        let span = if summary.packets >= capture::KEEP {
            format!("newest {} · {span}", count_label(capture::KEEP as u64))
        } else {
            span
        };
        let tiles = widgets::tiles([
            widgets::tile(
                "PACKETS",
                count_label(summary.packets as u64),
                span,
                TileAccent::None,
                cx,
            ),
            widgets::tile(
                "OUTBOUND",
                count_label(summary.outbound as u64),
                format!("{:.0}% of packets", share(summary.outbound) * 100.),
                TileAccent::Ratio(share(summary.outbound), theme::download(cx)),
                cx,
            ),
            widgets::tile(
                "DENIED",
                count_label(summary.denied as u64),
                format!("{:.1}% of packets", share(summary.denied) * 100.),
                if summary.denied > 0 {
                    TileAccent::Tint(cx.theme().danger)
                } else {
                    TileAccent::None
                },
                cx,
            ),
            widgets::tile(
                "BYTES",
                bytes_label(summary.bytes),
                if summary.packets == 0 {
                    "—".into()
                } else {
                    format!(
                        "avg {} per packet",
                        bytes_label(summary.bytes / summary.packets as u64)
                    )
                },
                TileAccent::None,
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
            .when(!self.capture_rate.is_empty(), |d| {
                d.child(widgets::section_title(
                    "PACKETS PER SECOND",
                    if live {
                        format!("last {HISTOGRAM_SECONDS} s · denied in red")
                    } else {
                        format!("{HISTOGRAM_SECONDS} s to the newest frame · denied in red")
                    },
                    cx,
                ))
                .child(
                    div()
                        .id("packet-histogram")
                        .test_support()
                        .child(widgets::histogram(
                            &self
                                .capture_rate
                                .window(HISTOGRAM_SECONDS, live.then(clock::now_millis)),
                            cx,
                        )),
                )
                .child(
                    div()
                        .flex()
                        .justify_between()
                        .text_size(px(10.))
                        .text_color(cx.theme().muted_foreground)
                        .child(format!("−{HISTOGRAM_SECONDS} s"))
                        .child(format!("−{} s", HISTOGRAM_SECONDS / 2))
                        .child(if live { "now" } else { "newest" }),
                )
            })
    }

    pub fn packet_inspector(&self, packet: &Packet, cx: &mut Context<Self>) -> InspectorView {
        let outbound = packet.direction == "tx";
        let bytes = capture::decode_base64(&packet.data).unwrap_or_default();
        let dump = capture::hex_dump(&bytes, 12);
        let hex = capture::hex_preview(&bytes, bytes.len());
        let (status, color) = if packet.allowed {
            ("Allowed", cx.theme().success)
        } else {
            ("Denied", cx.theme().danger)
        };
        let direction = if outbound { "outbound" } else { "inbound" };
        let time = clock::parse_millis(&packet.timestamp)
            .map(|ms| format!("{} UTC", clock::clock_millis(ms)))
            .unwrap_or_else(|| "—".into());
        let body = div()
            .flex()
            .flex_col()
            .gap(px(14.))
            .child(widgets::inspector_section(
                "FRAME",
                vec![
                    ("Time", time, false),
                    ("Direction", capitalized(direction), false),
                    (
                        "Length",
                        format!("{} B", count_label(packet.length.max(0) as u64)),
                        false,
                    ),
                    ("Captured", format!("{} B", bytes.len()), false),
                    ("Decision", status.into(), false),
                ],
                cx,
            ))
            .child(widgets::separator(cx))
            .child(crate::views::eyebrow("PAYLOAD", cx))
            .child(
                div()
                    .id("packet-hex")
                    .test_support()
                    .flex()
                    .flex_col()
                    .gap(px(3.))
                    .p(px(10.))
                    .rounded(px(6.))
                    .bg(cx.theme().background)
                    .border_1()
                    .border_color(cx.theme().border)
                    .font_family(cx.theme().mono_font_family.clone())
                    .text_size(px(11.))
                    .children(if dump.is_empty() {
                        vec![
                            div()
                                .text_color(cx.theme().muted_foreground)
                                .child("No payload"),
                        ]
                    } else {
                        dump.into_iter()
                            .map(|line| div().whitespace_nowrap().child(line))
                            .collect()
                    }),
            )
            .child(widgets::inspector_note(
                IconName::KeyRound,
                cx.theme().muted_foreground,
                "Payloads stay in memory.",
                "Stop and clear removes them from the manager's recorder too.",
                cx,
            ))
            .child(
                div().flex().child(
                    Button::new("packet-copy-hex")
                        .small()
                        .label("Copy Hex")
                        .on_click(move |_, _, cx| {
                            cx.write_to_clipboard(ClipboardItem::new_string(hex.clone()))
                        }),
                ),
            );
        InspectorView {
            header: widgets::inspector_header(
                IconName::Activity,
                &format!("Packet #{}", packet.sequence),
                Some((&format!("{status} · {direction}"), color)),
                self.source_name(),
                cx,
            ),
            body,
            footer: format!(
                "Inspecting a frame from {} on {}",
                self.packet_sandbox.as_deref().unwrap_or("a sandbox"),
                self.source_name()
            ),
        }
    }
}

fn capitalized(value: &str) -> String {
    let mut chars = value.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}
