//! Installing the matching Gantry CLI is offered only when no CLI exists at
//! all, and only runs on an explicit click. Download and verification stay off
//! the foreground thread; success is followed by a normal startup attempt.

use crate::{activity::Phase, app::*, views::empty_state};
use gantry_desktop::{bootstrap, workspace};
use gpui_kit::assets::IconName;
use gpui_kit::component::{
    ActiveTheme, Disableable, Sizable,
    button::{Button, ButtonVariants},
};
use gpui_kit::{AppContext, Context, Div, ParentElement, Styled, div, px};
use std::time::Duration;

impl Desktop {
    pub fn cli_offer(&self) -> Option<bootstrap::Offer> {
        bootstrap::offer(self.options.managed_gantry.as_deref())
    }

    pub fn install_cli(&mut self, cx: &mut Context<Self>) {
        if self.installing || self.writing {
            return;
        }
        let Some(offer) = self.cli_offer() else {
            return;
        };
        self.installing = true;
        self.generation += 1;
        self.refreshing = false;
        let generation = self.generation;
        self.begin_activity(
            generation,
            None,
            format!("Install Gantry CLI {}", offer.release),
        );
        self.record_activity(
            generation,
            Phase::Working,
            &format!("Downloading {} from GitHub Releases…", offer.asset),
        );
        self.notice = Some(format!(
            "Installing Gantry CLI {} from GitHub Releases…",
            offer.release
        ));
        let (progress_tx, progress_rx) = std::sync::mpsc::sync_channel::<String>(16);
        self.install_progress_task = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(100))
                    .await;
                let message = progress_rx.try_iter().last();
                let installing = this.update(cx, |this, cx| {
                    if !this.installing {
                        return false;
                    }
                    if let Some(message) = message {
                        this.record_activity(generation, Phase::Working, &message);
                        this.notice = Some(workspace::text(&message));
                        cx.notify();
                    }
                    true
                });
                if installing.ok() != Some(true) {
                    break;
                }
            }
        }));
        let request = cx.background_spawn(async move {
            bootstrap::install(&offer, |message| {
                let _ = progress_tx.try_send(message.to_owned());
            })
            .map(|()| offer)
        });
        self.install_task = Some(cx.spawn(async move |this, cx| {
            let result = request.await;
            let _ = this.update(cx, |this, cx| {
                this.installing = false;
                let (phase, message) = match &result {
                    Ok(offer) => (
                        Phase::Complete,
                        format!(
                            "Installed Gantry CLI {} at {}",
                            offer.release,
                            offer.destination.display()
                        ),
                    ),
                    Err(error) => (
                        Phase::Failed,
                        format!("Gantry CLI was not installed: {error:#}"),
                    ),
                };
                this.record_activity(generation, phase, &message);
                this.notice = Some(workspace::text(&message));
                // The connector notices the new CLI and makes one startup
                // attempt; skip it if the user switched connections meanwhile.
                if result.is_ok() && this.generation == generation {
                    this.fetch(false, cx);
                }
                cx.notify();
            });
        }));
        cx.notify();
    }

    pub fn cli_missing_state(&self, message: &str, cx: &mut Context<Self>) -> Div {
        let offer = self.cli_offer();
        let detail = match &offer {
            Some(offer) => format!(
                "Downloads {} from the {} GitHub release, verifies its published SHA-256{}, \
                 and installs it privately at {}. A CLI you install yourself always takes precedence.",
                offer.asset,
                offer.release,
                if cfg!(target_os = "macos") {
                    " and code signature"
                } else {
                    ""
                },
                offer.destination.display()
            ),
            None => "Installing from the desktop requires a tagged release build on Linux or \
                     macOS. Install a Gantry release matching this desktop, then retry."
                .into(),
        };
        let install = offer.map(|offer| {
            Button::new("install-cli")
                .small()
                .primary()
                .label(if self.installing {
                    "Installing…".to_owned()
                } else {
                    format!("Install Gantry CLI {}", offer.release)
                })
                .disabled(self.installing || self.writing)
                .on_click(cx.listener(|this, _, _, cx| this.install_cli(cx)))
        });
        empty_state(IconName::CircleAlert, "Gantry CLI not found", message, cx)
            .child(
                div()
                    .max_w(px(420.))
                    .text_size(px(11.))
                    .text_color(cx.theme().muted_foreground)
                    .child(detail),
            )
            .child(
                div().mt_2().flex().gap_2().children(install).child(
                    Button::new("retry-connection")
                        .small()
                        .label("Retry connection")
                        .disabled(self.refreshing || self.installing)
                        .on_click(cx.listener(|this, _, _, cx| this.refresh(cx))),
                ),
            )
    }
}
