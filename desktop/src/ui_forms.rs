use crate::app::Desktop;
use gantry_desktop::{
    commands::Outcome,
    connector::Target,
    forms::{self, FieldKind, Intent, Kind, Spec, Values},
    launcher, local_profiles, workspace,
};
use gpui_kit::component::{
    ActiveTheme, Disableable, FocusTrapElement, Selectable, Sizable,
    button::{Button, ButtonVariants},
    input::{Input, InputState, Textarea, TextareaState},
    scroll::ScrollableElement,
    switch::Switch,
};
use gpui_kit::{
    App, AppContext, Context, Div, Entity, FocusHandle, Focusable, InteractiveElement, IntoElement,
    ParentElement, Styled, TestSupportExt, Window, div, prelude::FluentBuilder, px,
};

pub enum FormInput {
    Single(Entity<InputState>),
    Multiline(Entity<TextareaState>),
}
impl FormInput {
    pub fn value(&self, cx: &App) -> gpui_kit::SharedString {
        match self {
            Self::Single(s) => s.read(cx).value(),
            Self::Multiline(s) => s.read(cx).value(),
        }
    }
    pub(crate) fn focus_handle(&self, cx: &App) -> FocusHandle {
        match self {
            Self::Single(s) => s.focus_handle(cx),
            Self::Multiline(s) => s.focus_handle(cx),
        }
    }
    pub(crate) fn set_value(
        &self,
        value: impl Into<gpui_kit::SharedString>,
        window: &mut Window,
        cx: &mut App,
    ) {
        let value = value.into();
        match self {
            Self::Single(s) => s.update(cx, |s, cx| s.set_value(value, window, cx)),
            Self::Multiline(s) => s.update(cx, |s, cx| s.set_value(value, window, cx)),
        }
    }
}
pub struct NativeForm {
    pub spec: Spec,
    pub inputs: Vec<FormInput>,
    pub focus: FocusHandle,
    pub target: Option<Target>,
    pub scope: String,
    pub error: Option<String>,
    pub sliders: crate::form_controls::ResourceSliders,
    pub picking_path: Option<usize>,
    _subscriptions: Vec<gpui_kit::Subscription>,
}
impl Desktop {
    pub fn open_form(&mut self, kind: Kind, window: &mut Window, cx: &mut Context<Self>) {
        if self.form.is_some() {
            return;
        }
        let sandbox = self
            .inventory
            .selected()
            .map(|s| s.name.as_str())
            .unwrap_or("");
        let spec = Spec::new(kind, &self.host, sandbox);
        if if spec.local() {
            !self.can_edit_profiles()
        } else {
            !self.can_write()
        } {
            return;
        }
        self.context_menu = None;
        self.context_subscription = None;
        let scope = if spec.local() {
            format!(
                "Client-local profiles · {}",
                self.config_dir.as_ref().unwrap().display()
            )
        } else {
            self.target.as_ref().unwrap().label()
        };
        let inputs = spec
            .fields
            .iter()
            .map(|f| {
                if f.key == "policy" {
                    FormInput::Multiline(cx.new(|cx| {
                        TextareaState::new(window, cx)
                            .default_value(&f.value)
                            .auto_grow(3, 8)
                    }))
                } else {
                    FormInput::Single(cx.new(|cx| {
                        InputState::new(window, cx)
                            .default_value(&f.value)
                            .masked(matches!(f.kind, FieldKind::Password))
                            .validate(|value, _| value.len() <= 256 * 1024)
                    }))
                }
            })
            .collect::<Vec<_>>();
        let (sliders, subscriptions) = self.resource_sliders(&spec, &inputs, window, cx);
        let focus = cx.focus_handle();
        // Buttons, switches and dropdowns keep their value in a hidden input;
        // focus the first field that is typed into.
        let typed = spec.fields.iter().position(|f| {
            !matches!(
                f.kind,
                FieldKind::Bool | FieldKind::Choice(_) | FieldKind::Select(_)
            )
        });
        if let Some(input) = typed.and_then(|index| inputs.get(index)) {
            input.focus_handle(cx).focus(window, cx);
        } else {
            focus.focus(window, cx);
        }
        if matches!(&spec.kind, Kind::Configure(_)) {
            self.inspector_open = true;
            self.inspector_settings = true;
        }
        self.form = Some(NativeForm {
            spec,
            inputs,
            focus,
            target: self.target.clone(),
            scope,
            error: None,
            sliders,
            picking_path: None,
            _subscriptions: subscriptions,
        });
        self.notice = None;
        cx.notify();
    }
    pub fn close_form(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.form = None;
        self.focus_inventory(window, cx);
        cx.notify();
    }
    pub fn submit_form(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(form) = &self.form else {
            return;
        };
        if form.picking_path.is_some() {
            return;
        }
        let allowed = if form.spec.local() {
            self.can_edit_profiles()
        } else {
            self.can_write() && form.target == self.target
        };
        if !allowed {
            self.form.as_mut().unwrap().error=Some("Connection changed or unavailable. Refresh and reopen this form; no write was sent.".into());
            cx.notify();
            return;
        }
        let values: Values = form
            .spec
            .fields
            .iter()
            .zip(&form.inputs)
            .map(|(f, input)| {
                (
                    f.key.into(),
                    zeroize::Zeroizing::new(input.value(cx).to_string()),
                )
            })
            .collect();
        match form.spec.build(&values, &self.host) {
            Err(error) => {
                self.form.as_mut().unwrap().error = Some(error.to_string());
                cx.notify();
            }
            Ok(intent) => {
                let target = form.target.clone();
                self.form = None;
                self.start_job(intent, target, cx);
                self.focus_inventory(window, cx);
            }
        }
    }
    pub fn start_job(&mut self, intent: Intent, target: Option<Target>, cx: &mut Context<Self>) {
        if matches!(&intent, Intent::Manager(_)) {
            if !self.can_write() || target != self.target {
                return;
            }
        } else if !self.can_edit_profiles() {
            return;
        }
        // Profile management belongs to this client, never the selected manager.
        let target = if matches!(&intent, Intent::Manager(_)) {
            target
        } else {
            None
        };
        let title = match &intent {
            Intent::Manager(command) => format!("{} · {}", command.label(), command.subject()),
            _ => "Update client-local profiles".into(),
        };
        self.writing = true;
        self.refreshing = false;
        self.generation += 1;
        let generation = self.generation;
        self.begin_activity(generation, target.clone(), title);
        let scope = target
            .as_ref()
            .map(Target::label)
            .unwrap_or_else(|| "Client-local profiles".into());
        self.notice = Some(format!(
            "Working · {scope}. Do not resubmit; the manager owns operation completion."
        ));
        let connector = self.connector.clone();
        let base = self.config_dir.clone();
        let program_override = self.options.gantry.clone();
        let managed = self.options.managed_gantry.clone();
        let (progress_tx, progress_rx) = std::sync::mpsc::sync_channel::<String>(16);
        let progress_scope = scope.clone();
        self.progress_task = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(std::time::Duration::from_millis(100))
                    .await;
                let message = progress_rx.try_iter().last();
                if this
                    .update(cx, |this, cx| {
                        if this.generation != generation || !this.writing {
                            return false;
                        }
                        if let Some(message) = message {
                            this.record_activity(
                                generation,
                                crate::activity::Phase::Working,
                                &message,
                            );
                            this.notice = Some(format!("{progress_scope} · {message}"));
                            cx.notify();
                        }
                        true
                    })
                    .ok()
                    != Some(true)
                {
                    break;
                }
            }
        }));
        let request = cx.background_spawn(async move {
            match intent {
                Intent::Manager(command) => connector
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Manager connector failed"))?
                    .execute_with_progress(
                        &target.ok_or_else(|| anyhow::anyhow!("No verified action target"))?,
                        &command,
                        |message| {
                            let _ = progress_tx.try_send(workspace::text(message));
                        },
                    ),
                intent => {
                    let program =
                        launcher::executable(program_override.as_deref(), managed.as_deref())?;
                    let base = base
                        .ok_or_else(|| anyhow::anyhow!("Cannot locate the client profile store"))?;
                    let message = local_profiles::apply(&program, &base, &intent)?;
                    Ok(Outcome {
                        message,
                        packets: None,
                    })
                }
            }
        });
        self.action_task = Some(cx.spawn(async move |this, cx| {
            let result = request.await;
            let _ = this.update(cx, |this, cx| {
                if this.generation != generation {
                    return;
                }
                this.writing = false;
                // Require a fresh snapshot before another write, including after
                // ambiguous failures. Never expose stale action eligibility.
                this.control_available = false;
                match result {
                    Ok(outcome) => {
                        this.record_activity(
                            generation,
                            crate::activity::Phase::Complete,
                            &outcome.message,
                        );
                        this.notice =
                            Some(format!("{scope} · {}", workspace::text(&outcome.message)));
                        if let Some((sandbox, packets)) = outcome.packets {
                            this.packet_sandbox = Some(sandbox);
                            // Start, clear and stop begin the count again.
                            this.capture_rate.clear();
                            this.capture_rate
                                .record(&packets.packets, gantry_desktop::clock::now_millis());
                            this.packets = packets;
                            this.packet_error = None;
                        }
                    }
                    Err(error) => {
                        this.record_activity(
                            generation,
                            crate::activity::Phase::Failed,
                            &error.to_string(),
                        );
                        this.notice =
                            Some(format!("{scope} · {}", workspace::text(&error.to_string())))
                    }
                }
                this.sync_pages(cx);
                this.fetch(false, cx);
                cx.notify();
            });
        }));
        cx.notify();
    }
    pub fn edit_selected_sandbox(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(row) = self.inventory.selected() {
            let name = row.name.clone();
            let target = self.target.clone();
            self.row_action(
                &name,
                target.as_ref(),
                crate::row_actions::RowAction::Edit,
                window,
                cx,
            );
        }
    }
    pub fn remove_selected(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(row) = self.selected_record(cx) {
            match forms::remove(&row) {
                Ok(kind) => self.open_form(kind, window, cx),
                Err(error) => {
                    self.notice = Some(error.to_string());
                    cx.notify();
                }
            }
        }
    }
    pub fn sandbox_action(&mut self, action: &str, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(row) = self.inventory.selected() {
            let name = row.name.clone();
            let action = match action {
                "start" => crate::row_actions::RowAction::Start,
                "stop" => crate::row_actions::RowAction::Stop,
                "delete" => crate::row_actions::RowAction::Delete,
                _ => return,
            };
            let target = self.target.clone();
            self.row_action(&name, target.as_ref(), action, window, cx);
        }
    }
    pub fn inline_form(&self) -> bool {
        self.form
            .as_ref()
            .is_some_and(|f| matches!(f.spec.kind, Kind::Configure(_)))
    }
    pub fn form_layer(&self, cx: &mut Context<Self>) -> gpui_kit::Stateful<Div> {
        if self.form.is_none() || self.inline_form() {
            return div().id("no-modal");
        }
        div()
            .id("form-overlay")
            .absolute()
            .inset_0()
            .occlude()
            .flex()
            .items_center()
            .justify_center()
            .p_4()
            .bg(gpui_kit::black().opacity(0.35))
            .child(self.form_content(false, cx))
    }
    pub fn form_content(&self, inline: bool, cx: &mut Context<Self>) -> gpui_kit::AnyElement {
        let Some(form) = &self.form else {
            return div().id("no-form").into_any_element();
        };
        let enabled = form.picking_path.is_none()
            && if form.spec.local() {
                self.can_edit_profiles()
            } else {
                self.can_write() && form.target == self.target
            };
        div()
            .id("action-form")
            .test_support()
            .focus_trap("action-form", &form.focus)
            .flex()
            .flex_col()
            .size_full()
            .when(!inline, |d| {
                d.w(px(560.))
                    .h(px(if form.spec.fields.is_empty() {
                        280.
                    } else {
                        580.
                    }))
                    .max_h_full()
                    .rounded(px(8.))
                    .border_1()
                    .border_color(cx.theme().border)
                    .shadow_lg()
            })
            .gap_3()
            .p_5()
            .bg(cx.theme().secondary)
            .child(
                div()
                    .text_size(px(17.))
                    .child(if let Kind::Configure(r) = &form.spec.kind {
                        format!("Settings · {}", r.name)
                    } else {
                        form.spec.title.clone()
                    }),
            )
            .child(
                div()
                    .text_size(px(12.))
                    .text_color(cx.theme().primary)
                    .child(workspace::text(&form.scope)),
            )
            .child(
                div()
                    .text_size(px(12.))
                    .text_color(cx.theme().muted_foreground)
                    .child(form.spec.help.clone()),
            )
            .children(form.error.as_ref().map(|error| {
                div()
                    .text_color(cx.theme().danger)
                    .child(workspace::text(error))
            }))
            .child(div().flex_1().min_h_0().overflow_y_scrollbar().child(
                div().flex().flex_col().gap_3().children(
                    form.spec.fields.iter().zip(&form.inputs).enumerate().map(
                        |(index, (field, input))| {
                            let label = div().text_size(px(12.)).child(field.label.clone());
                            let controls = match &field.kind {
                                FieldKind::Resource(range) => {
                                    self.resource_control(index, *range, enabled, cx)
                                }
                                FieldKind::Path(kind) => {
                                    self.path_control(index, *kind, enabled, cx)
                                }
                                FieldKind::Bool => {
                                    let checked = input.value(cx).as_ref() == "true";
                                    div().child(
                                        Switch::new(("form-toggle", index))
                                            .small()
                                            .accessibility_label(field.label.clone())
                                            .label(if checked { "On" } else { "Off" })
                                            .checked(checked)
                                            .disabled(!enabled)
                                            .on_click(cx.listener(move |this, _, window, cx| {
                                                if let Some(form) = &this.form {
                                                    form.inputs[index].set_value(
                                                        if checked { "false" } else { "true" },
                                                        window,
                                                        cx,
                                                    );
                                                    cx.notify();
                                                }
                                            })),
                                    )
                                }
                                FieldKind::Select(options) => {
                                    self.select_control(index, field, options, enabled, cx)
                                }
                                FieldKind::Choice(choices) => {
                                    div().flex().flex_wrap().gap_1().children(
                                        choices.iter().enumerate().map(|(choice_index, value)| {
                                            let selected = input.value(cx).as_ref() == value;
                                            let value = value.clone();
                                            Button::new(gpui_kit::SharedString::from(format!(
                                                "form-choice-{index}-{choice_index}"
                                            )))
                                            .small()
                                            .label(value.clone())
                                            .disabled(!enabled)
                                            .selected(selected)
                                            .on_click(cx.listener(move |this, _, window, cx| {
                                                if let Some(form) = &this.form {
                                                    form.inputs[index].set_value(
                                                        value.clone(),
                                                        window,
                                                        cx,
                                                    );
                                                    cx.notify();
                                                }
                                            }))
                                        }),
                                    )
                                }
                                _ => match input {
                                    FormInput::Single(input) => div().child(
                                        Input::new(input)
                                            .id(("form-input", index))
                                            .disabled(!enabled),
                                    ),
                                    FormInput::Multiline(input) => div().child(
                                        div()
                                            .id(("form-input", index))
                                            .test_support()
                                            .child(Textarea::new(input).disabled(!enabled)),
                                    ),
                                },
                            };
                            div().flex().flex_col().gap_1().child(label).child(controls)
                        },
                    ),
                ),
            ))
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap_2()
                    .child(
                        Button::new("form-cancel").label("Cancel").on_click(
                            cx.listener(|this, _, window, cx| this.close_form(window, cx)),
                        ),
                    )
                    .child(
                        Button::new("form-submit")
                            .primary()
                            .label(if inline { "Save Changes" } else { "Confirm" })
                            .disabled(!enabled)
                            .on_click(
                                cx.listener(|this, _, window, cx| this.submit_form(window, cx)),
                            ),
                    ),
            )
            .into_any_element()
    }
}
