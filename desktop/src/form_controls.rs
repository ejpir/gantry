//! Stateful sliders and asynchronous native path prompts. These only edit the
//! current draft; Save/Confirm and the existing target checks own all writes.
use crate::{app::Desktop, ui_forms::FormInput};
use gantry_desktop::forms::{FieldKind, PathKind, ResourceRange, Spec};
use gpui_kit::component::{
    ActiveTheme, Disableable, Sizable,
    button::Button,
    input::{Input, InputEvent},
    slider::{Slider, SliderEvent, SliderState},
};
use gpui_kit::{
    AppContext, Context, Div, Entity, InteractiveElement, ParentElement, PathPromptOptions, Styled,
    Subscription, TestSupportExt, Window, div, prelude::FluentBuilder, px,
};
use std::collections::BTreeMap;

pub type ResourceSliders = BTreeMap<usize, Entity<SliderState>>;

impl Desktop {
    pub(crate) fn resource_sliders(
        &self,
        spec: &Spec,
        inputs: &[FormInput],
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> (ResourceSliders, Vec<Subscription>) {
        let mut sliders = BTreeMap::new();
        let mut subscriptions = vec![];
        for (index, field) in spec.fields.iter().enumerate() {
            let FieldKind::Resource(range) = field.kind else {
                continue;
            };
            let FormInput::Single(input) = &inputs[index] else {
                continue;
            };
            let slider = cx.new(|_| {
                SliderState::new()
                    .max(range.max.max(range.min) as f32)
                    .min(range.min as f32)
                    .step(range.step as f32)
                    .default_value(field.value.parse::<f32>().unwrap_or(range.min as f32))
            });
            subscriptions.push(cx.subscribe_in(
                &slider,
                window,
                move |this, slider, event, window, cx| {
                    let SliderEvent::Change(value) = event else {
                        return;
                    };
                    let Some(form) = &this.form else { return };
                    if form.sliders.get(&index) != Some(slider)
                        || form.target != this.target
                        || form.picking_path.is_some()
                        || range.max <= range.min
                        || !this.can_write()
                    {
                        return;
                    }
                    // The toolkit rounds before clamping, including at either
                    // endpoint. Keep both exact manager bounds reachable.
                    let position = slider.read(cx).percentage().end;
                    let value = if position <= 0. {
                        range.min
                    } else if position >= 1. {
                        range.max.max(range.min)
                    } else {
                        range.slider_value(value.end())
                    };
                    slider.update(cx, |state, cx| state.set_value(value as f32, window, cx));
                    form.inputs[index].set_value(value.to_string(), window, cx);
                    cx.notify();
                },
            ));
            subscriptions.push(cx.subscribe_in(
                input,
                window,
                move |this, input, event, window, cx| {
                    if !matches!(event, InputEvent::Change) {
                        return;
                    }
                    let Some(form) = &this.form else { return };
                    let Some(FormInput::Single(current)) = form.inputs.get(index) else {
                        return;
                    };
                    if current != input {
                        return;
                    }
                    if let Ok(value) = input.read(cx).value().trim().parse::<u64>()
                        && let Some(slider) = form.sliders.get(&index)
                    {
                        // Moving the thumb must not round/clamp the exact input
                        // or silently change an unusual saved configuration.
                        slider.update(cx, |state, cx| state.set_value(value as f32, window, cx));
                    }
                    cx.notify();
                },
            ));
            // Accessibility increment/decrement calls set_value without emitting
            // Change in this toolkit version. Mirror those notifications too.
            // Input-originated updates already match and must not round or clamp
            // the user's exact number (including values outside slider bounds).
            subscriptions.push(
                cx.observe_in(&slider, window, move |this, slider, window, cx| {
                    let Some(form) = &this.form else { return };
                    if form.sliders.get(&index) != Some(&slider)
                        || form.target != this.target
                        || form.picking_path.is_some()
                        || range.max <= range.min
                        || !this.can_write()
                    {
                        return;
                    }
                    let value = slider.read(cx).value().end();
                    let exact = form.inputs[index].value(cx).trim().parse::<u64>().ok();
                    if value.is_finite() && exact.map(|n| n as f32) != Some(value) {
                        form.inputs[index].set_value(
                            range.slider_value(value).to_string(),
                            window,
                            cx,
                        );
                        cx.notify();
                    }
                }),
            );
            sliders.insert(index, slider);
        }
        (sliders, subscriptions)
    }

    pub(crate) fn resource_control(
        &self,
        index: usize,
        range: ResourceRange,
        enabled: bool,
        cx: &mut Context<Self>,
    ) -> Div {
        let form = self.form.as_ref().unwrap();
        let FormInput::Single(input) = &form.inputs[index] else {
            unreachable!()
        };
        div()
            .flex()
            .flex_col()
            .gap_1()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        div()
                            .id(("form-slider", index))
                            .test_support()
                            .flex_1()
                            .min_w_0()
                            .px_2()
                            .child(
                                Slider::new(&form.sliders[&index])
                                    .bg(cx.theme().primary)
                                    .text_color(cx.theme().foreground)
                                    .disabled(!enabled || range.max <= range.min),
                            ),
                    )
                    .child(
                        div().w(px(84.)).flex_shrink_0().child(
                            Input::new(input)
                                .id(("form-input", index))
                                .aria_label(format!(
                                    "{} ({})",
                                    form.spec.fields[index].label, range.unit
                                ))
                                .disabled(!enabled),
                        ),
                    ),
            )
            .child(
                div()
                    .text_size(px(11.))
                    .text_color(cx.theme().muted_foreground)
                    .child(if range.max >= range.min {
                        format!("{}–{} {} · slider range", range.min, range.max, range.unit)
                    } else {
                        "Manager bounds unavailable; enter an exact value".into()
                    }),
            )
    }

    pub(crate) fn path_control(
        &self,
        index: usize,
        kind: PathKind,
        enabled: bool,
        cx: &mut Context<Self>,
    ) -> Div {
        let form = self.form.as_ref().unwrap();
        let FormInput::Single(input) = &form.inputs[index] else {
            unreachable!()
        };
        let browse = kind.can_browse(&self.options.source);
        div()
            .flex()
            .flex_col()
            .gap_1()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        div().flex_1().min_w_0().child(
                            Input::new(input)
                                .id(("form-input", index))
                                .aria_label(form.spec.fields[index].label.clone())
                                .disabled(!enabled),
                        ),
                    )
                    .when(browse, |d| {
                        d.child(
                            Button::new(("form-browse", index))
                                .small()
                                .label("Browse…")
                                .disabled(!enabled)
                                .on_click(cx.listener(move |this, _, window, cx| {
                                    this.browse_form_path(index, window, cx)
                                })),
                        )
                    }),
            )
            .when(!browse, |d| {
                d.child(
                    div()
                        .text_size(px(11.))
                        .text_color(cx.theme().muted_foreground)
                        .child(if kind == PathKind::GuestDirectory {
                            "Path inside the sandbox"
                        } else {
                            "Path on the remote manager; local browsing is unavailable"
                        }),
                )
            })
    }

    pub(crate) fn browse_form_path(
        &mut self,
        index: usize,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(form) = &self.form else { return };
        let Some(field) = form.spec.fields.get(index) else {
            return;
        };
        let FieldKind::Path(kind) = field.kind else {
            return;
        };
        let Some(FormInput::Single(input)) = form.inputs.get(index) else {
            return;
        };
        let allowed = if form.spec.local() {
            self.can_edit_profiles()
        } else {
            self.can_write() && form.target == self.target
        };
        if !allowed || !kind.can_browse(&self.options.source) || form.picking_path.is_some() {
            return;
        }
        // An entity id binds a late chooser response to this exact form field,
        // not a new form that happens to reuse the same index.
        let input_id = input.entity_id();
        let target = form.target.clone();
        let response = cx.prompt_for_paths(PathPromptOptions {
            files: !kind.directories(),
            directories: kind.directories(),
            multiple: false,
            prompt: Some(
                if kind.directories() {
                    "Choose Folder"
                } else {
                    "Choose File"
                }
                .into(),
            ),
        });
        self.form.as_mut().unwrap().picking_path = Some(index);
        cx.notify();
        cx.spawn_in(window, async move |this, cx| {
            let response = response.await;
            let _ = cx.update(|window, cx| this.update(cx, |this, cx| {
                let Some(form) = &this.form else { return };
                let Some(FormInput::Single(input)) = form.inputs.get(index) else { return };
                if input.entity_id() != input_id || form.picking_path != Some(index) { return; }
                let allowed = if form.spec.local() {
                    this.can_edit_profiles()
                } else {
                    this.can_write() && form.target == target && this.target == target
                };
                let form = this.form.as_mut().unwrap();
                form.picking_path = None;
                if !allowed {
                    form.error = Some("Connection changed or unavailable. Reopen this form; no path was applied.".into());
                } else {
                    match response {
                        Ok(Ok(Some(paths))) if paths.len() == 1 => {
                            let path = &paths[0];
                            match path.to_str().filter(|text| path.is_absolute() && !text.contains('\0')) {
                                Some(path) => {
                                    form.inputs[index].set_value(path.to_owned(), window, cx);
                                    form.error = None;
                                }
                                None => form.error = Some("Choose an absolute UTF-8 path. The previous value was kept.".into()),
                            }
                        }
                        Ok(Ok(None)) => {} // Cancel leaves the draft unchanged.
                        _ => form.error = Some("The system file picker is unavailable. Enter the path directly.".into()),
                    }
                }
                form.inputs[index].focus_handle(cx).focus(window, cx);
                cx.notify();
            }));
        }).detach();
    }
}
