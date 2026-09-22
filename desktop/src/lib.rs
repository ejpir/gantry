//! Read-only manager client and presentation state, independent of GPUI.

pub mod api;
pub mod bootstrap;
pub mod commands;
pub mod forms;
pub mod wire;
pub mod workspace;
#[rustfmt::skip]
pub mod dashboard_wire;
pub mod connector;
pub mod inventory;
pub mod launcher;
pub mod local_profiles;
pub mod options;
mod profile_lock;
pub mod profiles;
mod security;
mod tls;
