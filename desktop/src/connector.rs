//! Transport selection and local-start policy, separate from the HTTP API.

use crate::{
    api::{self, ManagerClient, Snapshot},
    launcher,
    options::{Options, Source},
    profiles,
};
use anyhow::{Context, Result, bail};

pub struct Connector {
    source: Source,
    auto_start: bool,
    gantry: Option<std::path::PathBuf>,
    start_attempted: bool,
    start_error: Option<String>,
}

impl Connector {
    pub fn new(options: &Options) -> Self {
        Self {
            source: options.source.clone(),
            auto_start: options.auto_start,
            gantry: options.gantry.clone(),
            start_attempted: false,
            start_error: None,
        }
    }

    /// At most one automatic launch per window. Polling always reconnects, but
    /// does not create an endless respawn loop. An explicit Refresh permits a
    /// new attempt; custom sockets and remotes never invoke a local launcher.
    pub fn snapshot(&mut self, retry_start: bool) -> Result<Snapshot> {
        if retry_start {
            self.start_attempted = false;
            self.start_error = None;
        }
        match &self.source {
            Source::Local(socket) => {
                match api::snapshot(socket) {
                    Ok(snapshot) => {
                        self.start_error = None;
                        return Ok(snapshot);
                    }
                    Err(error) if self.auto_start && api::is_absent(&error) => {}
                    Err(error) => return Err(error),
                }
                if self.start_attempted {
                    bail!("{}", self.start_error.as_deref().unwrap_or("The local manager is unavailable. Press Refresh to retry startup, or run gantry serve explicitly."));
                }
                self.start_attempted = true;
                let program = launcher::executable(self.gantry.as_deref());
                if let Err(error) = launcher::ensure_local(socket, &program) {
                    self.start_error = Some(error.to_string());
                    return Err(error);
                }
                api::snapshot(socket)
                    .context("The local manager did not become usable after startup")
            }
            Source::Remote { name, config_dir } => {
                // Reload on each refresh: profile removal, CA changes and token
                // rotation must take effect without restarting the desktop.
                let (profile, token) = profiles::load(config_dir, name)?;
                ManagerClient::remote(&profile, token.expose())?.snapshot()
            }
            Source::Demo => Ok(Snapshot {
                version: "demo".into(),
                sandboxes: crate::inventory::demo_sandboxes(),
            }),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::options::Appearance;
    use std::os::unix::fs::PermissionsExt;

    fn setup() -> (tempfile::TempDir, Options, std::path::PathBuf) {
        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let marker = dir.path().join("launches");
        let program = dir.path().join("gantry");
        std::fs::write(
            &program,
            format!(
                "#!/bin/sh\nprintf x >> '{}'\nprintf 'test launcher refused startup' >&2\nexit 1\n",
                marker.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let options = Options {
            source: Source::Local(dir.path().join("manager.sock")),
            appearance: Appearance::Dark,
            auto_start: true,
            gantry: Some(program),
        };
        (dir, options, marker)
    }

    #[test]
    fn automatic_launch_is_latched_until_manual_retry() {
        let (_dir, options, marker) = setup();
        let mut connector = Connector::new(&options);
        for _ in 0..3 {
            let error = connector.snapshot(false).unwrap_err();
            assert!(
                error.to_string().contains("test launcher refused"),
                "{error:#}"
            );
        }
        assert_eq!(std::fs::read(&marker).unwrap(), b"x");
        assert!(connector.snapshot(true).is_err());
        assert_eq!(std::fs::read(&marker).unwrap(), b"xx");
    }

    #[test]
    fn custom_sockets_and_remote_failures_never_start_local_managers() {
        let (dir, mut options, marker) = setup();
        options.auto_start = false;
        assert!(Connector::new(&options).snapshot(true).is_err());
        assert!(!marker.exists());
        // Even a caller accidentally leaving auto_start true cannot turn a
        // remote profile error into a local connection or process launch.
        options.auto_start = true;
        options.source = Source::Remote {
            name: "team".into(),
            config_dir: dir.path().into(),
        };
        assert!(Connector::new(&options).snapshot(true).is_err());
        assert!(!marker.exists());
        options.source = Source::Demo;
        assert_eq!(
            Connector::new(&options)
                .snapshot(true)
                .unwrap()
                .sandboxes
                .len(),
            4
        );
        assert!(!marker.exists());
    }

    #[test]
    fn an_unsafe_or_non_socket_endpoint_is_not_an_autostart_signal() {
        let (_dir, options, marker) = setup();
        let Source::Local(path) = &options.source else {
            unreachable!()
        };
        std::fs::write(path, "not a socket").unwrap();
        assert!(Connector::new(&options).snapshot(false).is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), "not a socket");
        assert!(!marker.exists());
    }
}
