//! Transport selection and local-start policy, separate from the HTTP API.

use crate::{
    api::{self, ManagerClient, Snapshot},
    launcher,
    options::{Options, Source},
    profiles,
};
use anyhow::{Result, bail, ensure};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq)]
pub struct Target {
    pub source: Source,
    pub profile: Option<profiles::RemoteProfile>,
}
impl Target {
    pub fn label(&self) -> String {
        match &self.profile {
            Some(profile) => format!("{} · {}", profile.name, profile.url),
            None => self.source.description(),
        }
    }
}
pub struct WorkspaceSnapshot {
    pub inventory: Snapshot,
    pub dashboard: Option<crate::dashboard_wire::HostSnapshot>,
    pub target: Target,
}
fn resolve(source: &Source) -> Result<(ManagerClient, Target)> {
    let (client, profile) = match source {
        Source::Local(socket) => (ManagerClient::local(socket)?, None),
        Source::Remote { name, config_dir } => {
            let (profile, token) = profiles::load(config_dir, name)?;
            (
                ManagerClient::remote(&profile, token.expose())?,
                Some(profile),
            )
        }
        Source::Demo => bail!("Demo mode cannot send requests"),
    };
    Ok((
        client,
        Target {
            source: source.clone(),
            profile,
        },
    ))
}

type Locate = fn(Option<&Path>, Option<&Path>) -> Option<PathBuf>;

pub struct Connector {
    source: Source,
    auto_start: bool,
    gantry: Option<PathBuf>,
    managed: Option<PathBuf>,
    locate: Locate,
    start_attempted: bool,
    start_error: Option<String>,
    cli_missing: bool,
}

impl Connector {
    pub fn new(options: &Options) -> Self {
        Self {
            source: options.source.clone(),
            auto_start: options.auto_start,
            gantry: options.gantry.clone(),
            managed: options.managed_gantry.clone(),
            locate: launcher::locate,
            start_attempted: false,
            start_error: None,
            cli_missing: false,
        }
    }

    fn missing(&self) -> anyhow::Error {
        launcher::CliMissing {
            managed: self.managed.clone(),
        }
        .into()
    }

    /// At most one automatic launch per window. Polling always reconnects, but
    /// does not create an endless respawn loop. An explicit Refresh permits a
    /// new attempt; custom sockets and remotes never invoke a local launcher.
    pub fn snapshot(&mut self, retry_start: bool) -> Result<Snapshot> {
        if self.source == Source::Demo {
            return Ok(Snapshot {
                version: "demo".into(),
                sandboxes: crate::inventory::demo_sandboxes(),
                capabilities: vec!["dashboard-control-v1".into()],
            });
        }
        self.read(retry_start, |client, _| client.snapshot())
    }

    pub fn workspace(&mut self, retry_start: bool) -> Result<WorkspaceSnapshot> {
        if self.source == Source::Demo {
            return Ok(WorkspaceSnapshot {
                inventory: self.snapshot(false)?,
                dashboard: Some(crate::workspace::demo()),
                target: Target {
                    source: Source::Demo,
                    profile: None,
                },
            });
        }
        self.read(retry_start, |client, target| {
            let inventory = client.snapshot()?;
            let dashboard = match client.dashboard() {
                Ok(snapshot) => Some(snapshot),
                Err(error)
                    if error
                        .downcast_ref::<api::ManagerError>()
                        .is_some_and(|e| matches!(e.status, 404 | 501)) =>
                {
                    None
                }
                Err(error) => return Err(error),
            };
            Ok(WorkspaceSnapshot {
                inventory,
                dashboard,
                target,
            })
        })
    }

    /// Mutations never bootstrap or retry. A replaced URL/CA/pin invalidates an
    /// open form even if its profile alias is unchanged. Token rotation at the
    /// same authenticated origin is safe and takes effect on the next action.
    pub fn execute(
        &self,
        target: &Target,
        command: &crate::commands::Command,
    ) -> Result<crate::commands::Outcome> {
        self.execute_with_progress(target, command, |_| {})
    }

    pub fn execute_with_progress(
        &self,
        target: &Target,
        command: &crate::commands::Command,
        progress: impl Fn(&str),
    ) -> Result<crate::commands::Outcome> {
        let (client, current) = resolve(&self.source)?;
        ensure!(
            &current == target,
            "The selected connection changed. Refresh and reopen the form; no write was sent."
        );
        client.execute_with_progress(command, progress)
    }

    /// Live packet reads for the verified target; see
    /// [`ManagerClient::read_packets`].
    pub fn read_packets(
        &self,
        target: &Target,
        name: &str,
        after: u64,
    ) -> Result<crate::dashboard_wire::PacketSnapshot> {
        let (client, current) = resolve(&self.source)?;
        ensure!(&current == target, "The selected connection changed");
        client.read_packets(name, after)
    }

    fn read<T>(
        &mut self,
        retry_start: bool,
        read: impl Fn(ManagerClient, Target) -> Result<T>,
    ) -> Result<T> {
        if retry_start {
            self.start_attempted = false;
            self.start_error = None;
            self.cli_missing = false;
        }
        match resolve(&self.source).and_then(|(client, target)| read(client, target)) {
            Ok(value) => {
                self.start_error = None;
                return Ok(value);
            }
            Err(error)
                if matches!(self.source, Source::Local(_))
                    && self.auto_start
                    && api::is_absent(&error) => {}
            Err(error) => return Err(error),
        }
        // A CLI that appeared after a missing-CLI attempt (installed from the
        // desktop or by the user) earns exactly one new automatic attempt.
        let locate = self.locate;
        let program = locate(self.gantry.as_deref(), self.managed.as_deref());
        if self.start_attempted && !(self.cli_missing && program.is_some()) {
            if self.cli_missing {
                return Err(self.missing());
            }
            bail!("{}",self.start_error.as_deref().unwrap_or("The local manager is unavailable. Press Refresh to retry startup, or run gantry serve explicitly."));
        }
        self.start_attempted = true;
        let Source::Local(socket) = &self.source else {
            unreachable!()
        };
        self.cli_missing = program.is_none();
        let Some(program) = program else {
            let error = self.missing();
            self.start_error = Some(error.to_string());
            return Err(error);
        };
        if let Err(error) = launcher::ensure_local(socket, &program) {
            self.start_error = Some(error.to_string());
            return Err(error);
        }
        let (client, target) = resolve(&self.source)?;
        read(client, target)
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
            managed_gantry: None,
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
    fn a_missing_cli_latches_until_one_appears_then_launches_once() {
        let (dir, mut options, marker) = setup();
        let program = options.gantry.take().unwrap();
        let managed = dir.path().join("bin").join("gantry");
        options.managed_gantry = Some(managed.clone());
        let mut connector = Connector::new(&options);
        // Never consult the developer's own PATH or a real sibling CLI.
        connector.locate = |_, managed| managed.filter(|path| path.is_file()).map(Path::to_owned);
        for _ in 0..2 {
            let error = connector.snapshot(false).unwrap_err();
            assert!(
                error.downcast_ref::<launcher::CliMissing>().is_some(),
                "{error:#}"
            );
        }
        std::fs::create_dir(managed.parent().unwrap()).unwrap();
        std::fs::rename(&program, &managed).unwrap();
        // The newly installed CLI is launched without a manual retry...
        let error = connector.snapshot(false).unwrap_err();
        assert!(
            error.to_string().contains("test launcher refused"),
            "{error:#}"
        );
        // ...once: its failure then latches like any other startup failure.
        assert!(connector.snapshot(false).is_err());
        assert_eq!(std::fs::read(&marker).unwrap(), b"x");
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
