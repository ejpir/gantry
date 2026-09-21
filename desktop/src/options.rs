use std::{
    ffi::OsString,
    path::{Component, Path, PathBuf},
};

use anyhow::{Result, bail};

pub const HELP: &str = "Gantry Desktop — read-only local and remote sandbox inspector

Usage: gantry-desktop [--socket PATH | --remote NAME | --demo] [options]

  --socket PATH   Connect to an existing private manager socket (no autostart)
  --remote NAME   Use an existing gantry remote profile over verified HTTPS
  --no-start      Disable automatic startup of the default local manager
  --gantry PATH   Gantry executable for automatic startup (otherwise sibling/PATH)
  --demo          Show sample data; no connections or subprocesses
  --theme MODE    Initial appearance: system, dark, or light (default: system)
  -h, --help      Show this help

Local mode starts the default Unix-only manager on demand. --socket and
GANTRY_MANAGER_SOCKET are connect-only; remote errors never fall back to local.
GANTRY_HOME selects the same state tree as the CLI. Remote profiles are created
with gantry remote add; tokens are never passed on the desktop command line.
The desktop never starts, stops, or modifies sandboxes. Managers and VMs remain
independent of the GUI's lifetime. Local startup requires Linux or macOS.
";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    Local(PathBuf),
    Remote { name: String, config_dir: PathBuf },
    Demo,
}

impl Source {
    pub fn label(&self) -> String {
        match self {
            Self::Local(_) => "Local machine".into(),
            Self::Remote { name, .. } => format!("Remote · {name}"),
            Self::Demo => "Demo workspace".into(),
        }
    }

    pub fn description(&self) -> String {
        match self {
            Self::Local(path) => path.display().to_string(),
            Self::Remote { name, .. } => format!("Verified HTTPS · profile {name}"),
            Self::Demo => "No manager connection".into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Appearance {
    #[default]
    System,
    Dark,
    Light,
}

impl Appearance {
    pub fn label(self) -> &'static str {
        match self {
            Self::System => "System",
            Self::Dark => "Dark",
            Self::Light => "Light",
        }
    }

    pub fn next(self) -> Self {
        match self {
            Self::System => Self::Dark,
            Self::Dark => Self::Light,
            Self::Light => Self::System,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    pub source: Source,
    pub appearance: Appearance,
    pub auto_start: bool,
    pub gantry: Option<PathBuf>,
}

#[derive(Default)]
pub struct SocketDefaults {
    pub manager_socket: Option<PathBuf>,
    pub gantry_home: Option<PathBuf>,
    pub home: Option<PathBuf>,
}

impl SocketDefaults {
    pub fn from_env() -> Self {
        let path = |key| {
            std::env::var_os(key)
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        };
        Self {
            manager_socket: path("GANTRY_MANAGER_SOCKET"),
            gantry_home: path("GANTRY_HOME"),
            home: path("HOME").or_else(|| path("USERPROFILE")),
        }
    }

    fn resolve(&self) -> Result<PathBuf> {
        if let Some(path) = &self.manager_socket {
            return Ok(path.clone());
        }
        Ok(self.base()?.join("manager.sock"))
    }

    fn base(&self) -> Result<PathBuf> {
        if let Some(path) = &self.gantry_home {
            // Match filepath.Dir(filepath.Clean(GANTRY_HOME)) in the manager.
            // This is a lexical cleanup, not filesystem/symlink canonicalization.
            let path = clean_path(path);
            return Ok(path.parent().unwrap_or(&path).to_owned());
        }
        if let Some(path) = &self.home {
            return Ok(path.join(".gantry"));
        }
        bail!("Cannot locate the manager socket without a home directory; pass --socket PATH")
    }
}

pub(crate) fn clean_path(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => match result.components().next_back() {
                Some(Component::Normal(_)) => {
                    result.pop();
                }
                Some(Component::RootDir) => {}
                _ => result.push(component.as_os_str()),
            },
            _ => result.push(component.as_os_str()),
        }
    }
    if result.as_os_str().is_empty() {
        result.push(".");
    }
    result
}

impl Options {
    /// None means --help, which must work without a display or home directory.
    pub fn parse(
        args: impl IntoIterator<Item = OsString>,
        defaults: SocketDefaults,
    ) -> Result<Option<Self>> {
        let mut args = args.into_iter();
        let mut socket = None;
        let mut remote = None;
        let mut gantry = None;
        let mut no_start = false;
        let mut demo = false;
        let mut appearance = Appearance::System;
        while let Some(arg) = args.next() {
            match arg.to_str() {
                Some("-h" | "--help") => return Ok(None),
                Some("--demo") => demo = true,
                Some("--no-start") => no_start = true,
                Some("--remote") => {
                    if remote.is_some() {
                        bail!("--remote can only be specified once");
                    }
                    let name = args
                        .next()
                        .and_then(|value| value.into_string().ok())
                        .filter(|name| !name.starts_with("--"))
                        .ok_or_else(|| anyhow::anyhow!("--remote requires a profile name"))?;
                    crate::profiles::validate_name(&name)?;
                    remote = Some(name);
                }
                Some("--gantry") => {
                    if gantry.is_some() {
                        bail!("--gantry can only be specified once");
                    }
                    let path = args
                        .next()
                        .filter(|value| {
                            !value.is_empty() && !value.to_string_lossy().starts_with("--")
                        })
                        .ok_or_else(|| anyhow::anyhow!("--gantry requires an executable path"))?;
                    gantry = Some(PathBuf::from(path));
                }
                Some("--socket") => {
                    if socket.is_some() {
                        bail!("--socket can only be specified once");
                    }
                    let value = args
                        .next()
                        .filter(|value| {
                            !value.is_empty() && !value.to_string_lossy().starts_with("--")
                        })
                        .ok_or_else(|| anyhow::anyhow!("--socket requires a path"))?;
                    socket = Some(PathBuf::from(value));
                }
                Some("--theme") => {
                    appearance = match args.next().as_deref().and_then(|value| value.to_str()) {
                        Some("system") => Appearance::System,
                        Some("dark") => Appearance::Dark,
                        Some("light") => Appearance::Light,
                        _ => bail!("--theme requires system, dark, or light"),
                    };
                }
                _ => bail!(
                    "Unknown argument: {}. Use --help for usage.",
                    arg.to_string_lossy()
                ),
            }
        }
        if usize::from(demo) + usize::from(socket.is_some()) + usize::from(remote.is_some()) > 1 {
            bail!("--demo, --socket, and --remote are mutually exclusive");
        }
        let auto_start = !demo
            && remote.is_none()
            && socket.is_none()
            && defaults.manager_socket.is_none()
            && !no_start;
        if gantry.is_some() && !auto_start {
            bail!("--gantry is only used for automatic default-local startup");
        }
        if no_start && (demo || remote.is_some()) {
            bail!("--no-start only applies to local connections");
        }
        let source = if demo {
            Source::Demo
        } else if let Some(name) = remote {
            Source::Remote {
                name,
                config_dir: defaults.base()?,
            }
        } else {
            Source::Local(match socket {
                Some(path) => path,
                None => defaults.resolve()?,
            })
        };
        Ok(Some(Self {
            source,
            appearance,
            auto_start,
            gantry,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str], defaults: SocketDefaults) -> Result<Option<Options>> {
        Options::parse(args.iter().map(OsString::from), defaults)
    }

    #[test]
    fn default_path_matches_manager() {
        let defaults = SocketDefaults {
            home: Some("/home/test".into()),
            ..Default::default()
        };
        assert_eq!(
            parse(&[], defaults).unwrap().unwrap().source,
            Source::Local("/home/test/.gantry/manager.sock".into())
        );
    }

    #[test]
    fn socket_precedence_matches_manager() {
        let defaults = || SocketDefaults {
            manager_socket: Some("/private/override.sock".into()),
            gantry_home: Some("/state/sandboxes".into()),
            home: Some("/home/test".into()),
        };
        assert_eq!(
            parse(&[], defaults()).unwrap().unwrap().source,
            Source::Local("/private/override.sock".into())
        );
        assert_eq!(
            parse(&["--socket", "/explicit.sock"], defaults())
                .unwrap()
                .unwrap()
                .source,
            Source::Local("/explicit.sock".into())
        );
        let defaults = SocketDefaults {
            gantry_home: Some("/state/sandboxes/".into()),
            ..Default::default()
        };
        assert_eq!(
            parse(&[], defaults).unwrap().unwrap().source,
            Source::Local("/state/manager.sock".into())
        );
    }

    #[test]
    fn gantry_home_is_cleaned_before_selecting_its_parent() {
        for (home, expected) in [
            ("/state/old/../sandboxes/", "/state/manager.sock"),
            ("/state/sandboxes/..", "/manager.sock"),
            ("/", "/manager.sock"),
            ("sandboxes", "manager.sock"),
            ("../state/sandboxes", "../state/manager.sock"),
        ] {
            let defaults = SocketDefaults {
                gantry_home: Some(home.into()),
                ..Default::default()
            };
            assert_eq!(
                parse(&[], defaults).unwrap().unwrap().source,
                Source::Local(expected.into())
            );
        }
    }

    #[test]
    fn startup_is_default_local_only_and_can_be_disabled() {
        let defaults = || SocketDefaults {
            home: Some("/home/test".into()),
            ..Default::default()
        };
        assert!(parse(&[], defaults()).unwrap().unwrap().auto_start);
        assert!(
            !parse(&["--no-start"], defaults())
                .unwrap()
                .unwrap()
                .auto_start
        );
        assert!(
            !parse(&["--socket", "/tmp/explicit.sock"], defaults())
                .unwrap()
                .unwrap()
                .auto_start
        );
        let options = parse(&["--gantry", "/opt/gantry"], defaults())
            .unwrap()
            .unwrap();
        assert_eq!(options.gantry, Some("/opt/gantry".into()));
        let custom = SocketDefaults {
            manager_socket: Some("/explicit.sock".into()),
            ..defaults()
        };
        assert!(!parse(&[], custom).unwrap().unwrap().auto_start);
        let options = parse(&["--remote", "team"], defaults()).unwrap().unwrap();
        assert!(!options.auto_start);
        assert_eq!(
            options.source,
            Source::Remote {
                name: "team".into(),
                config_dir: "/home/test/.gantry".into()
            }
        );
    }

    #[test]
    fn target_selectors_never_silently_override_each_other() {
        let defaults = || SocketDefaults {
            home: Some("/home/test".into()),
            ..Default::default()
        };
        for args in [
            &["--remote", "team", "--socket", "/tmp/socket"][..],
            &["--remote", "team", "--demo"],
            &["--remote", "team", "--gantry", "gantry"],
            &["--socket", "/tmp/socket", "--gantry", "gantry"],
            &["--no-start", "--gantry", "gantry"],
            &["--demo", "--no-start"],
            &["--remote", "--demo"],
        ] {
            assert!(parse(args, defaults()).is_err(), "{args:?}");
        }
    }

    #[test]
    fn demo_is_explicit_and_does_not_require_home() {
        let options = parse(&["--demo", "--theme", "dark"], SocketDefaults::default())
            .unwrap()
            .unwrap();
        assert_eq!(options.source, Source::Demo);
        assert_eq!(options.appearance, Appearance::Dark);
        assert!(parse(&["--demo", "--socket", "x"], SocketDefaults::default()).is_err());
    }

    #[test]
    fn invalid_options_fail_instead_of_silently_connecting_elsewhere() {
        for args in [
            &["--remote", "team"][..],
            &["--socket"],
            &["--socket", "--demo"],
            &["--theme", "sepia"],
        ] {
            assert!(parse(args, SocketDefaults::default()).is_err());
        }
        assert!(parse(&[], SocketDefaults::default()).is_err());
        assert!(
            parse(&["--help"], SocketDefaults::default())
                .unwrap()
                .is_none()
        );
    }
}
