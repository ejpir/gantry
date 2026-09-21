//! Native form descriptions and typed intent construction. Go validates every
//! mutation; local checks only report basic input errors before a request.
use crate::{
    commands::{Command, CreateSandbox, name_path},
    dashboard_wire::*,
    wire::SecretInput,
    workspace::Record,
};
use anyhow::{Result, bail, ensure};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

#[derive(Clone)]
pub enum Kind {
    Create,
    Configure(SandboxConfigRequest),
    Rule(Option<RuleRequest>),
    Port,
    Share(Option<ShareRequest>),
    Secret,
    Mcp(Option<MCPRemoteRequest>),
    Filesystem,
    Pull,
    Registry,
    NetworkPolicy,
    Capture,
    Confirm(Command),
    RemoteAdd,
    RemoteRemove(String),
}
#[derive(Clone)]
pub enum FieldKind {
    Text,
    Password,
    Bool,
    Choice(Vec<String>),
}
#[derive(Clone)]
pub struct Field {
    pub key: &'static str,
    pub label: String,
    pub value: String,
    pub kind: FieldKind,
}
pub struct Spec {
    pub title: String,
    pub help: String,
    pub fields: Vec<Field>,
    pub kind: Kind,
}
pub enum Intent {
    Manager(Command),
    RemoteAdd {
        name: String,
        url: String,
        ca: String,
        pin: String,
        token: SecretInput,
    },
    RemoteRemove(String),
}
pub type Values = BTreeMap<String, Zeroizing<String>>;
fn field(key: &'static str, label: &str, value: impl ToString) -> Field {
    Field {
        key,
        label: label.into(),
        value: value.to_string(),
        kind: FieldKind::Text,
    }
}
fn toggle(key: &'static str, label: &str, value: bool) -> Field {
    Field {
        kind: FieldKind::Bool,
        ..field(key, label, value)
    }
}
fn choice(key: &'static str, label: &str, value: &str, choices: &[&str]) -> Field {
    Field {
        kind: FieldKind::Choice(choices.iter().map(|s| s.to_string()).collect()),
        ..field(key, label, value)
    }
}
fn password(key: &'static str, label: &str) -> Field {
    Field {
        kind: FieldKind::Password,
        ..field(key, label, "")
    }
}

impl Spec {
    pub fn new(kind: Kind, host: &HostSnapshot, sandbox: &str) -> Self {
        let mut fields = vec![];
        let mut help="Changes are validated and applied by the selected manager. They do not change which host is selected.".to_string();
        let sb = || field("sandbox", "Sandbox", sandbox);
        let title = match &kind {
            Kind::Create => {
                help="Create on this manager. Images must already be cached; use Images → Pull first. Writable disk and network changes are explicit.".into();
                fields = vec![
                    field("name", "Name", ""),
                    field(
                        "image",
                        "Cached image reference",
                        host.snapshot
                            .images
                            .first()
                            .map(|i| i.r#ref.as_str())
                            .unwrap_or(""),
                    ),
                    field("kernel", "Manager kernel (blank uses default)", ""),
                    field("runtime", "Runtime (blank uses default)", ""),
                    field("memory", "Memory MiB", 512),
                    field("cpus", "vCPUs", 1),
                    field(
                        "disk",
                        "Writable disk MiB (0 uses default)",
                        host.resource_limits.default_disk_size_mib,
                    ),
                    toggle("rw", "Writable filesystem", true),
                    toggle("net", "Networking", true),
                    toggle("ssh", "SSH", false),
                    toggle("devcontainers", "Dev containers (requires SSH)", false),
                    choice(
                        "isolation",
                        "Process isolation",
                        "auto",
                        &["auto", "required", "off"],
                    ),
                ];
                "Create sandbox"
            }
            Kind::Configure(r) => {
                fields = vec![
                    field("memory", "Saved memory MiB", r.mem_mb),
                    field("cpus", "Saved vCPUs", r.vcpus),
                    choice(
                        "isolation",
                        "Process isolation",
                        &r.process_isolation,
                        &["auto", "required", "off"],
                    ),
                    toggle("ssh", "SSH", r.ssh),
                    toggle(
                        "devcontainers",
                        "Dev containers (requires SSH)",
                        r.dev_containers,
                    ),
                ];
                help = format!(
                    "Edit saved settings for {}. The manager reports whether a restart is required; saving does not silently restart it.",
                    r.name
                );
                "Edit sandbox"
            }
            Kind::Rule(r) => {
                let r = r.clone().unwrap_or_default();
                fields = vec![
                    field(
                        "sandbox",
                        "Sandbox",
                        if r.sandbox.is_empty() {
                            sandbox
                        } else {
                            &r.sandbox
                        },
                    ),
                    choice(
                        "action",
                        "Action",
                        if r.action.is_empty() {
                            "allow"
                        } else {
                            &r.action
                        },
                        &["allow", "deny"],
                    ),
                    field("target", "IPv4 / CIDR, or domain for DNS rules", r.target),
                    choice(
                        "proto",
                        "Protocol",
                        if r.proto.is_empty() { "tcp" } else { &r.proto },
                        &["tcp", "udp", "icmp", "dns", "any"],
                    ),
                    field("ports", "Ports (blank means any)", r.ports),
                ];
                "Add network rule"
            }
            Kind::Port => {
                fields = vec![
                    sb(),
                    field("bind", "Host bind", "127.0.0.1:8080"),
                    field("guest", "Guest port", "80"),
                    toggle("udp", "UDP", false),
                ];
                "Publish port"
            }
            Kind::Share(r) => {
                let r = r.clone().unwrap_or(ShareRequest {
                    sandbox: sandbox.into(),
                    read_only: true,
                    ..Default::default()
                });
                fields = vec![
                    field("sandbox", "Sandbox", r.sandbox),
                    field("tag", "Tag", r.tag),
                    field("path", "Path on the manager host", r.path),
                    field(
                        "mountpoint",
                        "Guest mountpoint (blank uses default)",
                        r.mountpoint,
                    ),
                    field("owner", "Guest owner (optional UID:GID)", r.owner),
                    toggle("read_only", "Read-only mount", r.read_only),
                    toggle("replace", "Replace existing tag", r.replace),
                ];
                help="Paths are on the selected manager, not the desktop. Go plans and validates the mount before applying it. Runtime support determines live versus next-boot behavior.".into();
                "Configure mount"
            }
            Kind::Secret => {
                fields = vec![
                    sb(),
                    field("name", "Live environment secret name", ""),
                    password("value", "Value — write only"),
                ];
                help="Send one live, memory-only secret to this manager. The value is never returned in snapshots or written to desktop preferences. The form is cleared on submission.".into();
                "Add live secret"
            }
            Kind::Mcp(r) => {
                let r = r.clone().unwrap_or_default();
                fields = vec![
                    field(
                        "sandbox",
                        "Sandbox",
                        if r.sandbox.is_empty() {
                            sandbox
                        } else {
                            &r.sandbox
                        },
                    ),
                    field("name", "Server name", r.name),
                    field("url", "MCP HTTPS URL", r.url),
                    choice(
                        "auth_kind",
                        "Authentication kind",
                        if r.auth_kind.is_empty() {
                            "none"
                        } else {
                            &r.auth_kind
                        },
                        &["none", "bearer", "header", "custody"],
                    ),
                    field(
                        "auth_header",
                        "Custom header (if applicable)",
                        r.auth_header,
                    ),
                    field(
                        "auth_ref",
                        "Credential reference — not its value",
                        r.auth_ref,
                    ),
                    field(
                        "allow",
                        "Allowed tools (comma separated)",
                        r.allow.join(","),
                    ),
                    field("deny", "Denied tools (comma separated)", r.deny.join(",")),
                    field(
                        "redact",
                        "Redaction references (comma separated)",
                        r.redact.join(","),
                    ),
                    toggle("replace", "Replace existing server", r.replace),
                ];
                "Configure MCP remote"
            }
            Kind::Filesystem => {
                fields = vec![
                    sb(),
                    field("root", "Filesystem root on manager", ""),
                    field("user", "Guest user (optional)", ""),
                ];
                "Configure MCP filesystem"
            }
            Kind::Pull => {
                fields = vec![field("image", "OCI image reference", "")];
                help="Downloads into the selected manager's cache. The operation can continue after this window closes.".into();
                "Pull image"
            }
            Kind::Registry => {
                fields = vec![
                    field("registry", "Registry host", ""),
                    field("username", "Username", ""),
                    password("value", "Password / token — write only"),
                ];
                help="Stores a registry credential on the selected manager. It is never injected into a sandbox or returned in snapshots.".into();
                "Registry login"
            }
            Kind::NetworkPolicy => {
                fields = vec![
                    sb(),
                    toggle("default", "Restore default network policy", false),
                    field("policy", "Policy JSON (not a desktop file path)", ""),
                    toggle("allow_local", "Allow local-network access", false),
                ];
                "Set network policy"
            }
            Kind::Capture => {
                fields = vec![sb()];
                help="Explicitly enable bounded packet capture for this sandbox. Packets can contain sensitive data. Stop capture to disable recording and clear retained payloads.".into();
                "Start packet capture"
            }
            Kind::Confirm(command) => {
                help = format!(
                    "Confirm {} for {} on the host shown above. This may interrupt workloads or permanently remove data. No request is sent until you confirm.",
                    command.label(),
                    crate::workspace::text(&command.subject())
                );
                "Confirm action"
            }
            Kind::RemoteAdd => {
                fields = vec![
                    field("name", "Local profile name", ""),
                    field("url", "HTTPS manager origin", "https://"),
                    field("ca", "Public CA PEM path on this desktop (optional)", ""),
                    field("pin", "Optional sha256: leaf fingerprint", ""),
                    password("value", "Manager bearer token"),
                ];
                help="Client-local operation through Gantry's profile store. The CLI verifies the remote before storing it. Credentials go through stdin, never argv. Adding a profile does not switch your active host.".into();
                "Add remote profile"
            }
            Kind::RemoteRemove(name) => {
                help = format!(
                    "Remove local profile {name} and its stored credential. This does not delete or stop anything on that remote host."
                );
                "Remove remote profile"
            }
        };
        Self {
            title: title.into(),
            help,
            fields,
            kind,
        }
    }
    pub fn local(&self) -> bool {
        matches!(self.kind, Kind::RemoteAdd | Kind::RemoteRemove(_))
    }
    pub fn build(&self, values: &Values, host: &HostSnapshot) -> Result<Intent> {
        ensure!(
            values.values().map(|s| s.len()).sum::<usize>() <= 512 * 1024,
            "Form input exceeds 512 KiB"
        );
        let get = |k: &str| values.get(k).map(|s| s.as_str()).unwrap_or("");
        let required = |k: &str| -> Result<String> {
            let v = get(k).trim();
            ensure!(!v.is_empty(), "{k} is required");
            Ok(v.into())
        };
        let boolean = |k: &str| get(k) == "true";
        let number = |k: &str| -> Result<u64> {
            get(k)
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("{k} must be a non-negative whole number"))
        };
        let target = || -> Result<String> {
            let n = required("sandbox")?;
            name_path(&n)?;
            Ok(n)
        };
        let resource = || -> Result<(u64, i64)> {
            let mem = number("memory")?;
            let cpu = i64::try_from(number("cpus")?)?;
            let limits = &host.resource_limits;
            ensure!(
                mem > 0 && cpu > 0,
                "Memory and CPUs must be greater than zero"
            );
            ensure!(
                limits.min_memory_mb == 0 || mem >= limits.min_memory_mb,
                "Memory is below the manager's minimum"
            );
            ensure!(
                limits.max_memory_mb == 0 || mem <= limits.max_memory_mb,
                "Memory exceeds the manager's limit"
            );
            ensure!(
                limits.max_vcpus == 0 || cpu <= limits.max_vcpus,
                "CPUs exceed the manager's limit"
            );
            ensure!(
                !boolean("devcontainers") || boolean("ssh"),
                "Dev containers requires SSH"
            );
            Ok((mem, cpu))
        };
        let list = |k: &str| {
            get(k)
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        };
        let action = |r| Command::Dashboard(Box::new(r));
        let command = match &self.kind {
            Kind::Create => {
                let (memory_mib, cpus) = resource()?;
                let name = required("name")?;
                name_path(&name)?;
                Command::Create(CreateSandbox {
                    name,
                    image: required("image")?,
                    kernel: get("kernel").trim().into(),
                    runtime: get("runtime").trim().into(),
                    memory_mib,
                    cpus,
                    disk_size_mib: number("disk")?,
                    rw: boolean("rw"),
                    net: boolean("net"),
                    ssh: boolean("ssh"),
                    dev_containers: boolean("devcontainers"),
                    process_isolation: required("isolation")?,
                })
            }
            Kind::Configure(old) => {
                let (mem_mb, vcpus) = resource()?;
                Command::Configure(SandboxConfigRequest {
                    name: old.name.clone(),
                    mem_mb,
                    vcpus,
                    process_isolation: required("isolation")?,
                    ssh: boolean("ssh"),
                    dev_containers: boolean("devcontainers"),
                })
            }
            Kind::Rule(_) => action(ActionRequest {
                action: "add-rule".into(),
                rule_request: Some(RuleRequest {
                    sandbox: target()?,
                    action: required("action")?,
                    target: required("target")?,
                    proto: get("proto").into(),
                    ports: get("ports").trim().into(),
                }),
                ..Default::default()
            }),
            Kind::Port => Command::Port(
                target()?,
                PortRequest {
                    bind: required("bind")?,
                    guest: required("guest")?,
                    udp: boolean("udp"),
                },
            ),
            Kind::Share(_) => {
                let sandbox = target()?;
                let running = host
                    .snapshot
                    .sandboxes
                    .iter()
                    .any(|s| s.name == sandbox && s.state == "running");
                Command::Share(ShareRequest {
                    sandbox,
                    tag: required("tag")?,
                    path: required("path")?,
                    mountpoint: get("mountpoint").trim().into(),
                    owner: get("owner").trim().into(),
                    read_only: boolean("read_only"),
                    replace: boolean("replace"),
                    running,
                    current_guest: host
                        .snapshot
                        .mounts
                        .iter()
                        .find(|m| m.sandbox == get("sandbox") && m.tag == get("tag"))
                        .map(|m| m.guest.clone())
                        .unwrap_or_default(),
                })
            }
            Kind::Secret => {
                ensure!(!get("value").is_empty(), "Secret value is required");
                action(ActionRequest {
                    action: "add-secret".into(),
                    secret: Some(SecretRequest {
                        sandbox: target()?,
                        name: required("name")?,
                        value: SecretInput::new(get("value").into()),
                    }),
                    ..Default::default()
                })
            }
            Kind::Mcp(_) => action(ActionRequest {
                action: "configure-mcp-remote".into(),
                mcp_remote: Some(MCPRemoteRequest {
                    sandbox: target()?,
                    name: required("name")?,
                    url: required("url")?,
                    auth_kind: if get("auth_kind") == "none" {
                        String::new()
                    } else {
                        get("auth_kind").into()
                    },
                    auth_header: get("auth_header").trim().into(),
                    auth_ref: get("auth_ref").trim().into(),
                    allow: list("allow"),
                    deny: list("deny"),
                    redact: list("redact"),
                    replace: boolean("replace"),
                }),
                ..Default::default()
            }),
            Kind::Filesystem => action(ActionRequest {
                action: "configure-mcp-filesystem".into(),
                mcp_filesystem: Some(MCPFilesystemRequest {
                    sandbox: target()?,
                    root: required("root")?,
                    user: get("user").trim().into(),
                }),
                ..Default::default()
            }),
            Kind::Pull => Command::PullImage(required("image")?),
            Kind::Registry => {
                ensure!(!get("value").is_empty(), "Registry credential is required");
                action(ActionRequest {
                    action: "store-registry".into(),
                    registry: Some(RegistryLoginRequest {
                        registry: required("registry")?,
                        username: required("username")?,
                        secret: SecretInput::new(get("value").into()),
                    }),
                    ..Default::default()
                })
            }
            Kind::NetworkPolicy => {
                if !boolean("default") {
                    serde_json::from_str::<serde_json::Value>(get("policy"))
                        .map_err(|_| anyhow::anyhow!("Policy must be valid JSON"))?;
                }
                Command::NetworkPolicy {
                    sandbox: target()?,
                    policy: get("policy").into(),
                    default: boolean("default"),
                    allow_local: boolean("allow_local"),
                }
            }
            Kind::Capture => Command::Packets(
                target()?,
                PacketRequest {
                    start: true,
                    max_packets: 256,
                    max_bytes: 262144,
                    ..Default::default()
                },
            ),
            Kind::Confirm(command) => command.clone(),
            Kind::RemoteAdd => {
                let name = required("name")?;
                let url = required("url")?;
                let pin = get("pin").trim().to_owned();
                crate::profiles::RemoteProfile {
                    name: name.clone(),
                    url: url.clone(),
                    fingerprint: pin.clone(),
                    ca_cert: String::new(),
                }
                .validate()?;
                ensure!(
                    (16..=256).contains(&get("value").len())
                        && get("value").bytes().all(|b| (0x21..=0x7e).contains(&b)),
                    "Bearer must be 16–256 printable ASCII characters without spaces"
                );
                return Ok(Intent::RemoteAdd {
                    name,
                    url,
                    pin,
                    ca: get("ca").trim().into(),
                    token: SecretInput::new(get("value").into()),
                });
            }
            Kind::RemoteRemove(name) => return Ok(Intent::RemoteRemove(name.clone())),
        };
        Ok(Intent::Manager(command))
    }
}

pub fn remove(record: &Record) -> Result<Kind> {
    let mut action = ActionRequest::default();
    match record {
        Record::Rule(r) => {
            let mut r = r.clone();
            r.remote.clear();
            action.action = "remove-rule".into();
            action.rule = Some(r);
        }
        Record::Port(r) => {
            action.action = "unpublish-port".into();
            action.port = Some(PortMutationRequest {
                sandbox: r.sandbox.clone(),
                spec: format!("{}:{}/{}", r.bind, r.guest, r.proto),
            });
        }
        Record::Mount(r) => {
            let mut r = r.clone();
            r.remote.clear();
            action.action = "remove-share".into();
            action.mount = Some(r);
        }
        Record::Secret(r) => {
            let mut r = r.clone();
            r.remote.clear();
            action.action = "remove-secret".into();
            action.secret_row = Some(r);
        }
        Record::Mcp(r) => {
            ensure!(
                r.r#type == "remote",
                "Only remote MCP entries can be removed here"
            );
            let mut r = r.clone();
            r.remote.clear();
            action.action = "remove-mcp-remote".into();
            action.mcp_server = Some(r);
        }
        Record::Image(r) => {
            action.action = "remove-image".into();
            action.value = r.r#ref.clone();
        }
        Record::Registry(r) => {
            action.action = "remove-registry".into();
            action.value = r.registry.clone();
        }
        Record::Remote(r) => return Ok(Kind::RemoteRemove(r.name.clone())),
        _ => bail!("Select a removable configuration row"),
    }
    Ok(Kind::Confirm(Command::Dashboard(Box::new(action))))
}
