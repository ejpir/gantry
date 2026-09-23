//! Native form descriptions and typed intent construction. Go validates every
//! mutation; local checks only report basic input errors before a request.
use crate::{
    commands::{Command, CreateSandbox, name_path},
    dashboard_wire::*,
    options::Source,
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
    /// Prefilled from a registry row when logging in again.
    Registry(Option<RegistryAuth>),
    NetworkPolicy,
    Capture,
    Confirm(Command),
    RemoteAdd,
    RemoteRemove(String),
    /// Organization forms carry what they were opened from; the policy
    /// service validates every write again.
    OrgEnroll {
        profiles: Vec<String>,
        rings: Vec<String>,
    },
    OrgRule(Box<OrgRuleForm>),
    OrgDns(Box<OrgDraft>),
    OrgPublish(Box<OrgPublishForm>),
    OrgMoveHost {
        name: String,
        ring: String,
        rings: Vec<String>,
    },
    OrgDownload(u64),
}

/// The draft a form edits: the document and the generation it is based on.
#[derive(Clone)]
pub struct OrgDraft {
    pub base: u64,
    pub document: crate::org::Document,
    pub profile: String,
}

#[derive(Clone)]
pub struct OrgRuleForm {
    pub draft: OrgDraft,
    /// A network (CIDR) rule rather than a mount, MCP or credential rule.
    pub network: bool,
    pub existing: Option<crate::org::PolicyItem>,
}

#[derive(Clone)]
pub struct OrgPublishForm {
    pub draft: OrgDraft,
    pub rings: Vec<String>,
    pub key_fingerprint: String,
    pub revision: String,
    pub changes: usize,
    pub loosens: usize,
    pub hosts: usize,
    pub gantry: Option<std::path::PathBuf>,
    pub managed: Option<std::path::PathBuf>,
}
#[derive(Clone)]
pub enum FieldKind {
    Text,
    Password,
    Bool,
    Choice(Vec<String>),
    /// A dropdown, for lists too long for a row of buttons.
    Select(Vec<String>),
    Resource(ResourceRange),
    Path(PathKind),
}

/// UI bounds only: exact text remains authoritative until Go validates the write.
#[derive(Clone, Copy, Debug)]
pub struct ResourceRange {
    pub min: u64,
    pub max: u64,
    pub step: u64,
    pub unit: &'static str,
}
impl ResourceRange {
    pub fn slider_value(self, value: f32) -> u64 {
        (value.round() as u64).clamp(self.min, self.max.max(self.min))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathKind {
    DesktopFile,
    /// A folder on this desktop machine, such as where to save files.
    DesktopDirectory,
    ManagerFile,
    ManagerDirectory,
    GuestDirectory,
}
impl PathKind {
    pub fn can_browse(self, source: &Source) -> bool {
        match self {
            Self::DesktopFile | Self::DesktopDirectory => !matches!(source, Source::Demo),
            Self::ManagerFile | Self::ManagerDirectory => matches!(source, Source::Local(_)),
            Self::GuestDirectory => false,
        }
    }
    pub fn directories(self) -> bool {
        matches!(
            self,
            Self::ManagerDirectory | Self::GuestDirectory | Self::DesktopDirectory
        )
    }
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
/// The sandbox a change targets, picked from the manager's sandboxes. A
/// prefilled name the snapshot no longer lists stays selectable, so an edit
/// never silently moves to another sandbox; Go still validates the name.
fn sandbox_field(host: &HostSnapshot, value: &str) -> Field {
    let mut names: Vec<String> = host
        .snapshot
        .sandboxes
        .iter()
        .map(|s| s.name.clone())
        .collect();
    names.sort();
    names.dedup();
    if !value.is_empty() && !names.iter().any(|name| name == value) {
        names.insert(0, value.to_owned());
    }
    let value = if value.is_empty() {
        names.first().cloned().unwrap_or_default()
    } else {
        value.to_owned()
    };
    Field {
        kind: FieldKind::Select(names),
        ..field("sandbox", "Sandbox", value)
    }
}
fn password(key: &'static str, label: &str) -> Field {
    Field {
        kind: FieldKind::Password,
        ..field(key, label, "")
    }
}

fn resource(key: &'static str, label: &str, value: impl ToString, range: ResourceRange) -> Field {
    Field {
        kind: FieldKind::Resource(range),
        ..field(key, label, value)
    }
}
fn path(key: &'static str, label: &str, value: impl ToString, kind: PathKind) -> Field {
    Field {
        kind: FieldKind::Path(kind),
        ..field(key, label, value)
    }
}

impl Spec {
    pub fn new(kind: Kind, host: &HostSnapshot, sandbox: &str) -> Self {
        let mut fields = vec![];
        let mut help="Changes are validated and applied by the selected manager. They do not change which host is selected.".to_string();
        let sb = || sandbox_field(host, sandbox);
        let limits = &host.resource_limits;
        // Unknown limits get a convenience range, not an invented manager limit.
        // Numeric entry still permits other values; build() and Go validate them.
        let memory = ResourceRange {
            min: limits.min_memory_mb.max(1),
            max: if limits.max_memory_mb > 0 {
                limits.max_memory_mb
            } else {
                65536.max(limits.min_memory_mb)
            },
            step: 128,
            unit: "MiB",
        };
        let cpus = ResourceRange {
            min: 1,
            max: if limits.max_vcpus > 0 {
                limits.max_vcpus as u64
            } else {
                64
            },
            step: 1,
            unit: "vCPUs",
        };
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
                    path(
                        "kernel",
                        "Manager kernel (blank uses default)",
                        "",
                        PathKind::ManagerFile,
                    ),
                    field("runtime", "Runtime (blank uses default)", ""),
                    resource(
                        "memory",
                        "Memory",
                        512_u64.clamp(memory.min, memory.max.max(memory.min)),
                        memory,
                    ),
                    resource("cpus", "CPU", 1, cpus),
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
                    resource("memory", "Saved memory", r.mem_mb, memory),
                    resource("cpus", "Saved CPU", r.vcpus, cpus),
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
                    sandbox_field(
                        host,
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
                    sandbox_field(host, &r.sandbox),
                    field("tag", "Tag", r.tag),
                    path(
                        "path",
                        "Folder on the manager host",
                        r.path,
                        PathKind::ManagerDirectory,
                    ),
                    path(
                        "mountpoint",
                        "Guest mountpoint (blank uses default)",
                        r.mountpoint,
                        PathKind::GuestDirectory,
                    ),
                    field("owner", "Guest owner (optional UID:GID)", r.owner),
                    toggle("read_only", "Read-only mount", r.read_only),
                    toggle("replace", "Replace existing tag", r.replace),
                ];
                help="The shared folder is on the selected manager. Browse is available for local managers only; guest mountpoints are always typed. Go plans and validates the mount before applying it.".into();
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
                    sandbox_field(
                        host,
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
                    path(
                        "root",
                        "Filesystem root inside the sandbox",
                        "",
                        PathKind::GuestDirectory,
                    ),
                    field("user", "Guest user (optional)", ""),
                ];
                "Configure MCP filesystem"
            }
            Kind::Pull => {
                fields = vec![field("image", "OCI image reference", "")];
                help="Downloads into the selected manager's cache. The operation can continue after this window closes.".into();
                "Pull image"
            }
            Kind::Registry(r) => {
                let r = r.clone().unwrap_or_default();
                fields = vec![
                    field("registry", "Registry host", &r.registry),
                    field(
                        "username",
                        "Username",
                        if r.has_secret {
                            r.username.as_str()
                        } else {
                            ""
                        },
                    ),
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
            Kind::Confirm(Command::Org(command)) => {
                help = format!(
                    "{} · {}. {} No request is sent until you confirm.",
                    command.label(),
                    crate::workspace::text(&command.subject()),
                    command.consequence()
                );
                "Confirm action"
            }
            Kind::Confirm(command) => {
                help = format!(
                    "Confirm {} for {} on the host shown above. This may interrupt workloads or permanently remove data. No request is sent until you confirm.",
                    command.label(),
                    crate::workspace::text(&command.subject())
                );
                "Confirm action"
            }
            Kind::OrgEnroll { profiles, rings } => {
                let select = |key, label: &str, options: &[String]| Field {
                    kind: FieldKind::Select(options.to_vec()),
                    ..field(key, label, options.first().cloned().unwrap_or_default())
                };
                fields = vec![
                    field("name", "Host name", ""),
                    select("profile", "Profile", profiles),
                    select("ring", "Ring", rings),
                    path(
                        "request",
                        "Certificate request (host.csr)",
                        "",
                        PathKind::DesktopFile,
                    ),
                    path(
                        "save",
                        "Save the host's files to a new folder",
                        "",
                        PathKind::DesktopDirectory,
                    ),
                ];
                help = "On the host, gantry policy feed-request -out DIR -host NAME makes a key that never leaves it and host.csr. The service signs only that request. Its answer (feed.json, host.pem, ca.pem, org-public.pem) is saved here to hand back; the host then runs gantry serve -policy-feed DIR/feed.json.".into();
                "Enroll host"
            }
            Kind::OrgRule(form) => {
                let existing = form.existing.as_ref();
                let effect = existing.map(|i| i.effect.as_str()).unwrap_or("allow");
                if form.network {
                    let rule = existing.and_then(|i| i.network.clone()).unwrap_or_default();
                    fields = vec![
                        field("id", "Rule ID", &rule.id),
                        choice("effect", "Effect", effect, &["allow", "deny"]),
                        field(
                            "cidr",
                            "CIDR",
                            if rule.cidr.is_empty() {
                                "0.0.0.0/0"
                            } else {
                                &rule.cidr
                            },
                        ),
                        choice(
                            "protocol",
                            "Protocol",
                            if rule.protocol.is_empty() {
                                "tcp"
                            } else {
                                &rule.protocol
                            },
                            &["tcp", "udp", "icmp", "any"],
                        ),
                        field(
                            "ports",
                            "Ports (tcp/udp; empty for all)",
                            rule.ports
                                .iter()
                                .map(u16::to_string)
                                .collect::<Vec<_>>()
                                .join(", "),
                        ),
                    ];
                } else {
                    let rule =
                        existing
                            .and_then(|i| i.rule.clone())
                            .unwrap_or_else(|| crate::org::Rule {
                                action: "mount.read".into(),
                                ..Default::default()
                            });
                    let target = match rule.action.as_str() {
                        "mount.read" | "mount.write" => rule.path.clone(),
                        "credential.use" => rule.host.clone(),
                        _ => rule.server.clone(),
                    };
                    fields = vec![
                        field("id", "Rule ID", &rule.id),
                        choice("effect", "Effect", effect, &["allow", "deny"]),
                        Field {
                            kind: FieldKind::Select(
                                crate::org::RULE_ACTIONS
                                    .iter()
                                    .map(|a| a.to_string())
                                    .collect(),
                            ),
                            ..field("action", "Action", &rule.action)
                        },
                        field("target", "Path, MCP server, or credential host", target),
                        field(
                            "tool",
                            "MCP tool (tool actions only; * for all)",
                            &rule.tool,
                        ),
                    ];
                }
                help = format!(
                    "Changes the {} draft only. Hosts are unaffected until the draft is signed and published. Deny wins over allow; anything not allowed is denied.",
                    form.draft.profile
                );
                match (form.network, existing.is_some()) {
                    (true, false) => "Add network rule",
                    (true, true) => "Edit network rule",
                    (false, false) => "Add access rule",
                    (false, true) => "Edit access rule",
                }
            }
            Kind::OrgDns(draft) => {
                fields = vec![field("name", "DNS name (*.example.com for subdomains)", "")];
                help = format!(
                    "Allow {} sandboxes to resolve this name. Changes the draft only.",
                    draft.profile
                );
                "Allow DNS name"
            }
            Kind::OrgPublish(form) => {
                fields = vec![
                    field("revision", "Revision", &form.revision),
                    field("days", "Expires in (days)", "30"),
                    path(
                        "key",
                        "Organization signing key (private PEM)",
                        "",
                        PathKind::DesktopFile,
                    ),
                    Field {
                        kind: FieldKind::Select(form.rings.clone()),
                        ..field(
                            "ring",
                            "Offer first to",
                            form.rings.first().cloned().unwrap_or_default(),
                        )
                    },
                ];
                help = format!(
                    "{} change{} ({} loosening access) for up to {} host{}. The Gantry CLI signs on this machine; only the signed bundle is uploaded, and it must verify with the key hosts pin ({}). Hosts in later rings wait until you promote.",
                    form.changes,
                    if form.changes == 1 { "" } else { "s" },
                    form.loosens,
                    form.hosts,
                    if form.hosts == 1 { "" } else { "s" },
                    crate::org::short_fingerprint(&form.key_fingerprint)
                );
                "Sign and publish"
            }
            Kind::OrgMoveHost { name, ring, rings } => {
                fields = vec![Field {
                    kind: FieldKind::Select(rings.clone()),
                    ..field("ring", "Ring", ring)
                }];
                help = format!(
                    "{name} follows its new ring from its next poll. A host is never offered an older generation than it already has."
                );
                "Move host"
            }
            Kind::OrgDownload(generation) => {
                fields = vec![path(
                    "save",
                    "Save to folder",
                    "",
                    PathKind::DesktopDirectory,
                )];
                help = format!(
                    "Saves generation {generation}'s signed bundle exactly as hosts receive it."
                );
                "Download bundle"
            }
            Kind::RemoteAdd => {
                fields = vec![
                    field("name", "Local profile name", ""),
                    field("url", "HTTPS manager origin", "https://"),
                    path(
                        "ca",
                        "Public CA PEM on this desktop (optional)",
                        "",
                        PathKind::DesktopFile,
                    ),
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
        // Paths can contain spaces, but must not be silently retargeted by
        // downstream path parsers that trim their input.
        for field in &self.fields {
            if matches!(field.kind, FieldKind::Path(_)) {
                let value = get(field.key);
                ensure!(
                    value == value.trim(),
                    "{} cannot begin or end with whitespace",
                    field.label
                );
            }
        }
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
            Kind::Registry(_) => {
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
            Kind::OrgEnroll { .. } => {
                let name = required("name")?;
                crate::org::validate_name(&name)?;
                Command::Org(crate::org::OrgCommand::Enroll {
                    name,
                    profile: required("profile")?,
                    ring: required("ring")?,
                    request: required("request")?.into(),
                    save_to: required("save")?.into(),
                })
            }
            Kind::OrgRule(form) => {
                use crate::org::{Edit, NetworkRule, Rule, apply_edit, parse_ports};
                let replacing = form.existing.as_ref().map(|i| i.id.clone());
                let edit = if form.network {
                    let protocol = required("protocol")?;
                    let ports = parse_ports(get("ports"))?;
                    ensure!(
                        ports.is_empty() || matches!(protocol.as_str(), "tcp" | "udp"),
                        "Ports require tcp or udp"
                    );
                    Edit::Network {
                        rule: NetworkRule {
                            id: required("id")?,
                            effect: required("effect")?,
                            cidr: required("cidr")?,
                            protocol,
                            ports,
                        },
                        replacing,
                    }
                } else {
                    let action = required("action")?;
                    let target = get("target").trim().to_owned();
                    let mut rule = Rule {
                        id: required("id")?,
                        effect: required("effect")?,
                        action: action.clone(),
                        ..Default::default()
                    };
                    match action.as_str() {
                        "mount.read" | "mount.write" => rule.path = target,
                        "credential.use" => rule.host = target,
                        "mcp.connect" => rule.server = target,
                        _ => {
                            rule.server = target;
                            rule.tool = required("tool")?;
                        }
                    }
                    Edit::Rule { rule, replacing }
                };
                let draft = &form.draft;
                Command::Org(crate::org::OrgCommand::SaveDraft {
                    base: draft.base,
                    document: apply_edit(&draft.document, &draft.profile, &edit)?,
                    summary: edit.summary(&draft.profile),
                })
            }
            Kind::OrgDns(draft) => {
                let edit = crate::org::Edit::AddDns(required("name")?);
                Command::Org(crate::org::OrgCommand::SaveDraft {
                    base: draft.base,
                    document: crate::org::apply_edit(&draft.document, &draft.profile, &edit)?,
                    summary: edit.summary(&draft.profile),
                })
            }
            Kind::OrgPublish(form) => {
                let revision = required("revision")?;
                ensure!(
                    revision.len() <= 128
                        && revision
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b)),
                    "Revision uses letters, digits, '.', '_', ':' or '-'"
                );
                let days = number("days")?;
                ensure!((1..=365).contains(&days), "Expiry must be 1 to 365 days");
                let mut document = form.draft.document.clone();
                document.revision = revision;
                document.expires_at =
                    crate::clock::format(crate::clock::now() + days as i64 * 86_400);
                Command::Org(crate::org::OrgCommand::Publish(Box::new(
                    crate::org::Publish {
                        base: form.draft.base,
                        document,
                        signing_key: required("key")?.into(),
                        first_ring: required("ring")?,
                        key_fingerprint: form.key_fingerprint.clone(),
                        gantry: form.gantry.clone(),
                        managed: form.managed.clone(),
                    },
                )))
            }
            Kind::OrgMoveHost { name, .. } => Command::Org(crate::org::OrgCommand::MoveHost {
                name: name.clone(),
                ring: required("ring")?,
            }),
            Kind::OrgDownload(generation) => Command::Org(crate::org::OrgCommand::Download {
                generation: *generation,
                save_to: required("save")?.into(),
            }),
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
