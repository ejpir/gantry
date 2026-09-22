//! Presentation-neutral pages and row identities. The selected connection, not
//! a server-supplied Remote field, is the authority for every row and action.
use crate::{dashboard_wire::*, profiles::RemoteProfile};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Page {
    Overview,
    #[default]
    Sandboxes,
    Traffic,
    Rules,
    Ports,
    Packets,
    Mounts,
    Secrets,
    Mcp,
    Audit,
    Images,
    Remotes,
}
impl Page {
    pub const ALL: [Self; 12] = [
        Self::Overview,
        Self::Sandboxes,
        Self::Traffic,
        Self::Rules,
        Self::Ports,
        Self::Packets,
        Self::Mounts,
        Self::Secrets,
        Self::Mcp,
        Self::Audit,
        Self::Images,
        Self::Remotes,
    ];
    pub fn index(self) -> usize {
        Self::ALL.iter().position(|p| *p == self).unwrap()
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Sandboxes => "Sandboxes",
            Self::Traffic => "Traffic",
            Self::Rules => "Rules",
            Self::Ports => "Ports",
            Self::Packets => "Packets",
            Self::Mounts => "Mounts",
            Self::Secrets => "Secrets",
            Self::Mcp => "MCP",
            Self::Audit => "Audit",
            Self::Images => "Images",
            Self::Remotes => "Remotes",
        }
    }
    pub fn columns(self) -> &'static [&'static str] {
        match self {
            Self::Overview | Self::Sandboxes => {
                &["Sandbox", "State", "Image", "CPU / MiB", "Network"]
            }
            Self::Traffic => &[
                "Sandbox",
                "Destination",
                "Protocol / port",
                "Decision",
                "TX / RX bytes",
            ],
            Self::Rules => &["Sandbox", "Action", "Target", "Protocol / ports", "Source"],
            Self::Ports => &["Sandbox", "Host bind", "Guest port", "Protocol", "State"],
            Self::Packets => &["Sequence", "Time", "Direction", "Decision", "Bytes"],
            Self::Mounts => &[
                "Sandbox",
                "Tag",
                "Host path",
                "Guest path",
                "Access / state",
            ],
            Self::Secrets => &["Sandbox", "Name / binding", "State", "", ""],
            Self::Mcp => &["Sandbox", "Server", "Type", "Endpoint / root", "State"],
            Self::Audit => &["Sandbox", "Event", "Effect", "Policy revision", "Error"],
            Self::Images => &[
                "Image / registry",
                "Kind",
                "Architecture / user",
                "Size / credential",
                "State / source",
            ],
            Self::Remotes => &["Profile", "HTTPS origin", "CA trust", "Leaf pin", "Scope"],
        }
    }
    pub fn help(self) -> &'static str {
        match self {
            Self::Overview => {
                "Host overview. Active resources are shown only when the manager can report them."
            }
            Self::Traffic => {
                "Observed sandbox traffic. Select a destination to create an allow or deny rule."
            }
            Self::Rules => {
                "Effective network rules. Organization-managed policy remains authoritative."
            }
            Self::Ports => {
                "Published ports belong to the selected manager host, not this desktop machine."
            }
            Self::Mounts => {
                "Host paths refer to the selected manager. Read-only mounts are the default."
            }
            Self::Secrets => {
                "Values are write-only, live, and memory-only. Snapshots show names and state, never values."
            }
            Self::Mcp => {
                "MCP server configuration and credential references, not credential values."
            }
            Self::Audit => {
                "Bounded security-event tails. These are not durable history or payload logs."
            }
            Self::Images => {
                "Cached images and registry credentials on the selected manager. Credentials never enter guests."
            }
            Self::Remotes => {
                "Profiles are stored on this desktop machine. Switching is explicit; failures never select another host."
            }
            Self::Packets => {
                "Capture is opt-in and bounded. Packets may contain sensitive payloads. Stop clears retained manager payloads."
            }
            Self::Sandboxes => "Your containers. Their own kernel.",
        }
    }
}

#[derive(Clone, Debug)]
pub enum Record {
    Sandbox(Box<Sandbox>),
    Traffic(Traffic),
    Rule(Rule),
    Port(Port),
    Mount(Mount),
    Secret(Secret),
    Mcp(MCPServer),
    Audit(AuditEvent),
    Image(Image),
    Registry(RegistryAuth),
    Remote(RemoteProfile),
    Packet(Packet),
}
#[derive(Clone, Debug)]
pub struct Row {
    pub key: String,
    pub cells: Vec<String>,
    pub record: Record,
}
fn key(parts: &[&str]) -> String {
    serde_json::to_string(parts).expect("string key")
}
fn yes(value: bool) -> String {
    if value { "yes" } else { "no" }.into()
}
fn decision(value: bool) -> String {
    if value { "Allowed" } else { "Denied" }.into()
}
pub fn text(value: &str) -> String {
    value
        .chars()
        .filter(|c| {
            !c.is_control() && !matches!(*c,'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}')
        })
        .take(2048)
        .collect()
}
impl Record {
    pub fn details(&self) -> Vec<(String, String)> {
        let value = match self {
            Self::Sandbox(v) => serde_json::to_value(v),
            Self::Traffic(v) => serde_json::to_value(v),
            Self::Rule(v) => serde_json::to_value(v),
            Self::Port(v) => serde_json::to_value(v),
            Self::Mount(v) => serde_json::to_value(v),
            Self::Secret(v) => serde_json::to_value(v),
            Self::Mcp(v) => serde_json::to_value(v),
            Self::Audit(v) => serde_json::to_value(v),
            Self::Image(v) => serde_json::to_value(v),
            Self::Registry(v) => serde_json::to_value(v),
            Self::Packet(v) => serde_json::to_value(v),
            Self::Remote(v) => {
                return vec![
                    ("Profile".into(), v.name.clone()),
                    ("HTTPS origin".into(), v.url.clone()),
                    (
                        "Trust".into(),
                        if v.ca_cert.is_empty() {
                            "System roots"
                        } else {
                            "Configured CA"
                        }
                        .into(),
                    ),
                    ("Leaf pin".into(), v.fingerprint.clone()),
                ];
            }
        }
        .unwrap_or_default();
        value
            .as_object()
            .into_iter()
            .flat_map(|o| o.iter())
            .filter(|(k, _)| k.as_str() != "Remote")
            .map(|(k, v)| (k.clone(), text(v.as_str().unwrap_or(&v.to_string()))))
            .collect()
    }
}

pub fn rows(
    page: Page,
    host: &HostSnapshot,
    profiles: &[RemoteProfile],
    packets: &PacketSnapshot,
) -> Vec<Row> {
    let data = &host.snapshot;
    let mut result: Vec<Row> = match page {
        Page::Overview | Page::Sandboxes => data
            .sandboxes
            .iter()
            .map(|r| Row {
                key: key(&[&r.name]),
                cells: vec![
                    r.name.clone(),
                    r.state.clone(),
                    r.image.clone(),
                    if r.state == "running" {
                        if r.active_available {
                            format!("{} / {}", r.active_vcpus, r.active_mem_mb)
                        } else {
                            "Unknown active allocation".into()
                        }
                    } else {
                        format!("{} / {}", r.vcpus, r.mem_mb)
                    },
                    yes(r.net),
                ],
                record: Record::Sandbox(Box::new(r.clone())),
            })
            .collect(),
        Page::Traffic => data
            .traffic
            .iter()
            .map(|r| Row {
                key: key(&[
                    &r.sandbox,
                    &r.host,
                    &r.address,
                    &r.protocol,
                    &r.port.to_string(),
                    &yes(r.allowed),
                ]),
                cells: vec![
                    r.sandbox.clone(),
                    if r.host.is_empty() {
                        r.address.clone()
                    } else {
                        r.host.clone()
                    },
                    format!("{} / {}", r.protocol, r.port),
                    decision(r.allowed),
                    format!("{} / {}", r.tx_bytes, r.rx_bytes),
                ],
                record: Record::Traffic(r.clone()),
            })
            .collect(),
        Page::Rules => data
            .rules
            .iter()
            .map(|r| Row {
                key: key(&[
                    &r.sandbox, &r.action, &r.target, &r.proto, &r.ports, &r.source, &r.policy,
                ]),
                cells: vec![
                    r.sandbox.clone(),
                    r.action.clone(),
                    r.target.clone(),
                    format!("{} / {}", r.proto, r.ports),
                    r.source.clone(),
                ],
                record: Record::Rule(r.clone()),
            })
            .collect(),
        Page::Ports => data
            .ports
            .iter()
            .map(|r| Row {
                key: key(&[&r.sandbox, &r.bind, &r.guest.to_string(), &r.proto]),
                cells: vec![
                    r.sandbox.clone(),
                    r.bind.clone(),
                    r.guest.to_string(),
                    r.proto.clone(),
                    r.state.clone(),
                ],
                record: Record::Port(r.clone()),
            })
            .collect(),
        Page::Mounts => data
            .mounts
            .iter()
            .map(|r| Row {
                key: key(&[&r.sandbox, &r.tag]),
                cells: vec![
                    r.sandbox.clone(),
                    r.tag.clone(),
                    r.host.clone(),
                    r.guest.clone(),
                    format!("{} / {}", if r.read_only { "RO" } else { "RW" }, r.state),
                ],
                record: Record::Mount(r.clone()),
            })
            .collect(),
        Page::Secrets => data
            .secrets
            .iter()
            .map(|r| Row {
                key: key(&[&r.sandbox, &r.name]),
                cells: vec![
                    r.sandbox.clone(),
                    r.name.clone(),
                    r.state.clone(),
                    String::new(),
                    String::new(),
                ],
                record: Record::Secret(r.clone()),
            })
            .collect(),
        Page::Mcp => data
            .mcp_servers
            .iter()
            .map(|r| Row {
                key: key(&[&r.sandbox, &r.name, &r.r#type]),
                cells: vec![
                    r.sandbox.clone(),
                    r.name.clone(),
                    r.r#type.clone(),
                    if r.url.is_empty() {
                        r.root.clone()
                    } else {
                        r.url.clone()
                    },
                    r.state.clone(),
                ],
                record: Record::Mcp(r.clone()),
            })
            .collect(),
        Page::Audit => data
            .audit
            .iter()
            .map(|r| Row {
                key: key(&[&r.sandbox, &r.line, &r.occurrence.to_string()]),
                cells: vec![
                    r.sandbox.clone(),
                    r.line.clone(),
                    r.decision
                        .as_ref()
                        .map(|d| d.effect.clone())
                        .unwrap_or_default(),
                    r.decision
                        .as_ref()
                        .map(|d| d.revision.clone())
                        .unwrap_or_default(),
                    r.error.clone(),
                ],
                record: Record::Audit(r.clone()),
            })
            .collect(),
        Page::Images => data
            .images
            .iter()
            .map(|r| Row {
                key: key(&["image", &r.r#ref, &r.digest]),
                cells: vec![
                    r.r#ref.clone(),
                    "Image".into(),
                    r.arch.clone(),
                    format!("{} bytes", r.size),
                    if r.in_use { "In use" } else { "Cached" }.into(),
                ],
                record: Record::Image(r.clone()),
            })
            .chain(data.registries.iter().map(|r| Row {
                key: key(&["registry", &r.registry]),
                cells: vec![
                    r.registry.clone(),
                    "Registry".into(),
                    r.username.clone(),
                    if r.has_secret { "Stored" } else { "Not stored" }.into(),
                    r.source.clone(),
                ],
                record: Record::Registry(r.clone()),
            }))
            .collect(),
        Page::Remotes => profiles
            .iter()
            .map(|r| Row {
                key: key(&[&r.name, &r.url, &r.fingerprint, &r.ca_cert]),
                cells: vec![
                    r.name.clone(),
                    r.url.clone(),
                    if r.ca_cert.is_empty() {
                        "System roots"
                    } else {
                        "Configured CA"
                    }
                    .into(),
                    if r.fingerprint.is_empty() {
                        "None"
                    } else {
                        "Pinned"
                    }
                    .into(),
                    "Client-local profile".into(),
                ],
                record: Record::Remote(r.clone()),
            })
            .collect(),
        Page::Packets => packets
            .packets
            .iter()
            .map(|r| Row {
                key: key(&[&r.sequence.to_string()]),
                cells: vec![
                    r.sequence.to_string(),
                    r.timestamp.clone(),
                    r.direction.clone(),
                    decision(r.allowed),
                    r.length.to_string(),
                ],
                record: Record::Packet(r.clone()),
            })
            .collect(),
    };
    for row in &mut result {
        for cell in &mut row.cells {
            *cell = text(cell);
        }
    }
    result
}

pub fn demo() -> HostSnapshot {
    let sandboxes = crate::inventory::demo_sandboxes()
        .into_iter()
        .map(|s| Sandbox {
            name: s.name,
            state: s.state,
            image: s.image_ref,
            mem_mb: s.desired.memory_mib,
            vcpus: s.desired.cpus.into(),
            active_available: s.active.is_some(),
            active_mem_mb: s.active.as_ref().map(|a| a.memory_mib).unwrap_or_default(),
            active_vcpus: s.active.as_ref().map(|a| a.cpus.into()).unwrap_or_default(),
            restart_required: s.restart_required,
            net: true,
            rw: true,
            ssh: true,
            process_isolation: "auto".into(),
            ..Default::default()
        })
        .collect();
    HostSnapshot {
        snapshot: DashboardData {
            sandboxes,
            traffic: vec![Traffic {
                sandbox: "dev".into(),
                host: "registry.example.test".into(),
                protocol: "tcp".into(),
                port: 443,
                allowed: true,
                tx_bytes: 4096,
                rx_bytes: 8192,
                ..Default::default()
            }],
            rules: vec![Rule {
                sandbox: "dev".into(),
                action: "allow".into(),
                target: "registry.example.test".into(),
                proto: "tcp".into(),
                ports: "443".into(),
                source: "sandbox".into(),
                ..Default::default()
            }],
            ports: vec![Port {
                sandbox: "dev".into(),
                bind: "127.0.0.1:8080".into(),
                guest: 80,
                proto: "tcp".into(),
                state: "active".into(),
                ..Default::default()
            }],
            mounts: vec![Mount {
                sandbox: "dev".into(),
                tag: "src".into(),
                host: "/demo/workspace".into(),
                guest: "/workspace".into(),
                read_only: true,
                state: "active".into(),
                ..Default::default()
            }],
            secrets: vec![Secret {
                sandbox: "dev".into(),
                name: "API_TOKEN@api.example.test".into(),
                state: "live".into(),
                ..Default::default()
            }],
            mcp_servers: vec![MCPServer {
                sandbox: "dev".into(),
                name: "docs".into(),
                r#type: "remote".into(),
                url: "https://docs.example.test/mcp".into(),
                state: "saved".into(),
                ..Default::default()
            }],
            audit: vec![AuditEvent {
                sandbox: "dev".into(),
                line: "Demo: policy allowed registry access".into(),
                ..Default::default()
            }],
            images: vec![Image {
                r#ref: "debian:stable".into(),
                arch: "arm64".into(),
                size: 150_000_000,
                in_use: true,
                ..Default::default()
            }],
            ..Default::default()
        },
        resource_limits: ResourceLimits {
            min_memory_mb: 128,
            max_memory_mb: 16384,
            max_vcpus: 8,
            default_disk_size_mib: 4096,
            ..Default::default()
        },
        kernel_choices: vec![],
    }
}
