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
    // An organization's policy service, when the connection is one.
    OrgHosts,
    OrgPolicy,
    OrgRollouts,
    OrgHistory,
    OrgEnrollment,
}
impl Page {
    pub const ALL: [Self; 17] = [
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
        Self::OrgHosts,
        Self::OrgPolicy,
        Self::OrgRollouts,
        Self::OrgHistory,
        Self::OrgEnrollment,
    ];
    /// The pages of an organization connection, in sidebar order.
    pub const ORGANIZATION: [Self; 5] = [
        Self::OrgHosts,
        Self::OrgPolicy,
        Self::OrgRollouts,
        Self::OrgHistory,
        Self::OrgEnrollment,
    ];
    pub fn is_organization(self) -> bool {
        Self::ORGANIZATION.contains(&self)
    }
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
            Self::OrgHosts => "Hosts",
            Self::OrgPolicy => "Policy",
            Self::OrgRollouts => "Rollouts",
            Self::OrgHistory => "History",
            Self::OrgEnrollment => "Enrollment",
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
                "Port",
                "Transfer",
                "Bytes",
                "Packets",
                "Seen",
                "Decision",
            ],
            Self::Rules => &["Sandbox", "Action", "Target", "Protocol / ports", "Source"],
            Self::Ports => &["Sandbox", "Host bind", "Guest port", "Protocol", "State"],
            Self::Packets => &["#", "Time", "Direction", "Decision", "Length", "Payload"],
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
            Self::OrgHosts | Self::OrgRollouts | Self::OrgEnrollment => {
                &["Host", "Profile", "Ring", "Status", "Certificate"]
            }
            Self::OrgPolicy => &["Effect", "Target", "Detail", "ID", "Change"],
            Self::OrgHistory => &["Generation", "Revision", "Published by", "Changes", "Hosts"],
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
            Self::OrgHosts => {
                "Enrolled host managers and the generation each last reported. Hosts pull; nothing is pushed into them."
            }
            Self::OrgPolicy => {
                "The draft of the next generation. Signing happens on this machine; the service only verifies."
            }
            Self::OrgRollouts => "The newest generation, ring by ring, as hosts acknowledge it.",
            Self::OrgHistory => "Every published generation. Numbers are never reused.",
            Self::OrgEnrollment => {
                "Host identities issued by this service, and what every host pins."
            }
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
    Org(crate::org::OrgRecord),
}
#[derive(Clone, Debug)]
pub struct Row {
    pub key: String,
    pub cells: Vec<String>,
    pub record: Record,
}
pub(crate) fn key(parts: &[&str]) -> String {
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
            Self::Org(crate::org::OrgRecord::Host(v)) => serde_json::to_value(v),
            Self::Org(crate::org::OrgRecord::Generation(v)) => serde_json::to_value(v),
            Self::Org(crate::org::OrgRecord::Change(v)) => serde_json::to_value(v),
            Self::Org(crate::org::OrgRecord::Item(v)) => {
                return vec![
                    ("Profile".into(), v.profile.clone()),
                    ("ID".into(), v.id.clone()),
                    ("Effect".into(), v.effect.clone()),
                    ("Target".into(), v.selector.clone()),
                    ("Detail".into(), v.detail.clone()),
                ];
            }
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
                    format!("{} {}", r.protocol, r.port),
                    // The transfer bar is drawn; its text is the direction split.
                    format!(
                        "↓ {} ↑ {}",
                        crate::telemetry::bytes_label(r.rx_bytes),
                        crate::telemetry::bytes_label(r.tx_bytes)
                    ),
                    crate::telemetry::bytes_label(r.tx_bytes.saturating_add(r.rx_bytes)),
                    r.tx_packets.saturating_add(r.rx_packets).to_string(),
                    r.last_seen.clone(),
                    decision(r.allowed),
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
        // Organization pages read the policy service snapshot (org::*_rows).
        Page::OrgHosts
        | Page::OrgPolicy
        | Page::OrgRollouts
        | Page::OrgHistory
        | Page::OrgEnrollment => vec![],
        Page::Packets => packets
            .packets
            .iter()
            .map(|r| Row {
                key: key(&[&r.sequence.to_string()]),
                cells: vec![
                    r.sequence.to_string(),
                    crate::clock::parse_millis(&r.timestamp)
                        .map(crate::clock::clock_millis)
                        .unwrap_or_else(|| r.timestamp.clone()),
                    // The recorder's direction is from the sandbox: tx leaves it.
                    if r.direction == "tx" { "out" } else { "in" }.into(),
                    decision(r.allowed),
                    format!(
                        "{} B",
                        crate::telemetry::count_label(r.length.max(0) as u64)
                    ),
                    // The preview shows 12 bytes and marks longer frames; 20
                    // base64 characters decode 15. Live capture rebuilds these
                    // rows every second.
                    crate::capture::decode_base64(&r.data[..r.data.len().min(20)])
                        .map(|bytes| crate::capture::hex_preview(&bytes, 12))
                        .unwrap_or_default(),
                ],
                record: Record::Packet(r.clone()),
            })
            .collect(),
    };
    if page == Page::Audit {
        // One timeline across sandboxes, newest first. Events recorded before
        // the trail carried timestamps keep the manager's order at the end.
        let time = |row: &Row| match &row.record {
            Record::Audit(r) => crate::clock::parse(&r.time),
            _ => None,
        };
        result.sort_by_key(|row| std::cmp::Reverse(time(row)));
    }
    if page == Page::Packets {
        // Newest frame first, as a live recorder reads.
        result.sort_by(|a, b| match (&a.record, &b.record) {
            (Record::Packet(a), Record::Packet(b)) => b.sequence.cmp(&a.sequence),
            _ => std::cmp::Ordering::Equal,
        });
    }
    if matches!(page, Page::Rules | Page::Mounts | Page::Secrets) {
        // Grouped by sandbox; within a sandbox, the manager's order.
        let sandbox = |row: &Row| match &row.record {
            Record::Rule(r) => r.sandbox.clone(),
            Record::Mount(r) => r.sandbox.clone(),
            Record::Secret(r) => r.sandbox.clone(),
            _ => String::new(),
        };
        result.sort_by_key(sandbox);
    }
    if page == Page::Images {
        // Registries with a login first, then by host; images keep the
        // manager's order.
        result.sort_by_key(|row| match &row.record {
            Record::Registry(r) => (1, !r.has_secret, r.registry.clone()),
            _ => (0, false, String::new()),
        });
    }
    if page == Page::Traffic {
        // Largest flows first, as the Traffic screen reads top-down by volume.
        let bytes = |row: &Row| match &row.record {
            Record::Traffic(r) => r.tx_bytes.saturating_add(r.rx_bytes),
            _ => 0,
        };
        result.sort_by(|a, b| bytes(b).cmp(&bytes(a)).then_with(|| a.key.cmp(&b.key)));
    }
    for row in &mut result {
        for cell in &mut row.cells {
            *cell = text(cell);
        }
    }
    result
}

impl Page {
    /// Segmented filter above a page's table; index 0 always shows everything.
    pub fn segments(self) -> &'static [&'static str] {
        match self {
            Self::Traffic => &["All", "Allowed", "Denied"],
            Self::Rules => &["All", "Allow", "Deny"],
            Self::Ports => &["All", "Bound", "Not bound"],
            Self::Mounts => &["All", "Read-only", "Read-write"],
            Self::Secrets => &["All", "Loaded", "Next start"],
            Self::Mcp => &["All", "Active", "Not active"],
            Self::Audit => &["All", "Allowed", "Denied"],
            Self::Images => &["All", "In use", "Unused"],
            Self::OrgHosts => &["All", "Current", "Behind", "Attention", "Silent"],
            Self::OrgPolicy => &["Rules", "Changes"],
            Self::OrgRollouts => &["All", "Acknowledged", "In progress", "Attention", "Held"],
            Self::OrgHistory => &["All", "Rollbacks"],
            Self::OrgEnrollment => &["All", "Active", "Expiring", "Revoked"],
            _ => &[],
        }
    }
}

/// Registries share the Images page, with their own segments.
pub const REGISTRY_SEGMENTS: &[&str] = &["All", "Logged in", "Anonymous"];

/// Whether a record belongs to the page's selected segment.
pub fn segment_matches(page: Page, segment: usize, record: &Record) -> bool {
    use crate::org::{self, OrgRecord};
    match (page, segment, record) {
        // The Policy page's first segment lists rules; its second, changes.
        (Page::OrgPolicy, 0, Record::Org(r)) => matches!(r, OrgRecord::Item(_)),
        (Page::OrgPolicy, 1, Record::Org(r)) => matches!(r, OrgRecord::Change(_)),
        (_, 0, _) => true,
        (Page::OrgHosts, 1, Record::Org(OrgRecord::Host(h))) => h.status == "current",
        (Page::OrgHosts, 2, Record::Org(OrgRecord::Host(h))) => org::behind(h),
        (Page::OrgHosts, 3, Record::Org(OrgRecord::Host(h))) => org::needs_attention(h),
        (Page::OrgHosts, 4, Record::Org(OrgRecord::Host(h))) => org::silent(h),
        (Page::OrgRollouts, 1, Record::Org(OrgRecord::Host(h))) => !h.held && h.status == "current",
        (Page::OrgRollouts, 2, Record::Org(OrgRecord::Host(h))) => org::behind(h),
        (Page::OrgRollouts, 3, Record::Org(OrgRecord::Host(h))) => org::needs_attention(h),
        (Page::OrgRollouts, 4, Record::Org(OrgRecord::Host(h))) => h.held,
        (Page::OrgHistory, 1, Record::Org(OrgRecord::Generation(g))) => g.republish_of != 0,
        (Page::OrgEnrollment, 1, Record::Org(OrgRecord::Host(h))) => !h.revoked,
        (Page::OrgEnrollment, 2, Record::Org(OrgRecord::Host(h))) => {
            !h.revoked
                && org::days_until(&h.certificate.not_after, crate::clock::now())
                    .is_some_and(|days| days <= 30)
        }
        (Page::OrgEnrollment, 3, Record::Org(OrgRecord::Host(h))) => h.revoked,
        (Page::Traffic, 1, Record::Traffic(r)) => r.allowed,
        (Page::Traffic, 2, Record::Traffic(r)) => !r.allowed,
        (Page::Rules, 1, Record::Rule(r)) => r.action == "allow",
        (Page::Rules, 2, Record::Rule(r)) => r.action == "deny",
        (Page::Ports, 1, Record::Port(r)) => r.state == "bound",
        (Page::Ports, 2, Record::Port(r)) => r.state != "bound",
        (Page::Mounts, 1, Record::Mount(r)) => r.read_only,
        (Page::Mounts, 2, Record::Mount(r)) => !r.read_only,
        (Page::Secrets, 1, Record::Secret(r)) => r.state == "loaded",
        (Page::Secrets, 2, Record::Secret(r)) => r.state != "loaded",
        (Page::Mcp, 1, Record::Mcp(r)) => r.state == "active" && r.error.is_empty(),
        (Page::Mcp, 2, Record::Mcp(r)) => r.state != "active" || !r.error.is_empty(),
        (Page::Audit, 1, Record::Audit(r)) => {
            r.decision.as_ref().is_some_and(|d| d.effect == "allow")
        }
        (Page::Audit, 2, Record::Audit(r)) => {
            r.decision.as_ref().is_some_and(|d| d.effect == "deny")
        }
        (Page::Images, 1, Record::Image(r)) => r.in_use,
        (Page::Images, 2, Record::Image(r)) => !r.in_use,
        (Page::Images, 1, Record::Registry(r)) => r.has_secret,
        (Page::Images, 2, Record::Registry(r)) => !r.has_secret,
        _ => true,
    }
}

fn demo_base() -> HostSnapshot {
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
                proto: "dns".into(),
                source: "domain".into(),
                policy: "/demo/policies/dev.json".into(),
                ..Default::default()
            }],
            ports: vec![Port {
                sandbox: "dev".into(),
                bind: "127.0.0.1:8080".into(),
                guest: 80,
                proto: "tcp".into(),
                state: "bound".into(),
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
                state: "loaded".into(),
                ..Default::default()
            }],
            mcp_servers: vec![MCPServer {
                sandbox: "dev".into(),
                name: "docs".into(),
                r#type: "remote".into(),
                url: "https://docs.example.test/mcp".into(),
                state: "active".into(),
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

/// Sample data for demo mode, which is labeled as such everywhere and never
/// used as a fallback. The first record of each list is kept stable for tests.
pub fn demo() -> HostSnapshot {
    let mut host = demo_base();
    let data = &mut host.snapshot;
    for sandbox in &mut data.sandboxes {
        let running = sandbox.state == "running";
        sandbox.traffic_available = running;
        match sandbox.name.as_str() {
            "dev" => {
                sandbox.dev_containers = true;
                sandbox.ports = 2;
                sandbox.secret_count = 2;
                sandbox.shares = 2;
                sandbox.tx_bytes = 1_620_000;
                sandbox.rx_bytes = 29_780_000;
            }
            "agent" => {
                sandbox.ports = 1;
                sandbox.secret_count = 2;
                sandbox.proxy_enforce = true;
                sandbox.tx_bytes = 38_000;
                sandbox.rx_bytes = 121_000;
            }
            "build" => {
                sandbox.shares = 1;
                sandbox.secret_count = 1;
            }
            "scratch" => {
                sandbox.net = false;
                sandbox.ssh = false;
            }
            _ => {}
        }
    }
    let flow = |sandbox: &str, host: &str, address: &str, port: u16, allowed, tx, rx| Traffic {
        sandbox: sandbox.into(),
        host: host.into(),
        address: address.into(),
        protocol: "tcp".into(),
        port,
        allowed,
        tx_bytes: tx,
        rx_bytes: rx,
        tx_packets: tx / 900 + 1,
        rx_packets: rx / 1200 + 1,
        ..Default::default()
    };
    data.traffic.extend([
        flow(
            "dev",
            "github.com",
            "192.0.2.10",
            443,
            true,
            310_000,
            17_900_000,
        ),
        flow(
            "dev",
            "registry.npmjs.org",
            "192.0.2.11",
            443,
            true,
            120_000,
            6_980_000,
        ),
        flow(
            "dev",
            "objects.githubusercontent.com",
            "192.0.2.12",
            443,
            true,
            60_000,
            3_340_000,
        ),
        flow("dev", "pypi.org", "192.0.2.13", 443, true, 40_000, 946_000),
        flow("dev", "", "169.254.169.254", 80, false, 0, 0),
        flow(
            "agent",
            "api.anthropic.com",
            "192.0.2.20",
            443,
            true,
            31_000,
            90_000,
        ),
        flow(
            "agent",
            "telemetry.example.net",
            "203.0.113.24",
            443,
            false,
            0,
            0,
        ),
    ]);
    // Rules as the manager derives them from each sandbox's policy.
    let rule =
        |sandbox: &str, action: &str, target: &str, proto: &str, ports: &str, source: &str| Rule {
            sandbox: sandbox.into(),
            action: action.into(),
            target: target.into(),
            proto: proto.into(),
            ports: ports.into(),
            source: source.into(),
            policy: match sandbox {
                "dev" => "/demo/policies/dev.json",
                "build" => "/demo/policies/build.json",
                _ => "built-in default",
            }
            .into(),
            ..Default::default()
        };
    data.rules.extend([
        rule("dev", "allow", "github.com", "dns", "", "domain"),
        rule("dev", "allow", "registry.npmjs.org", "dns", "", "domain"),
        rule("dev", "allow", "192.0.2.0/24", "tcp", "443", "rule 1"),
        rule(
            "dev",
            "deny",
            "IPv6 and non-IPv4 traffic",
            "ether",
            "",
            "built-in",
        ),
        rule("dev", "deny", "local networks", "any", "", "built-in"),
        rule("dev", "deny", "public internet", "any", "", "default"),
        rule(
            "dev",
            "deny",
            "169.254.0.0/16",
            "any",
            "",
            "org:acme:deny-metadata",
        ),
        rule(
            "dev",
            "deny",
            "unmatched organization egress",
            "any",
            "",
            "org:acme",
        ),
        rule(
            "agent",
            "allow",
            "proxy.example.test",
            "tcp",
            "3128",
            "proxy endpoint",
        ),
        rule(
            "agent",
            "deny",
            "all destinations",
            "tcp",
            "80,443",
            "proxy enforcement",
        ),
        rule(
            "agent",
            "resolve",
            "api.anthropic.com",
            "dns",
            "",
            "org:acme",
        ),
        rule("agent", "deny", "local networks", "any", "", "built-in"),
        rule("agent", "deny", "public internet", "any", "", "default"),
        rule("build", "allow", "proxy.golang.org", "dns", "", "domain"),
        rule("build", "deny", "local networks", "any", "", "built-in"),
        rule("build", "allow", "public internet", "any", "", "default"),
        rule("scratch", "off", "network disabled", "—", "", "config"),
    ]);
    // Relative to now, so ages read like a live session.
    let now = crate::clock::now();
    for (index, flow) in data.traffic.iter_mut().enumerate() {
        let seen = [4, 2, 31, 120, 5, 420, 12, 7][index % 8];
        flow.last_seen = crate::clock::format(now - seen);
        flow.first_seen = crate::clock::format(now - 740 - 30 * index as i64);
    }
    data.ports.extend([
        Port {
            sandbox: "dev".into(),
            bind: "127.0.0.1:2222".into(),
            guest: 22,
            proto: "tcp".into(),
            state: "bound".into(),
            ..Default::default()
        },
        Port {
            sandbox: "agent".into(),
            bind: "0.0.0.0:5173".into(),
            guest: 5173,
            proto: "tcp".into(),
            state: "bound".into(),
            ..Default::default()
        },
        Port {
            sandbox: "build".into(),
            bind: "127.0.0.1:6060".into(),
            guest: 6060,
            proto: "tcp".into(),
            state: "saved".into(),
            ..Default::default()
        },
    ]);
    data.mounts.extend([
        Mount {
            sandbox: "dev".into(),
            tag: "datasets".into(),
            host: "/demo/datasets".into(),
            vm: "/mnt/shares/datasets".into(),
            guest: "/data".into(),
            read_only: true,
            state: "active".into(),
            ..Default::default()
        },
        Mount {
            sandbox: "agent".into(),
            tag: "notes".into(),
            host: "/demo/agents/notes".into(),
            vm: "/mnt/shares/notes".into(),
            guest: "/notes".into(),
            read_only: false,
            uid: Some(1000),
            gid: Some(1000),
            state: "active".into(),
            ..Default::default()
        },
        Mount {
            sandbox: "agent".into(),
            tag: "cache".into(),
            host: "/demo/cache/pip".into(),
            vm: "/mnt/shares/cache".into(),
            guest: "/home/agent/.cache/pip".into(),
            read_only: false,
            state: "restart".into(),
            ..Default::default()
        },
        Mount {
            sandbox: "build".into(),
            tag: "go".into(),
            host: "/demo/go/pkg".into(),
            vm: "/mnt/shares/go".into(),
            guest: "/root/go/pkg".into(),
            read_only: false,
            state: "saved".into(),
            ..Default::default()
        },
    ]);
    data.mcp_servers.extend([
        MCPServer {
            sandbox: "dev".into(),
            name: "fs".into(),
            r#type: "local".into(),
            root: "/workspace".into(),
            user: "dev".into(),
            state: "active".into(),
            ..Default::default()
        },
        MCPServer {
            sandbox: "agent".into(),
            name: "linear".into(),
            r#type: "remote".into(),
            url: "https://mcp.linear.app/sse".into(),
            auth_kind: "bearer".into(),
            auth_ref: "LINEAR_TOKEN".into(),
            allow: vec![
                "list_issues".into(),
                "get_issue".into(),
                "create_comment".into(),
            ],
            deny: vec!["delete_issue".into()],
            redact: vec!["LINEAR_TOKEN".into()],
            state: "active".into(),
            ..Default::default()
        },
        MCPServer {
            sandbox: "agent".into(),
            name: "github".into(),
            r#type: "remote".into(),
            url: "https://api.githubcopilot.com/mcp/".into(),
            auth_kind: "custody".into(),
            auth_ref: "github".into(),
            allow: vec!["get_pull_request".into(), "list_commits".into()],
            state: "restart".into(),
            error: "upstream returned 401 Unauthorized".into(),
            ..Default::default()
        },
    ]);
    let secret = |sandbox: &str, name: &str, state: &str| Secret {
        sandbox: sandbox.into(),
        name: name.into(),
        state: state.into(),
        ..Default::default()
    };
    data.secrets.extend([
        secret("dev", "NPM_TOKEN", "loaded"),
        secret("agent", "ANTHROPIC_API_KEY", "loaded"),
        secret("agent", "GITHUB_TOKEN@api.github.com", "loaded"),
        secret(
            "build",
            "GOPROXY_TOKEN@proxy.golang.org",
            "required next start",
        ),
    ]);
    // Cached images, as `gantry image ls` would list them.
    let image = |reference: &str, digest: &str, size: i64, days: i64, users: &[&str]| Image {
        r#ref: reference.into(),
        digest: digest.into(),
        arch: "arm64".into(),
        created: crate::clock::format(now - days * 86_400),
        size,
        in_use: !users.is_empty(),
        used_by: users.iter().map(|u| (*u).into()).collect(),
        user: "root".into(),
        working_dir: "/".into(),
        cmd: vec!["/bin/sh".into()],
        env_count: 1,
        ..Default::default()
    };
    data.images = vec![
        Image {
            user: "dev".into(),
            working_dir: "/workspace".into(),
            entrypoint: vec!["tini".into(), "--".into()],
            cmd: vec!["node".into(), "server.js".into()],
            env_count: 7,
            ..image(
                "ghcr.io/acme/api:1.8",
                "sha256:9f2c1e07a41b",
                612_000_000,
                3,
                &[],
            )
        },
        image(
            "alpine:latest",
            "sha256:1f4e9b3c0c2d",
            9_000_000,
            60,
            &["agent"],
        ),
        image(
            "debian:bookworm-slim",
            "sha256:98f471fd796a",
            348_000_000,
            30,
            &["dev"],
        ),
        image(
            "golang:1.26",
            "sha256:8b1c2f603d94",
            830_000_000,
            90,
            &["build"],
        ),
        image("python:3.12", "sha256:5d6a7c91e8b0", 1_020_000_000, 65, &[]),
        image(
            "ubuntu:24.04",
            "sha256:e3b8a1d277f1",
            412_000_000,
            32,
            &["scratch"],
        ),
    ];
    // Registry credential resolution, as `gantry image credentials` reports
    // it: the default registries, then any with a stored login.
    let login = |registry: &str, username: &str, source: &str| RegistryAuth {
        registry: registry.into(),
        username: username.into(),
        source: source.into(),
        has_secret: source != "-",
        ..Default::default()
    };
    data.registries = vec![
        login(
            "docker.io",
            "build-bot",
            "docker config credsStore (docker-credential-osxkeychain)",
        ),
        login(
            "ghcr.io",
            "acme-bot",
            "gantry credentials.json auths (base64)",
        ),
        login("quay.io", "(anonymous)", "-"),
        login("gcr.io", "(anonymous)", "-"),
        login(
            "registry.gitlab.com",
            "deploy-token-12",
            "podman auth.json #1 auths (base64)",
        ),
    ];
    // Policy decisions as the daemon records them, newest first, with the
    // decision the manager parses out of each `policy:` line.
    let decision =
        |effect: &str, action: &str, reason: &str, rules: &[&str], org: bool| AuditDecision {
            effect: effect.into(),
            action: action.into(),
            reason: reason.into(),
            rules: rules.iter().map(|r| (*r).into()).collect(),
            organization: if org { "acme" } else { "" }.into(),
            revision: if org { "r42" } else { "" }.into(),
            profile: if org { "dev" } else { "" }.into(),
        };
    let events = [
        (
            7,
            "agent",
            Some(decision("deny", "network.connect", "no_match", &[], true)),
            "telemetry.example.net:443",
            0,
        ),
        (
            12,
            "dev",
            Some(decision(
                "allow",
                "credential.use",
                "rule_match",
                &["github-credentials"],
                true,
            )),
            "github.com",
            0,
        ),
        (
            19,
            "agent",
            Some(decision(
                "deny",
                "network.connect",
                "rule_match",
                &["deny-metadata"],
                true,
            )),
            "169.254.169.254:80",
            0,
        ),
        (
            33,
            "dev",
            Some(decision(
                "allow",
                "mcp.tools.call",
                "rule_match",
                &["linear-read"],
                true,
            )),
            "linear.create_comment",
            0,
        ),
        (
            61,
            "dev",
            Some(decision(
                "deny",
                "mcp.tools.call",
                "rule_match",
                &["blocked-tool"],
                true,
            )),
            "linear.delete_issue",
            0,
        ),
        (
            95,
            "agent",
            Some(decision(
                "deny",
                "network.connect",
                "rule_match",
                &["deny-metadata"],
                true,
            )),
            "169.254.169.254:80",
            1,
        ),
        (
            140,
            "agent",
            None,
            "credential withheld: GITHUB_TOKEN for gist.github.com (no binding)",
            0,
        ),
        (
            205,
            "dev",
            Some(decision(
                "allow",
                "mount.read",
                "rule_match",
                &["workspace-read"],
                true,
            )),
            "/demo/workspace",
            0,
        ),
        (
            260,
            "agent",
            Some(decision(
                "deny",
                "network.connect",
                "rule_match",
                &["deny-metadata"],
                true,
            )),
            "169.254.169.254:80",
            2,
        ),
        (330, "dev", None, "mcp: session open linear", 0),
        (
            410,
            "build",
            Some(decision(
                "allow",
                "network.resolve",
                "unmanaged",
                &[],
                false,
            )),
            "proxy.golang.org",
            0,
        ),
    ];
    data.audit = events
        .into_iter()
        .map(|(age, sandbox, decision, subject, occurrence)| AuditEvent {
            sandbox: sandbox.into(),
            line: match &decision {
                Some(d) => format!(
                    "policy: {{\"effect\":\"{}\",\"action\":\"{}\",\"reason\":\"{}\",\"subject\":\"{subject}\"}}",
                    d.effect, d.action, d.reason
                ),
                None => subject.into(),
            },
            occurrence,
            decision,
            time: crate::clock::format(now - age),
            ..Default::default()
        })
        .collect();
    host
}

/// A recorded capture for demo mode: about a minute of one sandbox's frames,
/// ending now, with a few denied bursts.
pub fn demo_packets() -> PacketSnapshot {
    let now = crate::clock::now() * 1000;
    let count = 180_u64;
    let first = 1105_u64;
    let packets = (0..count)
        .map(|i| {
            let outbound = !matches!(i % 5, 1 | 3);
            let denied = matches!(i, 22..=25 | 61..=63 | 142..=147 | 171);
            let length = match i % 7 {
                0 => 1514,
                1 | 4 => 66,
                2 => 583,
                3 => 1460,
                5 => 74,
                _ => 54,
            };
            let mut frame = vec![
                0x45,
                0x00,
                0x00,
                0x4a,
                (i & 0xff) as u8,
                0x46,
                0x40,
                0x00,
                0x40,
                0x06,
                0x5b,
                0x1e,
                0x0a,
                0x00,
                0x02,
                0x0f,
            ];
            frame.extend(if denied {
                [169, 254, 169, 254, 0xd4, 0x1e, 0x00, 0x50]
            } else {
                [192, 0, 2, 10, 0xd4, 0x1e, 0x01, 0xbb]
            });
            frame.extend(b"\x8eK*q\0\0\0\0\xa0\x02\xfa\xf0<\x11\0\0\x02\x04\x05\xb4");
            // Spread over 60 s with a busier stretch near the end.
            let offset = (count - i) as i64 * 330 + ((i * 37) % 250) as i64;
            Packet {
                sequence: first + i,
                timestamp: crate::clock::format_millis(now - offset),
                direction: if outbound { "tx" } else { "rx" }.into(),
                allowed: !denied,
                length,
                data: crate::capture::encode_base64(&frame),
            }
        })
        .collect();
    PacketSnapshot {
        active: true,
        packets,
        next: first + count - 1,
        latest: first + count - 1,
        oldest: first,
        evicted: 0,
    }
}
