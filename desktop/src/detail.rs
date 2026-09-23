//! Per-sandbox projections for the Sandboxes screen: the feature badges in a
//! row and the tabs of the selected sandbox's detail pane. Every value comes
//! from the dashboard snapshot the manager already returns.

use crate::dashboard_wire::{HostSnapshot, Sandbox};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Feature {
    Ssh,
    DevContainers,
    Ports(i64),
    Secrets(i64),
    Shares(i64),
    NoNetwork,
    ProxyEnforced,
}

impl Feature {
    pub fn label(self) -> String {
        match self {
            Self::Ssh => "SSH enabled".into(),
            Self::DevContainers => "Dev Containers enabled".into(),
            Self::Ports(n) => plural(n, "published port"),
            Self::Secrets(n) => plural(n, "secret"),
            Self::Shares(n) => plural(n, "shared folder"),
            Self::NoNetwork => "No network".into(),
            Self::ProxyEnforced => "Egress proxy enforced".into(),
        }
    }

    pub fn count(self) -> Option<i64> {
        match self {
            Self::Ports(n) | Self::Secrets(n) | Self::Shares(n) => Some(n),
            _ => None,
        }
    }
}

fn plural(n: i64, noun: &str) -> String {
    format!("{n} {noun}{}", if n == 1 { "" } else { "s" })
}

/// Only what is on; absent capabilities are not listed as "off" badges.
pub fn features(sandbox: &Sandbox) -> Vec<Feature> {
    let mut features = Vec::new();
    if sandbox.ssh {
        features.push(Feature::Ssh);
    }
    if sandbox.dev_containers {
        features.push(Feature::DevContainers);
    }
    if sandbox.ports > 0 {
        features.push(Feature::Ports(sandbox.ports));
    }
    if sandbox.secret_count > 0 {
        features.push(Feature::Secrets(sandbox.secret_count));
    }
    if sandbox.shares > 0 {
        features.push(Feature::Shares(sandbox.shares));
    }
    if !sandbox.net {
        features.push(Feature::NoNetwork);
    } else if sandbox.proxy_enforce {
        features.push(Feature::ProxyEnforced);
    }
    features
}

/// `ghcr.io/acme/api:1.8` → (`ghcr.io/acme/`, `api:1.8`), so the registry and
/// namespace can be de-emphasized without hiding them.
pub fn split_image(reference: &str) -> (&str, &str) {
    // A digest may follow `@`; only the name part can contain the separator.
    let name_end = reference.find('@').unwrap_or(reference.len());
    match reference[..name_end].rfind('/') {
        Some(index) => reference.split_at(index + 1),
        None => ("", reference),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destination {
    pub label: String,
    pub protocol: String,
    pub port: u16,
    pub allowed: bool,
    pub bytes: u64,
}

/// One row per destination and decision, largest first. A host name is shown
/// when the manager resolved one; otherwise the address.
pub fn destinations(host: &HostSnapshot, sandbox: &str) -> Vec<Destination> {
    let mut result: Vec<Destination> = Vec::new();
    for flow in host
        .snapshot
        .traffic
        .iter()
        .filter(|flow| flow.sandbox == sandbox)
    {
        let label = if flow.host.is_empty() {
            flow.address.clone()
        } else {
            flow.host.clone()
        };
        let bytes = flow.tx_bytes.saturating_add(flow.rx_bytes);
        match result.iter_mut().find(|d| {
            d.label == label
                && d.protocol == flow.protocol
                && d.port == flow.port
                && d.allowed == flow.allowed
        }) {
            Some(existing) => existing.bytes = existing.bytes.saturating_add(bytes),
            None => result.push(Destination {
                label,
                protocol: flow.protocol.clone(),
                port: flow.port,
                allowed: flow.allowed,
                bytes,
            }),
        }
    }
    result.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.label.cmp(&b.label)));
    result
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Tab {
    #[default]
    Network,
    Ports,
    Mounts,
    Secrets,
    Mcp,
    Audit,
}

impl Tab {
    pub const ALL: [Self; 6] = [
        Self::Network,
        Self::Ports,
        Self::Mounts,
        Self::Secrets,
        Self::Mcp,
        Self::Audit,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Network => "Network",
            Self::Ports => "Ports",
            Self::Mounts => "Mounts",
            Self::Secrets => "Secrets",
            Self::Mcp => "MCP",
            Self::Audit => "Audit",
        }
    }

    /// Record count shown beside the tab label; Network has no single count.
    pub fn count(self, host: &HostSnapshot, sandbox: &str) -> Option<usize> {
        let data = &host.snapshot;
        let count = match self {
            Self::Network => return None,
            Self::Ports => data.ports.iter().filter(|r| r.sandbox == sandbox).count(),
            Self::Mounts => data.mounts.iter().filter(|r| r.sandbox == sandbox).count(),
            Self::Secrets => data.secrets.iter().filter(|r| r.sandbox == sandbox).count(),
            Self::Mcp => data
                .mcp_servers
                .iter()
                .filter(|r| r.sandbox == sandbox)
                .count(),
            Self::Audit => data.audit.iter().filter(|r| r.sandbox == sandbox).count(),
        };
        Some(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dashboard_wire::{DashboardData, Traffic};

    #[test]
    fn features_list_only_enabled_capabilities() {
        let sandbox = Sandbox {
            ssh: true,
            ports: 2,
            secret_count: 1,
            net: true,
            proxy_enforce: true,
            ..Default::default()
        };
        assert_eq!(
            features(&sandbox),
            [
                Feature::Ssh,
                Feature::Ports(2),
                Feature::Secrets(1),
                Feature::ProxyEnforced
            ]
        );
        assert_eq!(Feature::Secrets(1).label(), "1 secret");
        assert_eq!(Feature::Shares(3).label(), "3 shared folders");
        let offline = Sandbox {
            net: false,
            proxy_enforce: true,
            ..Default::default()
        };
        assert_eq!(features(&offline), [Feature::NoNetwork]);
    }

    #[test]
    fn image_registry_is_split_from_the_name() {
        assert_eq!(
            split_image("ghcr.io/acme/api:1.8"),
            ("ghcr.io/acme/", "api:1.8")
        );
        assert_eq!(split_image("debian:12"), ("", "debian:12"));
        assert_eq!(
            split_image("localhost:5000/tool@sha256:ab/cd"),
            ("localhost:5000/", "tool@sha256:ab/cd")
        );
        assert_eq!(split_image(""), ("", ""));
    }

    #[test]
    fn destinations_merge_by_decision_and_sort_by_volume() {
        let flow = |sandbox: &str, host: &str, address: &str, allowed, tx, rx| Traffic {
            sandbox: sandbox.into(),
            host: host.into(),
            address: address.into(),
            protocol: "tcp".into(),
            port: 443,
            allowed,
            tx_bytes: tx,
            rx_bytes: rx,
            ..Default::default()
        };
        let host = HostSnapshot {
            snapshot: DashboardData {
                traffic: vec![
                    flow("dev", "a.test", "192.0.2.1", true, 10, 20),
                    flow("dev", "a.test", "192.0.2.2", true, 5, 5),
                    flow("dev", "", "203.0.113.9", false, 0, 0),
                    flow("dev", "b.test", "192.0.2.3", true, 100, 900),
                    flow("web", "a.test", "192.0.2.1", true, 1, 1),
                ],
                ..Default::default()
            },
            ..Default::default()
        };
        let rows = destinations(&host, "dev");
        assert_eq!(
            rows.iter()
                .map(|d| (&*d.label, d.bytes))
                .collect::<Vec<_>>(),
            [("b.test", 1000), ("a.test", 40), ("203.0.113.9", 0)]
        );
        assert!(!rows[2].allowed);
        assert_eq!(Tab::Ports.count(&host, "dev"), Some(0));
        assert_eq!(Tab::Network.count(&host, "dev"), None);
    }
}
