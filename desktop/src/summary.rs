//! Headline figures for the dashboard screens: the summary tiles and the one
//! visual each page leads with. Computed from the snapshot the manager returns.

use crate::dashboard_wire::{HostSnapshot, Image, RegistryAuth, Rule};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrafficSummary {
    pub flows: usize,
    pub allowed: usize,
    pub denied: usize,
    pub sandboxes: usize,
    pub hosts: usize,
    /// What sandboxes sent (`tx_bytes`) and received (`rx_bytes`).
    pub sent: u64,
    pub received: u64,
    /// Bytes per sandbox, largest first.
    pub by_sandbox: Vec<(String, u64)>,
}

pub fn traffic(host: &HostSnapshot) -> TrafficSummary {
    let flows = &host.snapshot.traffic;
    let mut summary = TrafficSummary {
        flows: flows.len(),
        allowed: flows.iter().filter(|f| f.allowed).count(),
        ..Default::default()
    };
    summary.denied = summary.flows - summary.allowed;
    let mut sandboxes = BTreeSet::new();
    let mut hosts = BTreeSet::new();
    for flow in flows {
        sandboxes.insert(flow.sandbox.as_str());
        hosts.insert(if flow.host.is_empty() {
            flow.address.as_str()
        } else {
            flow.host.as_str()
        });
        summary.sent = summary.sent.saturating_add(flow.tx_bytes);
        summary.received = summary.received.saturating_add(flow.rx_bytes);
        let bytes = flow.tx_bytes.saturating_add(flow.rx_bytes);
        match summary
            .by_sandbox
            .iter_mut()
            .find(|(name, _)| name == &flow.sandbox)
        {
            Some((_, total)) => *total = total.saturating_add(bytes),
            None => summary.by_sandbox.push((flow.sandbox.clone(), bytes)),
        }
    }
    summary.sandboxes = sandboxes.len();
    summary.hosts = hosts.len();
    summary
        .by_sandbox
        .sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    summary
}

/// Where a rule comes from, parsed from the manager's `Source` label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleOrigin {
    /// A numbered rule in the sandbox's policy file.
    Policy(String),
    /// An allowed or resolve-only domain in the policy file.
    Domain,
    /// Organization policy delivered by a policy feed.
    Organization { organization: String, rule: String },
    /// Always present (built-in and default rows, proxy wiring, config).
    Managed(String),
}

impl RuleOrigin {
    pub fn of(rule: &Rule) -> Self {
        let source = rule.source.as_str();
        if let Some(rest) = source.strip_prefix("org:") {
            let (organization, rule) = rest.split_once(':').unwrap_or((rest, ""));
            return Self::Organization {
                organization: organization.into(),
                rule: rule.into(),
            };
        }
        match source {
            "domain" | "DNS only" => Self::Domain,
            _ if source.starts_with("rule ") => Self::Policy(source.into()),
            _ => Self::Managed(source.into()),
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::Policy(label) | Self::Managed(label) => label.clone(),
            Self::Domain => "domain".into(),
            Self::Organization { organization, .. } => organization.clone(),
        }
    }

    /// Only the sandbox's own policy entries can be edited from here.
    pub fn editable(&self) -> bool {
        matches!(self, Self::Policy(_) | Self::Domain)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SandboxPolicy {
    pub sandbox: String,
    /// "deny" or "allow" for public internet, or the single row's action
    /// when networking is off, delegated to gvproxy, or failed to load.
    pub default: String,
    pub policy: String,
    pub rules: usize,
    pub organization: usize,
    pub error: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RulesSummary {
    pub rules: usize,
    pub allow: usize,
    pub deny: usize,
    pub organization: usize,
    pub errors: usize,
    pub organizations: Vec<String>,
    pub sandboxes: Vec<SandboxPolicy>,
}

impl RulesSummary {
    pub fn default_deny(&self) -> usize {
        self.sandboxes
            .iter()
            .filter(|s| s.default == "deny")
            .count()
    }
}

pub fn rules(host: &HostSnapshot) -> RulesSummary {
    let rules = &host.snapshot.rules;
    let mut summary = RulesSummary {
        rules: rules.len(),
        allow: rules.iter().filter(|r| r.action == "allow").count(),
        deny: rules.iter().filter(|r| r.action == "deny").count(),
        errors: rules.iter().filter(|r| r.error).count(),
        ..Default::default()
    };
    for rule in rules {
        let origin = RuleOrigin::of(rule);
        if let RuleOrigin::Organization { organization, .. } = &origin {
            summary.organization += 1;
            if !summary.organizations.contains(organization) {
                summary.organizations.push(organization.clone());
            }
        }
        let index = match summary
            .sandboxes
            .iter()
            .position(|s| s.sandbox == rule.sandbox)
        {
            Some(index) => index,
            None => {
                summary.sandboxes.push(SandboxPolicy {
                    sandbox: rule.sandbox.clone(),
                    ..Default::default()
                });
                summary.sandboxes.len() - 1
            }
        };
        let entry = &mut summary.sandboxes[index];
        entry.rules += 1;
        entry.error |= rule.error;
        if matches!(origin, RuleOrigin::Organization { .. }) {
            entry.organization += 1;
        }
        if entry.policy.is_empty() {
            entry.policy = rule.policy.clone();
        }
        let is_default = rule.source == "default" && rule.target == "public internet";
        let single =
            matches!(rule.action.as_str(), "off" | "error") || rule.source == "external gvproxy";
        if is_default || (single && entry.default.is_empty()) {
            entry.default = if rule.source == "external gvproxy" {
                "gvproxy".into()
            } else {
                rule.action.clone()
            };
        }
    }
    summary.sandboxes.sort_by(|a, b| a.sandbox.cmp(&b.sandbox));
    summary
}

/// Whether an observed flow is what a rule's target names: the same host or
/// address, or an IPv4 address inside the rule's CIDR. Broad targets such as
/// "public internet" are not matched; they would cover almost everything.
pub fn rule_covers(rule: &Rule, flow: &crate::dashboard_wire::Traffic) -> bool {
    if rule.sandbox != flow.sandbox {
        return false;
    }
    let target = rule.target.as_str();
    if (!flow.host.is_empty() && flow.host.eq_ignore_ascii_case(target)) || flow.address == target {
        return true;
    }
    let Some((network, bits)) = target.split_once('/') else {
        return false;
    };
    let (Ok(network), Ok(address), Ok(bits)) = (
        network.parse::<std::net::Ipv4Addr>(),
        flow.address.parse::<std::net::Ipv4Addr>(),
        bits.parse::<u32>(),
    ) else {
        return false;
    };
    if bits > 32 {
        return false;
    }
    let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
    u32::from(network) & mask == u32::from(address) & mask
}

/// Who can reach a published port, from its host bind address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindScope {
    /// Only this machine (127.0.0.0/8, ::1, localhost).
    Loopback,
    /// Any machine that can route to the host (0.0.0.0, ::, or a LAN address).
    Network,
    /// Not a host:port (for example "unavailable" when listing failed).
    Unknown,
}

pub fn bind_scope(bind: &str) -> BindScope {
    let Some((host, port)) = bind.rsplit_once(':') else {
        return BindScope::Unknown;
    };
    if port.parse::<u16>().is_err() {
        return BindScope::Unknown;
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") {
        return BindScope::Loopback;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(address) if address.is_loopback() => BindScope::Loopback,
        Ok(_) => BindScope::Network,
        Err(_) => BindScope::Unknown,
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PortsSummary {
    pub published: usize,
    pub bound: usize,
    pub loopback: usize,
    pub network: usize,
    pub errors: usize,
    pub sandboxes: usize,
}

pub fn ports(host: &HostSnapshot) -> PortsSummary {
    let ports = &host.snapshot.ports;
    PortsSummary {
        published: ports.len(),
        bound: ports.iter().filter(|p| p.state == "bound").count(),
        loopback: ports
            .iter()
            .filter(|p| bind_scope(&p.bind) == BindScope::Loopback)
            .count(),
        network: ports
            .iter()
            .filter(|p| bind_scope(&p.bind) == BindScope::Network)
            .count(),
        errors: ports.iter().filter(|p| !p.error.is_empty()).count(),
        sandboxes: ports
            .iter()
            .map(|p| p.sandbox.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MountsSummary {
    pub shares: usize,
    pub read_only: usize,
    pub read_write: usize,
    /// Configured changes that apply at the next boot.
    pub pending: usize,
    pub errors: usize,
    pub sandboxes: usize,
}

pub fn mounts(host: &HostSnapshot) -> MountsSummary {
    let mounts = &host.snapshot.mounts;
    MountsSummary {
        shares: mounts.len(),
        read_only: mounts.iter().filter(|m| m.read_only).count(),
        read_write: mounts.iter().filter(|m| !m.read_only).count(),
        pending: mounts.iter().filter(|m| m.state == "restart").count(),
        errors: mounts
            .iter()
            .filter(|m| !m.error.is_empty() || m.state == "error")
            .count(),
        sandboxes: mounts
            .iter()
            .map(|m| m.sandbox.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
    }
}

/// `NAME@host` binds a secret to one destination: the credential broker
/// serves it only for that host, and only when the network policy allows it.
pub fn split_secret(name: &str) -> (&str, Option<&str>) {
    match name.split_once('@') {
        Some((name, host)) if !name.is_empty() && !host.is_empty() => (name, Some(host)),
        _ => (name, None),
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecretsSummary {
    pub secrets: usize,
    pub loaded: usize,
    pub pending: usize,
    pub host_bound: usize,
    pub sandboxes: usize,
}

pub fn secrets(host: &HostSnapshot) -> SecretsSummary {
    let secrets = &host.snapshot.secrets;
    SecretsSummary {
        secrets: secrets.len(),
        loaded: secrets.iter().filter(|s| s.state == "loaded").count(),
        pending: secrets.iter().filter(|s| s.state != "loaded").count(),
        host_bound: secrets
            .iter()
            .filter(|s| split_secret(&s.name).1.is_some())
            .count(),
        sandboxes: secrets
            .iter()
            .map(|s| s.sandbox.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct McpSummary {
    pub servers: usize,
    pub active: usize,
    /// Allow, deny, and redact entries across all servers.
    pub filters: usize,
    pub errors: usize,
    pub sandboxes: usize,
}

pub fn mcp(host: &HostSnapshot) -> McpSummary {
    let servers = &host.snapshot.mcp_servers;
    McpSummary {
        servers: servers.len(),
        active: servers
            .iter()
            .filter(|s| s.state == "active" && s.error.is_empty())
            .count(),
        filters: servers
            .iter()
            .map(|s| s.allow.len() + s.deny.len() + s.redact.len())
            .sum(),
        errors: servers.iter().filter(|s| !s.error.is_empty()).count(),
        sandboxes: servers
            .iter()
            .map(|s| s.sandbox.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
    }
}

/// How a remote MCP server authenticates, without any credential value.
pub fn mcp_auth(server: &crate::dashboard_wire::MCPServer) -> String {
    match server.auth_kind.as_str() {
        "bearer" => format!("Bearer token from {}", server.auth_ref),
        "header" => format!("{} header from {}", server.auth_header, server.auth_ref),
        "custody" => format!("OAuth custody · {}", server.auth_ref),
        _ if server.r#type == "local" => "Local · no credential".into(),
        _ => "No credential".into(),
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditSummary {
    pub events: usize,
    pub allowed: usize,
    pub denied: usize,
    pub errors: usize,
    pub sandboxes: usize,
    /// The rule behind the most denials, with its count.
    pub top_deny_rule: Option<(String, usize)>,
    /// Organization, revision, and profile from the newest governed decision.
    pub policy: Option<(String, String, String)>,
}

pub fn audit(host: &HostSnapshot) -> AuditSummary {
    let events = &host.snapshot.audit;
    let decisions = events.iter().filter_map(|e| e.decision.as_ref());
    let mut rules: Vec<(String, usize)> = Vec::new();
    for decision in decisions.clone().filter(|d| d.effect == "deny") {
        for rule in &decision.rules {
            match rules.iter_mut().find(|(name, _)| name == rule) {
                Some((_, count)) => *count += 1,
                None => rules.push((rule.clone(), 1)),
            }
        }
    }
    rules.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let newest = events
        .iter()
        .filter(|e| {
            e.decision
                .as_ref()
                .is_some_and(|d| !d.organization.is_empty())
        })
        .max_by_key(|e| crate::clock::parse(&e.time));
    AuditSummary {
        events: events.len(),
        allowed: decisions.clone().filter(|d| d.effect == "allow").count(),
        denied: decisions.filter(|d| d.effect == "deny").count(),
        errors: events.iter().filter(|e| !e.error.is_empty()).count(),
        sandboxes: events
            .iter()
            .map(|e| e.sandbox.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        top_deny_rule: rules.into_iter().next(),
        policy: newest.and_then(|e| e.decision.as_ref()).map(|d| {
            (
                d.organization.clone(),
                d.revision.clone(),
                d.profile.clone(),
            )
        }),
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImagesSummary {
    pub images: usize,
    pub in_use: usize,
    pub unused: usize,
    pub bytes: u64,
    /// What pruning unused images would free.
    pub reclaimable: u64,
    pub sandboxes: usize,
}

pub fn images(host: &HostSnapshot) -> ImagesSummary {
    let images = &host.snapshot.images;
    let size = |i: &crate::dashboard_wire::Image| i.size.max(0) as u64;
    ImagesSummary {
        images: images.len(),
        in_use: images.iter().filter(|i| i.in_use).count(),
        unused: images.iter().filter(|i| !i.in_use).count(),
        bytes: images.iter().map(size).sum(),
        reclaimable: images.iter().filter(|i| !i.in_use).map(size).sum(),
        sandboxes: images
            .iter()
            .flat_map(|i| i.used_by.iter().map(String::as_str))
            .collect::<BTreeSet<_>>()
            .len(),
    }
}

/// The registry an image reference pulls from, keyed the way the manager
/// keys credentials: `alpine` and `index.docker.io/…` are both docker.io.
/// Mirrors Go's `image.ParseRef`: the first path segment is a registry only
/// when it looks like a host.
pub fn image_registry(reference: &str) -> &str {
    let name = reference.split('@').next().unwrap_or(reference);
    match name.split_once('/') {
        Some((first, _)) if first.contains(['.', ':']) || first == "localhost" => match first {
            "index.docker.io" | "registry-1.docker.io" => "docker.io",
            host => host,
        },
        _ => "docker.io",
    }
}

/// Where the manager resolved a registry login from, in its precedence
/// order: the environment beats Gantry's store, which beats Docker, then
/// Podman.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialSource {
    /// `GANTRY_REGISTRY_AUTH` in the manager's environment.
    Environment,
    /// `~/.gantry/credentials.json`, written by a Gantry login.
    Gantry,
    /// A docker-credential helper from Docker's config. Gantry logins are
    /// stored there too when one is configured, so Docker shares the login.
    Helper,
    /// Plain `auths` in Docker's config, written by `docker login`.
    Docker,
    /// Podman's `auth.json`.
    Podman,
    /// No stored secret: pulls are anonymous.
    Anonymous,
    Other,
}

impl CredentialSource {
    pub fn of(registry: &RegistryAuth) -> Self {
        let source = registry.source.as_str();
        if !registry.has_secret {
            Self::Anonymous
        } else if source == "GANTRY_REGISTRY_AUTH" {
            Self::Environment
        } else if source.starts_with("gantry ") {
            Self::Gantry
        } else if source.starts_with("docker config credHelpers")
            || source.starts_with("docker config credsStore")
        {
            Self::Helper
        } else if source.starts_with("docker ") {
            Self::Docker
        } else if source.starts_with("podman ") {
            Self::Podman
        } else {
            Self::Other
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Environment => "GANTRY_REGISTRY_AUTH",
            Self::Gantry => "gantry login",
            Self::Helper => "credential helper",
            Self::Docker => "docker login",
            Self::Podman => "podman login",
            Self::Anonymous => "anonymous",
            Self::Other => "external",
        }
    }

    /// Whether logging out through the manager erases the login. The manager
    /// erases Gantry's store and the configured helper; other sources keep
    /// resolving afterwards.
    pub fn removable(self) -> bool {
        matches!(self, Self::Gantry | Self::Helper)
    }
}

/// The docker-credential helper holding a login, from the manager's source
/// label: `docker config credsStore (docker-credential-osxkeychain)` →
/// `osxkeychain`.
pub fn credential_helper(source: &str) -> Option<&str> {
    let (_, rest) = source.split_once("(docker-credential-")?;
    rest.strip_suffix(')').filter(|helper| !helper.is_empty())
}

/// The account a login pulls as. Identity tokens carry no username.
pub fn registry_user(registry: &RegistryAuth) -> String {
    if !registry.has_secret {
        "anonymous".into()
    } else if registry.username.is_empty() || registry.username == "<token>" {
        "identity token".into()
    } else {
        registry.username.clone()
    }
}

/// The cached images pulled from a registry.
pub fn registry_images<'a>(host: &'a HostSnapshot, registry: &str) -> Vec<&'a Image> {
    host.snapshot
        .images
        .iter()
        .filter(|image| image_registry(&image.r#ref) == registry)
        .collect()
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RegistriesSummary {
    pub registries: usize,
    pub logged_in: usize,
    /// Logins the manager cannot erase: environment, Docker or Podman.
    pub external: usize,
    pub images: usize,
    /// Cached images per registry, most first.
    pub by_registry: Vec<(String, usize)>,
}

pub fn registries(host: &HostSnapshot) -> RegistriesSummary {
    let registries = &host.snapshot.registries;
    let mut counts = std::collections::BTreeMap::<&str, usize>::new();
    for image in &host.snapshot.images {
        *counts.entry(image_registry(&image.r#ref)).or_default() += 1;
    }
    let mut by_registry: Vec<(String, usize)> = counts
        .into_iter()
        .map(|(registry, count)| (registry.to_owned(), count))
        .collect();
    by_registry.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    RegistriesSummary {
        registries: registries.len(),
        logged_in: registries.iter().filter(|r| r.has_secret).count(),
        external: registries
            .iter()
            .map(CredentialSource::of)
            .filter(|s| *s != CredentialSource::Anonymous && !s.removable())
            .count(),
        images: host.snapshot.images.len(),
        by_registry,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dashboard_wire::{DashboardData, Traffic};

    fn rule(sandbox: &str, action: &str, target: &str, source: &str) -> Rule {
        Rule {
            sandbox: sandbox.into(),
            action: action.into(),
            target: target.into(),
            source: source.into(),
            policy: "built-in default".into(),
            ..Default::default()
        }
    }

    #[test]
    fn rule_origins_follow_the_manager_source_labels() {
        let origin = |source| RuleOrigin::of(&rule("dev", "allow", "x", source));
        assert_eq!(origin("rule 3"), RuleOrigin::Policy("rule 3".into()));
        assert_eq!(origin("domain"), RuleOrigin::Domain);
        assert_eq!(origin("DNS only"), RuleOrigin::Domain);
        assert_eq!(
            origin("org:acme:deny-metadata"),
            RuleOrigin::Organization {
                organization: "acme".into(),
                rule: "deny-metadata".into()
            }
        );
        assert_eq!(origin("org:acme").label(), "acme");
        for managed in ["built-in", "default", "proxy enforcement", "config"] {
            assert!(!origin(managed).editable(), "{managed}");
        }
        assert!(origin("rule 1").editable() && origin("domain").editable());
    }

    #[test]
    fn bind_scope_separates_loopback_from_network_exposure() {
        for bind in [
            "127.0.0.1:8080",
            "127.1.2.3:1",
            "[::1]:8080",
            "localhost:3000",
        ] {
            assert_eq!(bind_scope(bind), BindScope::Loopback, "{bind}");
        }
        for bind in ["0.0.0.0:8080", "[::]:8080", "192.168.1.20:22"] {
            assert_eq!(bind_scope(bind), BindScope::Network, "{bind}");
        }
        for bind in [
            "unavailable",
            "invalid",
            "127.0.0.1:http",
            "host.example:80",
        ] {
            assert_eq!(bind_scope(bind), BindScope::Unknown, "{bind}");
        }
        let port = |bind: &str, state: &str, error: &str| crate::dashboard_wire::Port {
            sandbox: "dev".into(),
            bind: bind.into(),
            state: state.into(),
            error: error.into(),
            ..Default::default()
        };
        let host = HostSnapshot {
            snapshot: crate::dashboard_wire::DashboardData {
                ports: vec![
                    port("127.0.0.1:8080", "bound", ""),
                    port("0.0.0.0:9000", "saved", ""),
                    port("unavailable", "", "control socket closed"),
                ],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(
            ports(&host),
            PortsSummary {
                published: 3,
                bound: 1,
                loopback: 1,
                network: 1,
                errors: 1,
                sandboxes: 1
            }
        );
    }

    #[test]
    fn mounts_count_access_pending_and_errors() {
        let mount =
            |sandbox: &str, read_only, state: &str, error: &str| crate::dashboard_wire::Mount {
                sandbox: sandbox.into(),
                read_only,
                state: state.into(),
                error: error.into(),
                ..Default::default()
            };
        let host = HostSnapshot {
            snapshot: crate::dashboard_wire::DashboardData {
                mounts: vec![
                    mount("dev", true, "active", ""),
                    mount("dev", false, "restart", ""),
                    mount("web", false, "error", "share backend error"),
                ],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(
            mounts(&host),
            MountsSummary {
                shares: 3,
                read_only: 1,
                read_write: 2,
                pending: 1,
                errors: 1,
                sandboxes: 2
            }
        );
    }

    #[test]
    fn secrets_split_host_bindings_and_count_load_state() {
        assert_eq!(
            split_secret("TOKEN@api.github.com"),
            ("TOKEN", Some("api.github.com"))
        );
        assert_eq!(split_secret("TOKEN"), ("TOKEN", None));
        assert_eq!(split_secret("@host"), ("@host", None));
        let secret = |sandbox: &str, name: &str, state: &str| crate::dashboard_wire::Secret {
            sandbox: sandbox.into(),
            name: name.into(),
            state: state.into(),
            ..Default::default()
        };
        let host = HostSnapshot {
            snapshot: crate::dashboard_wire::DashboardData {
                secrets: vec![
                    secret("dev", "A", "loaded"),
                    secret("dev", "B@x.test", "loaded"),
                    secret("build", "C", "required next start"),
                ],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(
            secrets(&host),
            SecretsSummary {
                secrets: 3,
                loaded: 2,
                pending: 1,
                host_bound: 1,
                sandboxes: 2
            }
        );
    }

    #[test]
    fn mcp_counts_active_filters_and_describes_auth_without_values() {
        use crate::dashboard_wire::MCPServer;
        let server = |kind: &str, auth: &str, state: &str, error: &str| MCPServer {
            sandbox: "dev".into(),
            r#type: kind.into(),
            auth_kind: auth.into(),
            auth_header: "X-Api-Key".into(),
            auth_ref: "TOKEN".into(),
            allow: vec!["a".into(), "b".into()],
            deny: vec!["c".into()],
            state: state.into(),
            error: error.into(),
            ..Default::default()
        };
        let host = HostSnapshot {
            snapshot: crate::dashboard_wire::DashboardData {
                mcp_servers: vec![
                    server("remote", "bearer", "active", ""),
                    server("remote", "header", "active", "401"),
                    server("local", "", "saved", ""),
                ],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(
            mcp(&host),
            McpSummary {
                servers: 3,
                active: 1,
                filters: 9,
                errors: 1,
                sandboxes: 1
            }
        );
        let servers = &host.snapshot.mcp_servers;
        assert_eq!(mcp_auth(&servers[0]), "Bearer token from TOKEN");
        assert_eq!(mcp_auth(&servers[1]), "X-Api-Key header from TOKEN");
        assert_eq!(mcp_auth(&servers[2]), "Local · no credential");
    }

    #[test]
    fn audit_counts_effects_and_finds_the_top_deny_rule() {
        use crate::dashboard_wire::{AuditDecision, AuditEvent};
        let event =
            |sandbox: &str, effect: &str, rules: &[&str], org: &str, time: &str| AuditEvent {
                sandbox: sandbox.into(),
                decision: Some(AuditDecision {
                    effect: effect.into(),
                    rules: rules.iter().map(|r| (*r).into()).collect(),
                    organization: org.into(),
                    revision: format!("{org}-rev"),
                    ..Default::default()
                }),
                time: time.into(),
                ..Default::default()
            };
        let host = HostSnapshot {
            snapshot: crate::dashboard_wire::DashboardData {
                audit: vec![
                    event("dev", "deny", &["metadata"], "acme", "2026-09-22T09:00:00Z"),
                    event(
                        "dev",
                        "deny",
                        &["metadata", "tools"],
                        "acme",
                        "2026-09-22T09:05:00Z",
                    ),
                    event("web", "allow", &[], "beta", "2026-09-22T09:10:00Z"),
                    AuditEvent {
                        sandbox: "web".into(),
                        error: "ctl.sock unavailable".into(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
            ..Default::default()
        };
        let summary = audit(&host);
        assert_eq!(
            (
                summary.events,
                summary.allowed,
                summary.denied,
                summary.errors
            ),
            (4, 1, 2, 1)
        );
        assert_eq!(summary.sandboxes, 2);
        assert_eq!(summary.top_deny_rule, Some(("metadata".into(), 2)));
        assert_eq!(
            summary.policy.unwrap().0,
            "beta",
            "newest governed decision"
        );
        assert_eq!(audit(&HostSnapshot::default()), AuditSummary::default());
    }

    #[test]
    fn images_sum_sizes_usage_and_reclaimable_space() {
        let image = |size, users: &[&str]| crate::dashboard_wire::Image {
            size,
            in_use: !users.is_empty(),
            used_by: users.iter().map(|u| (*u).into()).collect(),
            ..Default::default()
        };
        let host = HostSnapshot {
            snapshot: crate::dashboard_wire::DashboardData {
                images: vec![image(10, &["a", "b"]), image(100, &["a"]), image(1000, &[])],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(
            images(&host),
            ImagesSummary {
                images: 3,
                in_use: 2,
                unused: 1,
                bytes: 1110,
                reclaimable: 1000,
                sandboxes: 2
            }
        );
    }

    #[test]
    fn rules_cover_hosts_addresses_and_ipv4_networks() {
        let flow = |host: &str, address: &str| crate::dashboard_wire::Traffic {
            sandbox: "dev".into(),
            host: host.into(),
            address: address.into(),
            ..Default::default()
        };
        let github = rule("dev", "allow", "GitHub.com", "domain");
        assert!(rule_covers(&github, &flow("github.com", "192.0.2.10")));
        assert!(!rule_covers(&github, &flow("gitlab.com", "192.0.2.10")));
        let network = rule("dev", "deny", "169.254.0.0/16", "org:acme:x");
        assert!(rule_covers(&network, &flow("", "169.254.169.254")));
        assert!(!rule_covers(&network, &flow("", "169.255.0.1")));
        assert!(!rule_covers(&network, &flow("", "not-an-ip")));
        let everything = rule("dev", "deny", "0.0.0.0/0", "rule 1");
        assert!(rule_covers(&everything, &flow("", "203.0.113.9")));
        let other = rule("web", "allow", "github.com", "domain");
        assert!(!rule_covers(&other, &flow("github.com", "192.0.2.10")));
    }

    #[test]
    fn rules_summarize_default_policy_per_sandbox() {
        let mut broken = rule("web", "error", "bad policy", "policy");
        broken.error = true;
        let host = HostSnapshot {
            snapshot: DashboardData {
                rules: vec![
                    rule("dev", "deny", "IPv6 and non-IPv4 traffic", "built-in"),
                    rule("dev", "allow", "github.com", "domain"),
                    rule("dev", "deny", "public internet", "default"),
                    rule("dev", "deny", "10.0.0.0/8", "org:acme:private"),
                    rule("agent", "allow", "public internet", "default"),
                    rule("off", "off", "network disabled", "config"),
                    broken,
                ],
                ..Default::default()
            },
            ..Default::default()
        };
        let summary = rules(&host);
        assert_eq!((summary.rules, summary.allow, summary.deny), (7, 2, 3));
        assert_eq!((summary.organization, summary.errors), (1, 1));
        assert_eq!(summary.organizations, ["acme"]);
        let defaults: Vec<_> = summary
            .sandboxes
            .iter()
            .map(|s| (s.sandbox.as_str(), s.default.as_str(), s.rules))
            .collect();
        assert_eq!(
            defaults,
            [
                ("agent", "allow", 1),
                ("dev", "deny", 4),
                ("off", "off", 1),
                ("web", "error", 1)
            ]
        );
        assert_eq!(summary.default_deny(), 1);
        assert!(summary.sandboxes[3].error);
    }

    #[test]
    fn traffic_totals_decisions_and_per_sandbox_share() {
        let flow = |sandbox: &str, host: &str, address: &str, allowed, tx, rx| Traffic {
            sandbox: sandbox.into(),
            host: host.into(),
            address: address.into(),
            allowed,
            tx_bytes: tx,
            rx_bytes: rx,
            ..Default::default()
        };
        let host = HostSnapshot {
            snapshot: DashboardData {
                traffic: vec![
                    flow("dev", "a.test", "192.0.2.1", true, 10, 90),
                    flow("dev", "a.test", "192.0.2.2", true, 0, 100),
                    flow("web", "", "203.0.113.9", false, 0, 0),
                    flow("agent", "b.test", "192.0.2.3", true, 5, 5),
                ],
                ..Default::default()
            },
            ..Default::default()
        };
        let summary = traffic(&host);
        assert_eq!((summary.flows, summary.allowed, summary.denied), (4, 3, 1));
        assert_eq!((summary.sandboxes, summary.hosts), (3, 3));
        assert_eq!((summary.sent, summary.received), (15, 195));
        assert_eq!(
            summary.by_sandbox,
            [("dev".into(), 200), ("agent".into(), 10), ("web".into(), 0)]
        );
        assert_eq!(traffic(&HostSnapshot::default()), TrafficSummary::default());
    }

    #[test]
    fn image_registries_follow_the_manager_reference_rules() {
        for (reference, registry) in [
            ("alpine", "docker.io"),
            ("alpine:3.20", "docker.io"),
            ("library/alpine", "docker.io"),
            ("acme/tool:1", "docker.io"),
            ("index.docker.io/acme/tool", "docker.io"),
            ("ghcr.io/acme/api:1.8", "ghcr.io"),
            ("localhost/dev:latest", "localhost"),
            ("localhost:5000/dev", "localhost:5000"),
            (
                "registry.example.test/a/b@sha256:00",
                "registry.example.test",
            ),
            ("host:5000", "docker.io"),
        ] {
            assert_eq!(image_registry(reference), registry, "{reference}");
        }
    }

    #[test]
    fn registry_logins_name_their_source_and_whether_logout_erases_them() {
        let login = |source: &str, has_secret| RegistryAuth {
            registry: "ghcr.io".into(),
            username: "acme-bot".into(),
            source: source.into(),
            has_secret,
            ..Default::default()
        };
        for (source, expected, removable) in [
            (
                "gantry credentials.json auths (base64)",
                CredentialSource::Gantry,
                true,
            ),
            (
                "gantry credentials.json credsStore (docker-credential-pass)",
                CredentialSource::Gantry,
                true,
            ),
            (
                "docker config credsStore (docker-credential-osxkeychain)",
                CredentialSource::Helper,
                true,
            ),
            (
                "docker config credHelpers[ghcr.io] (docker-credential-gcr)",
                CredentialSource::Helper,
                true,
            ),
            (
                "docker config auths (base64)",
                CredentialSource::Docker,
                false,
            ),
            (
                "podman auth.json #1 auths (base64)",
                CredentialSource::Podman,
                false,
            ),
            ("GANTRY_REGISTRY_AUTH", CredentialSource::Environment, false),
            ("somewhere new", CredentialSource::Other, false),
        ] {
            let source = CredentialSource::of(&login(source, true));
            assert_eq!(source, expected);
            assert_eq!(source.removable(), removable);
        }
        let anonymous = RegistryAuth {
            username: "(anonymous)".into(),
            ..login("-", false)
        };
        assert_eq!(
            credential_helper("docker config credsStore (docker-credential-osxkeychain)"),
            Some("osxkeychain")
        );
        assert_eq!(credential_helper("docker config auths (base64)"), None);
        assert_eq!(
            CredentialSource::of(&anonymous),
            CredentialSource::Anonymous
        );
        assert!(!CredentialSource::Anonymous.removable());
        assert_eq!(registry_user(&anonymous), "anonymous");
        assert_eq!(registry_user(&login("gantry x", true)), "acme-bot");
        let token = RegistryAuth {
            username: String::new(),
            ..login("docker config auths (identity token)", true)
        };
        assert_eq!(registry_user(&token), "identity token");
    }

    #[test]
    fn registries_count_logins_and_the_images_each_one_serves() {
        let login = |registry: &str, source: &str, has_secret| RegistryAuth {
            registry: registry.into(),
            source: source.into(),
            has_secret,
            ..Default::default()
        };
        let image = |reference: &str| Image {
            r#ref: reference.into(),
            ..Default::default()
        };
        let host = HostSnapshot {
            snapshot: DashboardData {
                registries: vec![
                    login("docker.io", "docker config auths (base64)", true),
                    login("ghcr.io", "gantry credentials.json auths (base64)", true),
                    login("quay.io", "-", false),
                ],
                images: vec![
                    image("alpine"),
                    image("ghcr.io/acme/api:1.8"),
                    image("debian:bookworm"),
                ],
                ..Default::default()
            },
            ..Default::default()
        };
        let summary = registries(&host);
        assert_eq!(
            (summary.registries, summary.logged_in, summary.external),
            (3, 2, 1)
        );
        assert_eq!(summary.images, 3);
        assert_eq!(
            summary.by_registry,
            [("docker.io".into(), 2), ("ghcr.io".into(), 1)]
        );
        let served = registry_images(&host, "docker.io");
        assert_eq!(
            served.iter().map(|i| i.r#ref.as_str()).collect::<Vec<_>>(),
            ["alpine", "debian:bookworm"]
        );
        assert!(registry_images(&host, "quay.io").is_empty());
        assert_eq!(
            registries(&HostSnapshot::default()),
            RegistriesSummary::default()
        );
    }
}
