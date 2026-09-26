//! The organization policy service, as its administrators see it: the wire
//! contract of `gantry policy-service` (api/policyservice in Go), the policy
//! document an administrator edits, and the writes the Organization workspace
//! sends. Bundles are signed on this machine by the Gantry CLI with a key the
//! service never sees; the service only verifies them with the key every host
//! pins.
use crate::{
    api::ManagerClient,
    commands::Outcome,
    wire::null_vec,
    workspace::{Row, key, text},
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};

/// Health capability that marks a policy service rather than a manager.
pub const CAPABILITY: &str = "policy-service-admin-v1";
/// Hosts that have not polled for this long are reported silent.
pub const SILENT_AFTER_SECONDS: i64 = 600;

// ---------------------------------------------------------------- wire

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Overview {
    pub organization: String,
    pub feed_url: String,
    pub public_key_fingerprint: String,
    pub public_key_bits: u32,
    pub ca_fingerprint: String,
    pub ca_expires_at: String,
    pub admin: String,
    pub latest: u64,
    #[serde(deserialize_with = "null_vec")]
    pub rings: Vec<Ring>,
    pub rollout: Option<Rollout>,
    pub hosts: HostCounts,
    pub next_expiry: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Ring {
    pub name: String,
    pub generation: u64,
    pub hosts: u32,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Rollout {
    pub generation: u64,
    pub started_at: String,
    pub started_by: String,
    #[serde(deserialize_with = "null_vec")]
    pub rings: Vec<RolloutRing>,
    pub complete: bool,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct RolloutRing {
    pub name: String,
    pub promoted_at: Option<String>,
    pub promoted_by: String,
    pub hosts: u32,
    pub acknowledged: u32,
    pub offered: u32,
    pub stalled: u32,
    pub rejected: u32,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct HostCounts {
    pub enrolled: u32,
    pub current: u32,
    pub behind: u32,
    pub stalled: u32,
    pub rejected: u32,
    pub silent: u32,
    pub revoked: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Host {
    pub name: String,
    pub profile: String,
    pub ring: String,
    pub certificate: HostCertificate,
    pub revoked: bool,
    pub revoked_at: Option<String>,
    pub revoked_by: String,
    pub target: u64,
    pub served: u64,
    pub served_at: Option<String>,
    pub acknowledged_at: Option<String>,
    pub polls_since_served: u32,
    pub status: String,
    pub last_seen: Option<String>,
    pub report: Option<HostReport>,
    /// Not served the rollout generation yet because its ring is held.
    /// Derived by this desktop from the overview; not part of the wire.
    #[serde(skip)]
    pub held: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct HostCertificate {
    pub serial: String,
    pub fingerprint: String,
    pub not_after: String,
    pub issued_at: String,
    pub issued_by: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct HostReport {
    pub at: String,
    pub applied: u64,
    pub digest_matches: bool,
    pub pending: u64,
    pub attempts: u32,
    pub failed: Option<u32>,
    pub rejected_generation: u64,
    pub rejected_reason: String,
    pub profile: String,
    pub agent: String,
    pub address: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Generation {
    pub number: u64,
    pub revision: String,
    pub expires_at: String,
    pub published_at: String,
    pub published_by: String,
    pub bundle_sha256: String,
    pub size: u64,
    #[serde(deserialize_with = "null_vec")]
    pub profiles: Vec<String>,
    pub rules: u32,
    pub dns_names: u32,
    pub republish_of: u64,
    #[serde(deserialize_with = "null_vec")]
    pub changes: Vec<Change>,
    pub hosts: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct Change {
    pub profile: String,
    pub kind: String,
    pub id: String,
    pub change: String,
    pub effect: String,
    pub summary: String,
    pub before: String,
    pub after: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Draft {
    pub base: u64,
    pub data: serde_json::Value,
    #[serde(deserialize_with = "null_vec")]
    pub changes: Vec<Change>,
    pub saved: bool,
    pub updated_at: Option<String>,
    pub updated_by: String,
    pub problem: String,
}

#[derive(Deserialize)]
struct Enrollment {
    host: Host,
    files: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct ManagedFeedRequest {
    id: String,
    csr: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManagedFeedStatus {
    state: String,
    #[serde(default)]
    config_path: String,
}

// ---------------------------------------------------------------- document

/// Root data.json. Field names and omissions match Go's strict decoder, so a
/// document read from the service round-trips unchanged.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct Root {
    pub gantry: Document,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct Document {
    pub version: u32,
    pub organization: String,
    pub revision: String,
    pub expires_at: String,
    pub profiles: BTreeMap<String, Profile>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct Profile {
    #[serde(default, deserialize_with = "null_vec")]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub network: Network,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct Network {
    #[serde(default, deserialize_with = "null_vec")]
    pub rules: Vec<NetworkRule>,
    #[serde(default, deserialize_with = "null_vec")]
    pub dns: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct Rule {
    pub id: String,
    pub effect: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tool: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct NetworkRule {
    pub id: String,
    pub effect: String,
    pub cidr: String,
    pub protocol: String,
    #[serde(default, deserialize_with = "null_vec")]
    pub ports: Vec<u16>,
}

pub const RULE_ACTIONS: [&str; 6] = [
    "mount.read",
    "mount.write",
    "mcp.connect",
    "mcp.tools.list",
    "mcp.tools.call",
    "credential.use",
];

impl Rule {
    /// The rule's one selector, as the policy engine matches it.
    pub fn selector(&self) -> String {
        match self.action.as_str() {
            "mount.read" | "mount.write" => self.path.clone(),
            "mcp.connect" => self.server.clone(),
            "mcp.tools.list" | "mcp.tools.call" => format!("{} · {}", self.server, self.tool),
            "credential.use" => self.host.clone(),
            _ => String::new(),
        }
    }
}

impl NetworkRule {
    pub fn target(&self) -> String {
        if self.ports.is_empty() {
            self.protocol.clone()
        } else {
            let ports: Vec<String> = self.ports.iter().map(u16::to_string).collect();
            format!("{} {}", self.protocol, ports.join(", "))
        }
    }
}

impl Draft {
    pub fn document(&self) -> Result<Document> {
        Ok(serde_json::from_value::<Root>(self.data.clone())
            .context("The service returned a draft this desktop cannot read")?
            .gantry)
    }
}

// ---------------------------------------------------------------- snapshot

/// Everything the Organization workspace shows, read in one refresh.
#[derive(Clone, Debug, Default)]
pub struct OrgSnapshot {
    pub overview: Overview,
    pub hosts: Vec<Host>,
    pub generations: Vec<Generation>,
    pub draft: Draft,
    /// The parsed draft, or None when the service returned one this desktop
    /// cannot represent (then editing is disabled, never guessed).
    pub document: Option<Document>,
    /// The signed data.json the draft is based on, for its diff tree. Read
    /// only while an unpublished draft exists.
    pub base_data: Option<serde_json::Value>,
}

impl OrgSnapshot {
    /// The draft against its base, when there is something to compare.
    pub fn diff(&self) -> Option<Vec<DiffLine>> {
        if self.draft.changes.is_empty() {
            return None;
        }
        let after = self.draft.data.get("gantry")?;
        let before = self.base_data.as_ref().and_then(|b| b.get("gantry"));
        Some(diff_tree(before, after))
    }
    /// Mark hosts whose ring has not been offered the rollout generation.
    pub fn with_held(mut self) -> Self {
        let rollout = self
            .overview
            .rollout
            .as_ref()
            .map(|r| r.generation)
            .unwrap_or(0);
        for host in &mut self.hosts {
            host.held = !host.revoked && host.target < rollout;
        }
        self
    }
    pub fn profiles(&self) -> Vec<String> {
        self.document
            .as_ref()
            .map(|d| d.profiles.keys().cloned().collect())
            .unwrap_or_default()
    }
    pub fn rings(&self) -> Vec<String> {
        self.overview.rings.iter().map(|r| r.name.clone()).collect()
    }
    pub fn active_hosts(&self) -> impl Iterator<Item = &Host> {
        self.hosts.iter().filter(|h| !h.revoked)
    }
    pub fn generation(&self, number: u64) -> Option<&Generation> {
        self.generations.iter().find(|g| g.number == number)
    }
    /// The ring after the last one serving the rollout generation.
    pub fn next_ring(&self) -> Option<String> {
        let rollout = self.overview.rollout.as_ref()?;
        self.overview
            .rings
            .iter()
            .find(|ring| ring.generation < rollout.generation)
            .map(|ring| ring.name.clone())
    }
    /// The newest generation before the rollout's, to roll back to.
    pub fn previous_generation(&self) -> Option<u64> {
        let latest = self.overview.latest;
        (latest > 1).then(|| latest - 1)
    }
}

impl ManagerClient {
    pub fn organization(&self) -> Result<OrgSnapshot> {
        let get = |route: &str| -> Result<serde_json::Value> {
            self.request::<_, ()>("GET", route, None, Duration::from_secs(15), &[])
        };
        let overview: Overview = serde_json::from_value(get("/v1/admin/overview")?)
            .context("Invalid policy-service overview")?;
        let hosts: Vec<Host> =
            serde_json::from_value(get("/v1/admin/hosts")?).context("Invalid host list")?;
        let generations: Vec<Generation> = serde_json::from_value(get("/v1/admin/generations")?)
            .context("Invalid generation history")?;
        let draft: Draft =
            serde_json::from_value(get("/v1/admin/draft")?).context("Invalid policy draft")?;
        let document = draft.document().ok();
        let base_data = if draft.saved && draft.base > 0 {
            get(&format!("/v1/admin/generations/{}", draft.base))?
                .get("data")
                .cloned()
        } else {
            None
        };
        Ok(OrgSnapshot {
            overview,
            hosts,
            generations,
            draft,
            document,
            base_data,
        }
        .with_held())
    }
}

// ---------------------------------------------------------------- writes

/// Administrator writes. Each is one explicit request to the service that
/// was verified when the form opened; nothing replays after a failure.
#[derive(Clone, Debug)]
pub enum OrgCommand {
    SaveDraft {
        base: u64,
        document: Document,
        summary: String,
    },
    DiscardDraft,
    Publish(Box<Publish>),
    Promote {
        generation: u64,
        ring: String,
    },
    Republish {
        generation: u64,
        first_ring: String,
    },
    Enroll {
        name: String,
        profile: String,
        ring: String,
        request: PathBuf,
        save_to: PathBuf,
    },
    EnrollManaged {
        name: String,
        profile: String,
        ring: String,
        remote: crate::profiles::RemoteProfile,
        config_dir: PathBuf,
    },
    MoveHost {
        name: String,
        ring: String,
    },
    Revoke {
        name: String,
    },
    Download {
        generation: u64,
        save_to: PathBuf,
    },
}

/// Sign the draft on this machine and publish it.
#[derive(Clone, Debug)]
pub struct Publish {
    pub base: u64,
    pub document: Document,
    pub signing_key: PathBuf,
    pub first_ring: String,
    /// The key every host pins; the signed bundle must verify with it.
    pub key_fingerprint: String,
    pub gantry: Option<PathBuf>,
    pub managed: Option<PathBuf>,
}

impl OrgCommand {
    pub fn label(&self) -> &str {
        match self {
            Self::SaveDraft { .. } => "Update draft",
            Self::DiscardDraft => "Discard draft",
            Self::Publish(_) => "Sign and publish",
            Self::Promote { .. } => "Promote rollout",
            Self::Republish { .. } => "Roll back",
            Self::Enroll { .. } => "Enroll host",
            Self::EnrollManaged { .. } => "Enroll managed remote",
            Self::MoveHost { .. } => "Move host",
            Self::Revoke { .. } => "Revoke host",
            Self::Download { .. } => "Download bundle",
        }
    }
    pub fn subject(&self) -> String {
        match self {
            Self::SaveDraft { summary, .. } => summary.clone(),
            Self::DiscardDraft => "all unpublished changes".into(),
            Self::Publish(p) => format!("revision {}", p.document.revision),
            Self::Promote { generation, ring } => format!("g{generation} through {ring}"),
            Self::Republish { generation, .. } => format!("g{generation} as a new generation"),
            Self::Enroll { name, .. }
            | Self::EnrollManaged { name, .. }
            | Self::MoveHost { name, .. }
            | Self::Revoke { name } => name.clone(),
            Self::Download { generation, .. } => format!("g{generation}"),
        }
    }
    /// Confirmations explain what the write does before anything is sent.
    pub fn consequence(&self) -> String {
        match self {
            Self::DiscardDraft => {
                "Every unpublished change is dropped. Published generations and hosts are not affected.".into()
            }
            Self::Promote { generation, ring } => format!(
                "Every host in {ring} and the rings before it is offered generation {generation} on its next poll. Connected hosts receive it at once."
            ),
            Self::Republish { generation, first_ring } => format!(
                "Generation {generation}'s signed bundle is served again under the next number, starting with {}. Hosts never go back to a used number, and its original expiry is kept.",
                if first_ring.is_empty() { "the first ring" } else { first_ring }
            ),
            Self::Revoke { name } => format!(
                "The feed refuses {name}'s certificate from its next poll. The host keeps enforcing the last generation it applied until that expires. This cannot be undone; enroll it again with a new request."
            ),
            _ => String::new(),
        }
    }
}

impl ManagerClient {
    pub(crate) fn org_execute(
        &self,
        command: &OrgCommand,
        progress: impl Fn(&str),
    ) -> Result<Outcome> {
        let write =
            |method: &str, route: &str, body: &serde_json::Value| -> Result<serde_json::Value> {
                self.request(method, route, Some(body), Duration::from_secs(30), &[])
            };
        let message = match command {
            OrgCommand::SaveDraft {
                base,
                document,
                summary,
            } => {
                let draft = save_draft(self, *base, document)?;
                format!(
                    "Draft saved · {summary} · {} change{} from g{}",
                    draft.changes.len(),
                    if draft.changes.len() == 1 { "" } else { "s" },
                    draft.base
                )
            }
            OrgCommand::DiscardDraft => {
                self.request::<serde_json::Value, ()>(
                    "DELETE",
                    "/v1/admin/draft",
                    None,
                    Duration::from_secs(30),
                    &[],
                )?;
                "Draft discarded".into()
            }
            OrgCommand::Publish(publish) => publish_draft(self, publish, &progress)?,
            OrgCommand::Promote { generation, ring } => {
                write(
                    "POST",
                    "/v1/admin/rollout/promote",
                    &serde_json::json!({ "ring": ring }),
                )?;
                format!("Generation {generation} promoted through {ring}")
            }
            OrgCommand::Republish {
                generation,
                first_ring,
            } => {
                let created: Generation = serde_json::from_value(write(
                    "POST",
                    &format!("/v1/admin/generations/{generation}/republish"),
                    &serde_json::json!({ "firstRing": first_ring }),
                )?)?;
                format!("Generation {generation} republished as g{}", created.number)
            }
            OrgCommand::Enroll {
                name,
                profile,
                ring,
                request,
                save_to,
            } => {
                validate_name(name)?;
                let csr = read_small(request, 64 * 1024)?;
                ensure!(
                    csr.contains("BEGIN CERTIFICATE REQUEST"),
                    "{} is not a PEM certificate request (host.csr)",
                    request.display()
                );
                prepare_directory(save_to)?;
                let enrollment: Enrollment = serde_json::from_value(write(
                    "POST",
                    "/v1/admin/hosts",
                    &serde_json::json!({ "name": name, "profile": profile, "ring": ring, "csr": csr }),
                )?)?;
                for (file, content) in &enrollment.files {
                    ensure!(
                        !file.contains(['/', '\\']) && !file.starts_with('.') && file.len() <= 64,
                        "The service returned an unexpected file name"
                    );
                    write_new(&save_to.join(file), content.as_bytes())?;
                }
                format!(
                    "Enrolled {} ({} · {}). Its files are in {}; place them beside host-key.pem on the host",
                    enrollment.host.name,
                    enrollment.host.profile,
                    enrollment.host.ring,
                    save_to.display()
                )
            }
            OrgCommand::EnrollManaged {
                name,
                profile,
                ring,
                remote,
                config_dir,
            } => {
                validate_name(name)?;
                progress("Verifying both registered connections");
                let (current, token) = crate::profiles::load(config_dir, &remote.name)?;
                ensure!(
                    current == *remote,
                    "The remote profile changed; reopen enrollment. No request was sent."
                );
                let manager = ManagerClient::remote(&current, token.expose())?;
                let (_, capabilities) = manager.health()?;
                ensure!(
                    capabilities.iter().any(|c| c == "policy-feed-enroll-v1"),
                    "This remote manager does not support host-side feed enrollment. Upgrade and restart it; no request was sent."
                );
                ensure!(
                    !capabilities.iter().any(|c| c == CAPABILITY),
                    "The selected remote is another policy service, not a sandbox manager."
                );
                let overview: Overview = self.request(
                    "GET",
                    "/v1/admin/overview",
                    None::<&()>,
                    Duration::from_secs(15),
                    &[],
                )?;
                ensure!(
                    overview.rings.iter().any(|r| r.name == *ring),
                    "Rollout ring changed; reopen enrollment."
                );
                let status: ManagedFeedStatus = manager.request(
                    "GET",
                    "/v1/policy-feed/enrollment",
                    None::<&()>,
                    Duration::from_secs(15),
                    &[],
                )?;
                ensure!(
                    status.state == "none" || status.state == "awaiting-enrollment",
                    "The manager already has a feed staged or configured: {}",
                    status.state
                );
                progress("Generating the host key and request on the selected remote");
                let prepared: ManagedFeedRequest = manager.request(
                    "POST",
                    "/v1/policy-feed/enrollment",
                    Some(&serde_json::json!({
                        "host": name, "organization": overview.organization,
                        "profile": profile, "url": overview.feed_url,
                        "publicKeyFingerprint": overview.public_key_fingerprint,
                        "caFingerprint": overview.ca_fingerprint,
                    })),
                    Duration::from_secs(30),
                    &[],
                )?;
                ensure!(
                    prepared.csr.contains("BEGIN CERTIFICATE REQUEST"),
                    "Manager did not return a CSR"
                );
                progress("Enrolling the request with the policy service");
                let enrollment: Enrollment = serde_json::from_value(write(
                    "POST",
                    "/v1/admin/hosts",
                    &serde_json::json!({ "name": name, "profile": profile, "ring": ring, "csr": prepared.csr }),
                )?)?;
                ensure!(
                    enrollment.host.name == *name
                        && enrollment.host.profile == *profile
                        && enrollment.host.ring == *ring,
                    "Service returned an enrollment for another host. Check manager staging and revoke the unexpected host."
                );
                progress("Installing the public enrollment files on the selected remote");
                let installed: ManagedFeedStatus = manager.request(
                    "POST", "/v1/policy-feed/enrollment/install",
                    Some(&serde_json::json!({ "id": prepared.id, "files": enrollment.files })),
                    Duration::from_secs(30), &[],
                ).context("Host was enrolled by the service, but manager installation was not confirmed. Check both hosts' status; do not repeat enrollment blindly or restart the manager until installed.")?;
                ensure!(
                    installed.state == "restart-required" && !installed.config_path.is_empty(),
                    "Manager did not confirm a staged enrollment; inspect its status before restarting"
                );
                format!(
                    "Enrolled {name} on {}. NOT ENFORCING YET: restart that manager with -policy-feed {} (keeping its other serve flags).",
                    remote.name, installed.config_path
                )
            }
            OrgCommand::MoveHost { name, ring } => {
                validate_name(name)?;
                write(
                    "PATCH",
                    &format!("/v1/admin/hosts/{name}"),
                    &serde_json::json!({ "ring": ring }),
                )?;
                format!("{name} moved to {ring}")
            }
            OrgCommand::Revoke { name } => {
                validate_name(name)?;
                write(
                    "POST",
                    &format!("/v1/admin/hosts/{name}/revoke"),
                    &serde_json::json!({}),
                )?;
                format!("{name} revoked; the feed refuses it from its next poll")
            }
            OrgCommand::Download {
                generation,
                save_to,
            } => {
                let bytes = self.get_bytes(
                    &format!("/v1/admin/generations/{generation}/bundle"),
                    512 * 1024,
                )?;
                let path = save_to.join(format!("g{generation}-bundle.tar.gz"));
                write_new(&path, &bytes)?;
                format!("Saved {}", path.display())
            }
        };
        Ok(Outcome {
            message,
            packets: None,
        })
    }
}

fn save_draft(client: &ManagerClient, base: u64, document: &Document) -> Result<Draft> {
    let body = serde_json::json!({ "base": base, "data": Root { gantry: document.clone() } });
    let value: serde_json::Value = client.request(
        "PUT",
        "/v1/admin/draft",
        Some(&body),
        Duration::from_secs(30),
        &[],
    )?;
    Ok(serde_json::from_value(value)?)
}

/// Save the reviewed draft (the service validates it), sign that exact
/// document with the Gantry CLI on this machine, check the signature key is
/// the one hosts pin, and publish. The private key is only read by the CLI.
fn publish_draft(
    client: &ManagerClient,
    publish: &Publish,
    progress: &dyn Fn(&str),
) -> Result<String> {
    progress("Validating the draft");
    let draft = save_draft(client, publish.base, &publish.document)?;
    ensure!(
        draft.problem.is_empty(),
        "The draft does not validate: {}",
        text(&draft.problem)
    );
    let program =
        crate::launcher::executable(publish.gantry.as_deref(), publish.managed.as_deref())?;
    let work = PrivateDir::new()?;
    let data = work.path.join("data.json");
    write_new(&data, &serde_json::to_vec_pretty(&draft.data)?)?;
    let out = work.path.join("signed");
    progress("Signing with the Gantry CLI on this machine");
    run_sign(&program, &data, &publish.signing_key, &out)?;
    let public = read_small(&out.join("public.pem"), 16 * 1024)?;
    let fingerprint = public_key_fingerprint(public.as_bytes())?;
    ensure!(
        fingerprint == publish.key_fingerprint,
        "This signing key ({}) is not the organization key hosts pin ({}). Nothing was published.",
        short_fingerprint(&fingerprint),
        short_fingerprint(&publish.key_fingerprint)
    );
    let bundle = std::fs::read(out.join("bundle.tar.gz")).context("Read the signed bundle")?;
    ensure!(
        !bundle.is_empty() && bundle.len() <= 256 * 1024,
        "The signed bundle exceeds 256 KiB"
    );
    progress("Publishing");
    let body = serde_json::json!({ "bundle": base64(&bundle), "firstRing": publish.first_ring });
    let created: Generation = serde_json::from_value(client.request(
        "POST",
        "/v1/admin/generations",
        Some(&body),
        Duration::from_secs(30),
        &[],
    )?)?;
    Ok(format!(
        "Published generation {} (revision {}) to {}",
        created.number,
        created.revision,
        if publish.first_ring.is_empty() {
            "the first ring".into()
        } else {
            publish.first_ring.clone()
        }
    ))
}

#[cfg(unix)]
fn run_sign(program: &Path, data: &Path, key: &Path, out: &Path) -> Result<()> {
    use std::{
        process::{Command, Stdio},
        time::Instant,
    };
    let mut child = Command::new(program)
        .args(["policy", "sign", "-data"])
        .arg(data)
        .arg("-signing-key")
        .arg(key)
        .arg("-out")
        .arg(out)
        .env("GANTRY_REMOTE", "")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Cannot start the Gantry CLI to sign; install it or select --gantry PATH")?;
    let result = (|| {
        let mut stdout = child.stdout.take().context("Missing signer output")?;
        let mut stderr = child.stderr.take().context("Missing signer diagnostic")?;
        crate::launcher::nonblocking(&stdout)?;
        crate::launcher::nonblocking(&stderr)?;
        let (mut output, mut diagnostic) = (Vec::new(), Vec::new());
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let a = crate::launcher::collect_output(&mut stdout, &mut output)?;
            let b = crate::launcher::collect_output(&mut stderr, &mut diagnostic)?;
            if let Some(status) = child.try_wait()?
                && a
                && b
            {
                ensure!(
                    status.success(),
                    "Signing failed: {}",
                    text(String::from_utf8_lossy(&diagnostic).trim())
                );
                return Ok(());
            }
            ensure!(Instant::now() < deadline, "Signing timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

#[cfg(not(unix))]
fn run_sign(_: &Path, _: &Path, _: &Path, _: &Path) -> Result<()> {
    bail!("Signing from the desktop requires Linux or macOS")
}

/// A private temporary directory, removed with everything in it.
struct PrivateDir {
    path: PathBuf,
}

impl PrivateDir {
    fn new() -> Result<Self> {
        let base = std::env::temp_dir();
        for attempt in 0..16u32 {
            let name = format!(
                "gantry-publish-{}-{}-{attempt}",
                std::process::id(),
                crate::clock::now_millis()
            );
            let path = base.join(name);
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
            match builder.create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error).context("Create a private signing directory"),
            }
        }
        bail!("Cannot create a private signing directory")
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A new directory, or an existing empty one. Enrollment files are never
/// written over something else.
fn prepare_directory(path: &Path) -> Result<()> {
    match std::fs::read_dir(path) {
        Ok(mut entries) => ensure!(
            entries.next().is_none(),
            "{} is not empty; choose a new or empty folder",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
            builder
                .create(path)
                .with_context(|| format!("Create {}", path.display()))?;
        }
        Err(error) => return Err(error).with_context(|| format!("Open {}", path.display())),
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options
        .open(path)
        .with_context(|| format!("{} already exists or cannot be created", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn read_small(path: &Path, limit: u64) -> Result<String> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("Cannot read {}", path.display()))?;
    ensure!(
        metadata.is_file() && metadata.len() <= limit,
        "{} must be a file under {} KiB",
        path.display(),
        limit / 1024
    );
    std::fs::read_to_string(path).with_context(|| format!("Cannot read {}", path.display()))
}

/// SHA-256 over the DER SubjectPublicKeyInfo, as the service reports it.
pub fn public_key_fingerprint(pem: &[u8]) -> Result<String> {
    use sha2::Digest;
    let mut reader = std::io::BufReader::new(pem);
    for item in rustls_pemfile::read_all(&mut reader) {
        if let rustls_pemfile::Item::SubjectPublicKeyInfo(der) = item? {
            return Ok(format!("sha256:{:x}", sha2::Sha256::digest(der.as_ref())));
        }
    }
    bail!("The signer did not produce a PEM public key")
}

pub fn short_fingerprint(value: &str) -> String {
    let hex: Vec<char> = value.trim_start_matches("sha256:").chars().collect();
    if hex.len() > 12 {
        let head: String = hex[..6].iter().collect();
        let tail: String = hex[hex.len() - 4..].iter().collect();
        format!("{head}…{tail}")
    } else {
        hex.into_iter().collect()
    }
}

pub fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b)),
        "Names use letters, digits, '.', '_', ':' or '-' (at most 64)"
    );
    Ok(())
}

/// Standard base64 with padding, as Go encodes []byte in JSON.
pub fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

// ---------------------------------------------------------------- draft edits

/// What a policy row is, for the editor and its inspector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ItemKind {
    Network,
    Dns,
    Mount,
    Mcp,
    Credential,
}

impl ItemKind {
    pub fn of_action(action: &str) -> Self {
        match action {
            "mount.read" | "mount.write" => Self::Mount,
            "credential.use" => Self::Credential,
            _ => Self::Mcp,
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            Self::Network => "Network",
            Self::Dns => "DNS",
            Self::Mount => "Mounts",
            Self::Mcp => "MCP",
            Self::Credential => "Credentials",
        }
    }
}

/// One rule or DNS name of a profile in the draft, or one the draft removes.
#[derive(Clone, Debug, PartialEq)]
pub struct PolicyItem {
    pub profile: String,
    pub kind: ItemKind,
    pub id: String,
    pub effect: String,
    pub action: String,
    pub selector: String,
    pub detail: String,
    /// "added", "changed" or "removed" relative to the draft's base.
    pub change: String,
    /// "loosens", "tightens" or "neutral" for a change.
    pub effect_of_change: String,
    pub rule: Option<Rule>,
    pub network: Option<NetworkRule>,
}

impl PolicyItem {
    pub fn removed(&self) -> bool {
        self.change == "removed"
    }
}

pub fn items(snapshot: &OrgSnapshot, profile: &str) -> Vec<PolicyItem> {
    let Some(document) = &snapshot.document else {
        return vec![];
    };
    let Some(current) = document.profiles.get(profile) else {
        return vec![];
    };
    let change = |kind: &str, id: &str| {
        snapshot
            .draft
            .changes
            .iter()
            .find(|c| c.profile == profile && c.kind == kind && c.id == id)
    };
    let mark = |kind: &str, id: &str| {
        change(kind, id)
            .map(|c| (c.change.clone(), c.effect.clone()))
            .unwrap_or_default()
    };
    let mut result = vec![];
    for rule in &current.network.rules {
        let (change, effect) = mark("network", &rule.id);
        result.push(PolicyItem {
            profile: profile.into(),
            kind: ItemKind::Network,
            id: rule.id.clone(),
            effect: rule.effect.clone(),
            action: "network".into(),
            selector: rule.cidr.clone(),
            detail: rule.target(),
            change,
            effect_of_change: effect,
            rule: None,
            network: Some(rule.clone()),
        });
    }
    for name in &current.network.dns {
        let (change, effect) = mark("dns", name);
        result.push(PolicyItem {
            profile: profile.into(),
            kind: ItemKind::Dns,
            id: name.clone(),
            effect: "allow".into(),
            action: "network.resolve".into(),
            selector: name.clone(),
            detail: "DNS".into(),
            change,
            effect_of_change: effect,
            rule: None,
            network: None,
        });
    }
    for rule in &current.rules {
        let (change, effect) = mark("rule", &rule.id);
        result.push(PolicyItem {
            profile: profile.into(),
            kind: ItemKind::of_action(&rule.action),
            id: rule.id.clone(),
            effect: rule.effect.clone(),
            action: rule.action.clone(),
            selector: rule.selector(),
            detail: rule.action.clone(),
            change,
            effect_of_change: effect,
            rule: Some(rule.clone()),
            network: None,
        });
    }
    // Rules the draft removes stay visible, struck through, until published.
    for removed in snapshot
        .draft
        .changes
        .iter()
        .filter(|c| c.profile == profile && c.change == "removed" && c.kind != "profile")
    {
        let words: Vec<&str> = removed.before.splitn(3, ' ').collect();
        let (kind, effect, action, selector, detail) = match removed.kind.as_str() {
            "dns" => (
                ItemKind::Dns,
                "allow",
                "network.resolve".to_string(),
                removed.id.clone(),
                "DNS".to_string(),
            ),
            "network" => (
                ItemKind::Network,
                words.first().copied().unwrap_or(""),
                "network".to_string(),
                words.get(1).copied().unwrap_or("").to_string(),
                words.get(2).copied().unwrap_or("").to_string(),
            ),
            _ => {
                let action = words.get(1).copied().unwrap_or("").to_string();
                (
                    ItemKind::of_action(&action),
                    words.first().copied().unwrap_or(""),
                    action.clone(),
                    words.get(2).copied().unwrap_or("").to_string(),
                    action,
                )
            }
        };
        result.push(PolicyItem {
            profile: profile.into(),
            kind,
            id: removed.id.clone(),
            effect: effect.into(),
            action,
            selector,
            detail,
            change: "removed".into(),
            effect_of_change: removed.effect.clone(),
            rule: None,
            network: None,
        });
    }
    let order = |kind: &ItemKind| match kind {
        ItemKind::Network => 0,
        ItemKind::Dns => 1,
        ItemKind::Mount => 2,
        ItemKind::Mcp => 3,
        ItemKind::Credential => 4,
    };
    result.sort_by_key(|item| order(&item.kind));
    result
}

/// An edit to one profile of the draft document.
#[derive(Clone, Debug, PartialEq)]
pub enum Edit {
    /// Add a network rule, or replace the one with `replacing` as its ID.
    Network {
        rule: NetworkRule,
        replacing: Option<String>,
    },
    Rule {
        rule: Rule,
        replacing: Option<String>,
    },
    AddDns(String),
    Remove {
        kind: ItemKind,
        id: String,
    },
}

impl Edit {
    pub fn summary(&self, profile: &str) -> String {
        match self {
            Self::Network {
                rule,
                replacing: Some(_),
            } => format!("{profile} · edit {}", rule.id),
            Self::Network { rule, .. } => format!("{profile} · add {}", rule.id),
            Self::Rule {
                rule,
                replacing: Some(_),
            } => format!("{profile} · edit {}", rule.id),
            Self::Rule { rule, .. } => format!("{profile} · add {}", rule.id),
            Self::AddDns(name) => format!("{profile} · add DNS {name}"),
            Self::Remove { id, .. } => format!("{profile} · remove {id}"),
        }
    }
}

/// Apply an edit, checking what the service would reject anyway: unique IDs
/// within the profile and a selector for the action. Go validates again.
pub fn apply_edit(document: &Document, profile: &str, edit: &Edit) -> Result<Document> {
    let mut document = document.clone();
    let entry = document
        .profiles
        .get_mut(profile)
        .ok_or_else(|| anyhow::anyhow!("Profile {profile} is not in the draft"))?;
    let taken = |entry: &Profile, id: &str, replacing: &Option<String>| {
        replacing.as_deref() != Some(id)
            && (entry.rules.iter().any(|r| r.id == id)
                || entry.network.rules.iter().any(|r| r.id == id))
    };
    match edit {
        Edit::Network { rule, replacing } => {
            validate_id(&rule.id)?;
            ensure!(
                !taken(entry, &rule.id, replacing),
                "Rule ID {} is already used in {profile}",
                rule.id
            );
            ensure!(
                matches!(rule.effect.as_str(), "allow" | "deny"),
                "Effect must be allow or deny"
            );
            ensure!(!rule.cidr.trim().is_empty(), "CIDR is required");
            match replacing {
                Some(id) => {
                    let slot = entry
                        .network
                        .rules
                        .iter_mut()
                        .find(|r| &r.id == id)
                        .ok_or_else(|| anyhow::anyhow!("Rule {id} is no longer in the draft"))?;
                    *slot = rule.clone();
                }
                None => entry.network.rules.push(rule.clone()),
            }
        }
        Edit::Rule { rule, replacing } => {
            validate_id(&rule.id)?;
            ensure!(
                !taken(entry, &rule.id, replacing),
                "Rule ID {} is already used in {profile}",
                rule.id
            );
            ensure!(
                matches!(rule.effect.as_str(), "allow" | "deny"),
                "Effect must be allow or deny"
            );
            ensure!(
                RULE_ACTIONS.contains(&rule.action.as_str()),
                "Unsupported action {}",
                rule.action
            );
            ensure!(
                !rule.selector().trim_matches([' ', '·']).is_empty(),
                "The rule needs a target"
            );
            match replacing {
                Some(id) => {
                    let slot = entry
                        .rules
                        .iter_mut()
                        .find(|r| &r.id == id)
                        .ok_or_else(|| anyhow::anyhow!("Rule {id} is no longer in the draft"))?;
                    *slot = rule.clone();
                }
                None => entry.rules.push(rule.clone()),
            }
        }
        Edit::AddDns(name) => {
            let name = name.trim().to_ascii_lowercase();
            ensure!(
                !name.is_empty() && !name.contains(char::is_whitespace),
                "Enter one DNS name"
            );
            ensure!(
                !entry.network.dns.contains(&name),
                "{name} is already allowed"
            );
            entry.network.dns.push(name);
        }
        Edit::Remove { kind, id } => {
            let before = entry.rules.len() + entry.network.rules.len() + entry.network.dns.len();
            match kind {
                ItemKind::Network => entry.network.rules.retain(|r| &r.id != id),
                ItemKind::Dns => entry.network.dns.retain(|name| name != id),
                _ => entry.rules.retain(|r| &r.id != id),
            }
            ensure!(
                entry.rules.len() + entry.network.rules.len() + entry.network.dns.len() < before,
                "{id} is no longer in the draft"
            );
        }
    }
    Ok(document)
}

fn validate_id(id: &str) -> Result<()> {
    ensure!(
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b)),
        "Rule IDs use letters, digits, '.', '_', ':' or '-'"
    );
    Ok(())
}

/// Parse "443, 8443" into ports; empty means every port.
pub fn parse_ports(value: &str) -> Result<Vec<u16>> {
    value
        .split([',', ' '])
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| {
            p.parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or_else(|| anyhow::anyhow!("Ports are numbers from 1 to 65535"))
        })
        .collect()
}

/// A new revision label for today, unique among recent generations.
pub fn next_revision(snapshot: &OrgSnapshot, now: i64) -> String {
    let day = crate::clock::format(now)[..10].to_owned();
    (1..)
        .map(|n| format!("{day}.{n}"))
        .find(|candidate| {
            !snapshot
                .generations
                .iter()
                .any(|g| &g.revision == candidate)
        })
        .unwrap_or(day)
}

// ---------------------------------------------------------------- acknowledgements

/// How the rollout generation was acknowledged over time: the data behind
/// the Rollouts chart. Times are Unix seconds.
#[derive(Clone, Debug, PartialEq)]
pub struct AckSeries {
    pub generation: u64,
    pub start: i64,
    pub end: i64,
    /// Cumulative acknowledgements: (time, hosts acknowledged by then).
    pub steps: Vec<(i64, u32)>,
    pub offered: u32,
    pub total: u32,
    /// Later rings promoted during the rollout: (time, ring).
    pub promotions: Vec<(i64, String)>,
}

impl AckSeries {
    /// Where `time` falls between start and end, 0.0..=1.0.
    pub fn x(&self, time: i64) -> f32 {
        ((time - self.start) as f32 / (self.end - self.start).max(1) as f32).clamp(0.0, 1.0)
    }
    pub fn y(&self, count: u32) -> f32 {
        count as f32 / self.total.max(1) as f32
    }
}

pub fn acknowledgements(snapshot: &OrgSnapshot, now: i64) -> Option<AckSeries> {
    let rollout = snapshot.overview.rollout.as_ref()?;
    let start = crate::clock::parse(&rollout.started_at)?;
    let offered: Vec<&Host> = snapshot
        .active_hosts()
        .filter(|h| h.served >= rollout.generation)
        .collect();
    let mut times: Vec<i64> = offered
        .iter()
        .filter(|h| h.served == rollout.generation)
        .filter_map(|h| h.acknowledged_at.as_deref().and_then(crate::clock::parse))
        .map(|t| t.max(start))
        .collect();
    times.sort_unstable();
    let end = now
        .max(times.last().copied().unwrap_or(start))
        .max(start + 60);
    let promotions = rollout
        .rings
        .iter()
        .filter_map(|ring| {
            let at = crate::clock::parse(ring.promoted_at.as_deref()?)?;
            (at > start).then(|| (at, ring.name.clone()))
        })
        .collect();
    Some(AckSeries {
        generation: rollout.generation,
        start,
        end,
        steps: times
            .into_iter()
            .enumerate()
            .map(|(i, t)| (t, i as u32 + 1))
            .collect(),
        offered: offered.len() as u32,
        total: snapshot.active_hosts().count() as u32,
        promotions,
    })
}

// ---------------------------------------------------------------- diff tree

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mark {
    Same,
    Added,
    Removed,
}

/// One line of a data.json diff tree, indented by `depth`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffLine {
    pub depth: usize,
    pub mark: Mark,
    pub text: String,
}

/// A structural diff of two policy documents. Changed objects and arrays are
/// expanded; unchanged ones collapse to a line. Rules are matched by ID, and
/// names such as DNS entries by value, so a reordering is not a change.
pub fn diff_tree(before: Option<&serde_json::Value>, after: &serde_json::Value) -> Vec<DiffLine> {
    let mut out = vec![];
    diff_node(None, before, Some(after), 0, &mut out);
    out
}

fn diff_line(depth: usize, mark: Mark, text: String) -> DiffLine {
    DiffLine { depth, mark, text }
}

fn diff_node(
    key: Option<&str>,
    before: Option<&serde_json::Value>,
    after: Option<&serde_json::Value>,
    depth: usize,
    out: &mut Vec<DiffLine>,
) {
    use serde_json::Value;
    let prefix = key
        .map(|k| format!("{}: ", Value::from(k)))
        .unwrap_or_default();
    match (before, after) {
        (Some(b), Some(a)) if b == a => out.push(diff_line(
            depth,
            Mark::Same,
            format!("{prefix}{}", collapsed(a)),
        )),
        (None, Some(a)) => expand(&prefix, a, depth, Mark::Added, out),
        (Some(b), None) => expand(&prefix, b, depth, Mark::Removed, out),
        (Some(Value::Object(b)), Some(Value::Object(a))) => {
            out.push(diff_line(depth, Mark::Same, format!("{prefix}{{")));
            let mut keys: Vec<&String> = b.keys().collect();
            keys.extend(a.keys().filter(|k| !b.contains_key(*k)));
            for k in keys {
                diff_node(Some(k), b.get(k), a.get(k), depth + 1, out);
            }
            out.push(diff_line(depth, Mark::Same, "}".into()));
        }
        (Some(Value::Array(b)), Some(Value::Array(a))) => {
            out.push(diff_line(depth, Mark::Same, format!("{prefix}[")));
            diff_array(b, a, depth + 1, out);
            out.push(diff_line(depth, Mark::Same, "]".into()));
        }
        (Some(b), Some(a)) => {
            expand(&prefix, b, depth, Mark::Removed, out);
            expand(&prefix, a, depth, Mark::Added, out);
        }
        (None, None) => {}
    }
}

fn diff_array(
    before: &[serde_json::Value],
    after: &[serde_json::Value],
    depth: usize,
    out: &mut Vec<DiffLine>,
) {
    let id = |v: &serde_json::Value| v.get("id").and_then(|id| id.as_str()).map(str::to_owned);
    let keyed = before.iter().chain(after).all(|v| id(v).is_some());
    let key = |v: &serde_json::Value| {
        if keyed {
            id(v).unwrap_or_default()
        } else {
            v.to_string()
        }
    };
    // Unchanged names collapse into a count; unchanged rules keep their ID.
    let mut unchanged = 0;
    let flush = |unchanged: &mut usize, out: &mut Vec<DiffLine>| {
        if *unchanged > 0 {
            out.push(diff_line(
                depth,
                Mark::Same,
                format!("… {unchanged} unchanged"),
            ));
            *unchanged = 0;
        }
    };
    for a in after {
        match before.iter().find(|b| key(b) == key(a)) {
            Some(b) if b == a && !keyed => unchanged += 1,
            Some(b) => {
                flush(&mut unchanged, out);
                diff_node(None, Some(b), Some(a), depth, out);
            }
            None => {
                flush(&mut unchanged, out);
                diff_node(None, None, Some(a), depth, out);
            }
        }
    }
    flush(&mut unchanged, out);
    for b in before
        .iter()
        .filter(|b| !after.iter().any(|a| key(a) == key(b)))
    {
        diff_node(None, Some(b), None, depth, out);
    }
}

/// One line for an unchanged value: scalars in full, containers summarized.
fn collapsed(value: &serde_json::Value) -> String {
    use serde_json::Value;
    match value {
        Value::Object(map) if map.is_empty() => "{}".into(),
        Value::Object(map) => match map.get("id") {
            Some(id) => format!("{{ \"id\": {id}, … }}"),
            None => "{ … }".into(),
        },
        Value::Array(items) if items.is_empty() => "[]".into(),
        Value::Array(_) => inline(value).unwrap_or_else(|| {
            let count = value.as_array().map(Vec::len).unwrap_or_default();
            format!("[ … {count} item{} ]", if count == 1 { "" } else { "s" })
        }),
        scalar => scalar.to_string(),
    }
}

/// Short arrays of scalars fit on one line, like `[443, 8443]`.
fn inline(value: &serde_json::Value) -> Option<String> {
    let items = value.as_array()?;
    if items.iter().any(|v| v.is_object() || v.is_array()) {
        return None;
    }
    let text = format!(
        "[{}]",
        items
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    (text.chars().count() <= 48).then_some(text)
}

fn expand(
    prefix: &str,
    value: &serde_json::Value,
    depth: usize,
    mark: Mark,
    out: &mut Vec<DiffLine>,
) {
    use serde_json::Value;
    match value {
        Value::Object(map) if !map.is_empty() => {
            out.push(diff_line(depth, mark, format!("{prefix}{{")));
            for (k, v) in map {
                expand(
                    &format!("{}: ", Value::from(k.as_str())),
                    v,
                    depth + 1,
                    mark,
                    out,
                );
            }
            out.push(diff_line(depth, mark, "}".into()));
        }
        Value::Array(items) if !items.is_empty() => match inline(value) {
            Some(text) => out.push(diff_line(depth, mark, format!("{prefix}{text}"))),
            None => {
                out.push(diff_line(depth, mark, format!("{prefix}[")));
                for item in items {
                    expand("", item, depth + 1, mark, out);
                }
                out.push(diff_line(depth, mark, "]".into()));
            }
        },
        other => out.push(diff_line(
            depth,
            mark,
            format!("{prefix}{}", collapsed(other)),
        )),
    }
}

// ---------------------------------------------------------------- page rows

/// Records the Organization pages list.
#[derive(Clone, Debug)]
pub enum OrgRecord {
    Host(Box<Host>),
    Generation(Box<Generation>),
    Item(Box<PolicyItem>),
    Change(Box<Change>),
}

pub fn host_rows(snapshot: &OrgSnapshot, revoked: bool) -> Vec<Row> {
    snapshot
        .hosts
        .iter()
        .filter(|h| revoked || !h.revoked)
        .map(|h| Row {
            key: key(&["host", &h.name, &h.certificate.fingerprint]),
            cells: vec![
                h.name.clone(),
                h.profile.clone(),
                h.ring.clone(),
                status_label(h).into(),
                h.certificate.fingerprint.clone(),
            ],
            record: crate::workspace::Record::Org(OrgRecord::Host(Box::new(h.clone()))),
        })
        .collect()
}

pub fn generation_rows(snapshot: &OrgSnapshot) -> Vec<Row> {
    snapshot
        .generations
        .iter()
        .map(|g| Row {
            key: key(&["generation", &g.number.to_string()]),
            cells: vec![
                format!("g{}", g.number),
                g.revision.clone(),
                g.published_by.clone(),
                g.changes
                    .iter()
                    .map(|c| c.summary.clone())
                    .collect::<Vec<_>>()
                    .join(", "),
                g.hosts.to_string(),
            ],
            record: crate::workspace::Record::Org(OrgRecord::Generation(Box::new(g.clone()))),
        })
        .collect()
}

pub fn policy_rows(snapshot: &OrgSnapshot, profile: &str) -> Vec<Row> {
    let mut rows: Vec<Row> = items(snapshot, profile)
        .into_iter()
        .map(|item| Row {
            key: key(&[
                "item",
                &item.profile,
                item.kind.label(),
                &item.id,
                &item.change,
            ]),
            cells: vec![
                item.effect.to_uppercase(),
                item.selector.clone(),
                item.detail.clone(),
                item.id.clone(),
                item.change.clone(),
            ],
            record: crate::workspace::Record::Org(OrgRecord::Item(Box::new(item))),
        })
        .collect();
    rows.extend(
        snapshot
            .draft
            .changes
            .iter()
            .enumerate()
            .map(|(index, change)| Row {
                key: key(&[
                    "change",
                    &index.to_string(),
                    &change.profile,
                    &change.kind,
                    &change.id,
                ]),
                cells: vec![
                    change.change.clone(),
                    change.profile.clone(),
                    change.kind.clone(),
                    change.summary.clone(),
                    change.effect.clone(),
                ],
                record: crate::workspace::Record::Org(OrgRecord::Change(Box::new(change.clone()))),
            }),
    );
    rows
}

/// Human wording for a host status reported by the service.
pub fn status_label(host: &Host) -> &'static str {
    match host.status.as_str() {
        "idle" if host.held => "held for its ring",
        "current" => "current",
        "waiting" => "waiting",
        "offered" => "offered",
        "pending" => "applying",
        "stalled" => "stalled",
        "rejected" => "rejected",
        "mismatch" => "digest mismatch",
        "silent" => "silent",
        "never" => "never polled",
        "revoked" => "revoked",
        "idle" => "nothing published",
        _ => "unknown",
    }
}

/// Statuses that need an administrator to look.
pub fn needs_attention(host: &Host) -> bool {
    matches!(host.status.as_str(), "stalled" | "rejected" | "mismatch")
}

pub fn behind(host: &Host) -> bool {
    matches!(host.status.as_str(), "waiting" | "offered" | "pending")
}

pub fn silent(host: &Host) -> bool {
    matches!(host.status.as_str(), "silent" | "never")
}

/// Days until an RFC 3339 time, negative once past.
pub fn days_until(value: &str, now: i64) -> Option<i64> {
    crate::clock::parse(value).map(|then| (then - now).div_euclid(86_400))
}

// ---------------------------------------------------------------- demo

/// Sample organization for demo mode and tests. Clearly labelled; never a
/// fallback for a failed connection.
pub fn demo() -> OrgSnapshot {
    use sha2::Digest;
    let digest = |seed: &str| format!("{:x}", sha2::Sha256::digest(seed.as_bytes()));
    let now = crate::clock::now();
    let at = |seconds_ago: i64| crate::clock::format(now - seconds_ago);
    let later = |days: i64| crate::clock::format(now + days * 86_400);
    let document = Document {
        version: 1,
        organization: "acme".into(),
        revision: "2026-09-16.1".into(),
        expires_at: later(23),
        profiles: BTreeMap::from([
            (
                "developer".into(),
                Profile {
                    rules: vec![
                        Rule {
                            id: "src-read".into(),
                            effect: "allow".into(),
                            action: "mount.read".into(),
                            path: "/srv/src".into(),
                            ..Default::default()
                        },
                        Rule {
                            id: "scratch-write".into(),
                            effect: "allow".into(),
                            action: "mount.write".into(),
                            path: "/srv/src/scratch".into(),
                            ..Default::default()
                        },
                        Rule {
                            id: "linear".into(),
                            effect: "allow".into(),
                            action: "mcp.connect".into(),
                            server: "linear".into(),
                            ..Default::default()
                        },
                        Rule {
                            id: "linear-comment".into(),
                            effect: "allow".into(),
                            action: "mcp.tools.call".into(),
                            server: "linear".into(),
                            tool: "create_comment".into(),
                            ..Default::default()
                        },
                        Rule {
                            id: "gh-cred".into(),
                            effect: "allow".into(),
                            action: "credential.use".into(),
                            host: "github.com".into(),
                            ..Default::default()
                        },
                    ],
                    network: Network {
                        rules: vec![
                            NetworkRule {
                                id: "https".into(),
                                effect: "allow".into(),
                                cidr: "0.0.0.0/0".into(),
                                protocol: "tcp".into(),
                                ports: vec![443],
                            },
                            NetworkRule {
                                id: "metadata".into(),
                                effect: "deny".into(),
                                cidr: "169.254.0.0/16".into(),
                                protocol: "any".into(),
                                ports: vec![],
                            },
                            NetworkRule {
                                id: "staging-db".into(),
                                effect: "allow".into(),
                                cidr: "10.20.0.0/16".into(),
                                protocol: "tcp".into(),
                                ports: vec![5432],
                            },
                        ],
                        dns: vec![
                            "github.com".into(),
                            "*.githubusercontent.com".into(),
                            "*.docker.io".into(),
                            "pypi.org".into(),
                            "registry.npmjs.org".into(),
                        ],
                    },
                },
            ),
            (
                "ci".into(),
                Profile {
                    rules: vec![Rule {
                        id: "ghcr".into(),
                        effect: "allow".into(),
                        action: "credential.use".into(),
                        host: "ghcr.io".into(),
                        ..Default::default()
                    }],
                    network: Network {
                        rules: vec![NetworkRule {
                            id: "https".into(),
                            effect: "allow".into(),
                            cidr: "0.0.0.0/0".into(),
                            protocol: "tcp".into(),
                            ports: vec![443],
                        }],
                        dns: vec!["github.com".into(), "ghcr.io".into()],
                    },
                },
            ),
            (
                "contractor".into(),
                Profile {
                    rules: vec![Rule {
                        id: "vendor-read".into(),
                        effect: "allow".into(),
                        action: "mount.read".into(),
                        path: "/srv/vendor".into(),
                        ..Default::default()
                    }],
                    network: Network {
                        rules: vec![NetworkRule {
                            id: "https".into(),
                            effect: "allow".into(),
                            cidr: "0.0.0.0/0".into(),
                            protocol: "tcp".into(),
                            ports: vec![443],
                        }],
                        dns: vec!["github.com".into()],
                    },
                },
            ),
        ]),
    };
    // The unpublished draft: one rule added and one removed since g43.
    let mut draft = document.clone();
    if let Some(developer) = draft.profiles.get_mut("developer") {
        developer.network.rules.push(NetworkRule {
            id: "redis-cache".into(),
            effect: "allow".into(),
            cidr: "10.30.0.0/16".into(),
            protocol: "tcp".into(),
            ports: vec![6379],
        });
        developer.rules.retain(|rule| rule.id != "scratch-write");
    }
    let change =
        |profile: &str, kind: &str, id: &str, change: &str, effect: &str, summary: &str| Change {
            profile: profile.into(),
            kind: kind.into(),
            id: id.into(),
            change: change.into(),
            effect: effect.into(),
            summary: summary.into(),
            before: if change == "removed" {
                summary.into()
            } else {
                String::new()
            },
            after: if change == "removed" {
                String::new()
            } else {
                summary.into()
            },
        };
    let draft_changes = vec![
        change(
            "developer",
            "network",
            "staging-db",
            "added",
            "loosens",
            "allow 10.20.0.0/16 tcp 5432",
        ),
        change(
            "developer",
            "dns",
            "registry.npmjs.org",
            "added",
            "loosens",
            "registry.npmjs.org",
        ),
        change(
            "developer",
            "rule",
            "linear-delete",
            "removed",
            "tightens",
            "allow mcp.tools.call linear · delete_issue",
        ),
    ];
    let ring = |name: &str, generation: u64, hosts: u32| Ring {
        name: name.into(),
        generation,
        hosts,
    };
    let host = |name: &str,
                profile: &str,
                ring: &str,
                status: &str,
                applied: u64,
                target: u64,
                seen: i64,
                cert_days: i64| {
        let mut report = HostReport {
            at: at(seen),
            applied,
            digest_matches: true,
            profile: profile.into(),
            agent: "gantry/v0.0.24".into(),
            address: "10.0.4.17".into(),
            ..Default::default()
        };
        if status == "stalled" {
            report.pending = target;
            report.attempts = 13;
            report.failed = Some(1);
        }
        Host {
            name: name.into(),
            profile: profile.into(),
            ring: ring.into(),
            certificate: HostCertificate {
                serial: "4be1c0ffee90af".into(),
                fingerprint: format!("sha256:{}", digest(name)),
                not_after: later(cert_days),
                issued_at: at(86_400 * 30),
                issued_by: "ops-admin".into(),
            },
            target,
            served: target,
            served_at: Some(at(700)),
            acknowledged_at: (status == "current").then(|| at(660)),
            polls_since_served: if status == "stalled" { 13 } else { 1 },
            status: status.into(),
            last_seen: Some(at(seen)),
            report: Some(report),
            ..Default::default()
        }
    };
    let mut hosts = vec![
        host("build-eu-1", "ci", "canary", "current", 43, 43, 8, 214),
        host("build-eu-2", "ci", "canary", "current", 43, 43, 21, 214),
        host(
            "dev-mac-014",
            "developer",
            "canary",
            "current",
            43,
            43,
            3,
            301,
        ),
        host(
            "dev-lin-007",
            "developer",
            "early",
            "current",
            43,
            43,
            12,
            160,
        ),
        host(
            "dev-mac-021",
            "developer",
            "early",
            "stalled",
            42,
            43,
            9,
            288,
        ),
        host(
            "dev-lin-012",
            "developer",
            "early",
            "offered",
            42,
            43,
            27,
            97,
        ),
        host("ci-runner-us-4", "ci", "early", "current", 43, 43, 2, 214),
        host(
            "dev-mac-003",
            "developer",
            "everyone",
            "current",
            42,
            42,
            14,
            41,
        ),
        host(
            "dev-mac-030",
            "developer",
            "everyone",
            "silent",
            42,
            42,
            3 * 3600,
            180,
        ),
        host(
            "ext-vendor-1",
            "contractor",
            "everyone",
            "current",
            42,
            42,
            19,
            12,
        ),
        host(
            "ext-vendor-2",
            "contractor",
            "everyone",
            "current",
            42,
            42,
            9,
            12,
        ),
    ];
    // g43 went to canary 720 s ago and to early 420 s ago; hosts acknowledged
    // within their next poll, except the stalled and the late one.
    for (index, host) in hosts.iter_mut().enumerate() {
        let (offered, acked) = match host.ring.as_str() {
            "canary" => (715, 700 - index as i64 * 9),
            "early" => (415, 400 - index as i64 * 6),
            _ => (86_400 * 7, 86_400 * 7 - 30),
        };
        host.served_at = Some(at(offered));
        host.acknowledged_at = (host.status == "current").then(|| at(acked));
        if host.status == "offered" {
            host.served_at = Some(at(40));
        }
    }
    let generation = |number: u64,
                      revision: &str,
                      days_ago: i64,
                      changes: Vec<Change>,
                      hosts: u32,
                      republish_of: u64| Generation {
        number,
        revision: revision.into(),
        expires_at: later(30 - days_ago),
        published_at: at(days_ago * 86_400 + 600),
        published_by: "ops-admin".into(),
        bundle_sha256: digest(&format!("g{number}")),
        size: 3100,
        profiles: vec!["ci".into(), "contractor".into(), "developer".into()],
        rules: 23,
        dns_names: 11,
        republish_of,
        changes,
        hosts,
    };
    let generations = vec![
        generation(43, "2026-09-23.1", 0, draft_changes.clone(), 5, 0),
        generation(
            42,
            "2026-09-16.1",
            7,
            vec![change(
                "",
                "expiry",
                "",
                "changed",
                "neutral",
                "Expiry 2026-10-09 → 2026-10-16",
            )],
            6,
            0,
        ),
        generation(
            41,
            "2026-09-09.1",
            14,
            vec![change(
                "ci",
                "rule",
                "ghcr",
                "added",
                "loosens",
                "allow credential.use ghcr.io",
            )],
            0,
            0,
        ),
        generation(
            40,
            "2026-09-02.2",
            21,
            vec![change(
                "developer",
                "network",
                "block-docker",
                "removed",
                "loosens",
                "deny *.docker.io",
            )],
            0,
            38,
        ),
        generation(
            39,
            "2026-09-02.1",
            21,
            vec![change(
                "developer",
                "network",
                "block-docker",
                "added",
                "tightens",
                "deny *.docker.io",
            )],
            0,
            0,
        ),
    ];
    OrgSnapshot {
        overview: Overview {
            organization: "acme".into(),
            feed_url: "https://policy.acme.dev:8443/v1/feed".into(),
            public_key_fingerprint: format!("sha256:{}", digest("acme-policy-2026")),
            public_key_bits: 3072,
            ca_fingerprint: format!("sha256:{}", digest("acme hosts CA")),
            ca_expires_at: later(840),
            admin: "ops-admin".into(),
            latest: 43,
            rings: vec![
                ring("canary", 43, 3),
                ring("early", 43, 4),
                ring("everyone", 42, 4),
            ],
            rollout: Some(Rollout {
                generation: 43,
                started_at: at(720),
                started_by: "ops-admin".into(),
                rings: vec![
                    RolloutRing {
                        name: "canary".into(),
                        promoted_at: Some(at(720)),
                        promoted_by: "ops-admin".into(),
                        hosts: 3,
                        acknowledged: 3,
                        ..Default::default()
                    },
                    RolloutRing {
                        name: "early".into(),
                        promoted_at: Some(at(420)),
                        promoted_by: "ops-admin".into(),
                        hosts: 4,
                        acknowledged: 2,
                        offered: 1,
                        stalled: 1,
                        ..Default::default()
                    },
                    RolloutRing {
                        name: "everyone".into(),
                        hosts: 4,
                        ..Default::default()
                    },
                ],
                complete: false,
            }),
            hosts: HostCounts {
                enrolled: 11,
                current: 8,
                behind: 1,
                stalled: 1,
                silent: 1,
                ..Default::default()
            },
            next_expiry: Some(later(23)),
        },
        hosts,
        generations,
        draft: Draft {
            base: 43,
            data: serde_json::to_value(Root {
                gantry: draft.clone(),
            })
            .unwrap_or_default(),
            changes: vec![
                change(
                    "developer",
                    "network",
                    "redis-cache",
                    "added",
                    "loosens",
                    "allow 10.30.0.0/16 tcp 6379",
                ),
                change(
                    "developer",
                    "rule",
                    "scratch-write",
                    "removed",
                    "tightens",
                    "allow mount.write /srv/src/scratch",
                ),
            ],
            saved: true,
            updated_at: Some(at(300)),
            updated_by: "ops-admin".into(),
            problem: String::new(),
        },
        base_data: serde_json::to_value(Root { gantry: document }).ok(),
        document: Some(draft),
    }
    .with_held()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_types_read_the_go_contract() {
        let overview: Overview = serde_json::from_str(r#"{
            "organization":"acme","feedUrl":"https://p:8443/v1/feed","publicKeyFingerprint":"sha256:ab",
            "publicKeyBits":3072,"caFingerprint":"sha256:cd","caExpiresAt":"2036-01-01T00:00:00Z",
            "admin":"ops-admin","latest":2,
            "rings":[{"name":"canary","generation":2,"hosts":1},{"name":"everyone","generation":1,"hosts":0}],
            "rollout":{"generation":2,"startedAt":"2026-09-23T09:41:00Z","startedBy":"ops-admin",
              "rings":[{"name":"canary","promotedAt":"2026-09-23T09:41:00Z","promotedBy":"ops-admin","hosts":1,"acknowledged":1,"offered":0,"stalled":0,"rejected":0},
                       {"name":"everyone","hosts":0,"acknowledged":0,"offered":0,"stalled":0,"rejected":0}],"complete":false},
            "hosts":{"enrolled":1,"current":1,"behind":0,"stalled":0,"rejected":0,"silent":0,"revoked":0}}"#).unwrap();
        assert_eq!(overview.rings.len(), 2);
        assert_eq!(overview.rollout.as_ref().unwrap().rings[0].acknowledged, 1);
        let host: Host = serde_json::from_str(r#"{"name":"h","profile":"developer","ring":"canary",
            "certificate":{"serial":"1f","fingerprint":"sha256:00","notAfter":"2027-01-01T00:00:00Z","issuedAt":"2026-01-01T00:00:00Z","issuedBy":"ops-admin"},
            "revoked":false,"target":2,"served":2,"servedAt":"2026-09-23T09:41:00Z","pollsSinceServed":3,"status":"stalled",
            "report":{"at":"2026-09-23T09:42:00Z","applied":1,"digestMatches":true,"pending":2,"attempts":3,"failed":1,
              "profile":"developer","agent":"gantry/v1","address":"10.0.0.1"}}"#).unwrap();
        assert_eq!(host.report.as_ref().unwrap().failed, Some(1));
        let generation: Generation = serde_json::from_str(r#"{"number":2,"revision":"r2","expiresAt":"2026-10-01T00:00:00Z",
            "publishedAt":"2026-09-23T09:41:00Z","publishedBy":"ops-admin","bundleSha256":"ff","size":3100,
            "profiles":["developer"],"rules":3,"dnsNames":1,"republishOf":1,"changes":null,"hosts":1}"#).unwrap();
        assert_eq!(
            (
                generation.republish_of,
                generation.dns_names,
                generation.changes.len()
            ),
            (1, 1, 0)
        );
    }

    #[test]
    fn documents_round_trip_in_the_shape_go_accepts() {
        let raw = r#"{"gantry":{"version":1,"organization":"acme","revision":"r1","expires_at":"2026-10-23T09:40:00Z",
            "profiles":{"developer":{"rules":[{"id":"src","effect":"allow","action":"mount.read","path":"/srv/src"}],
            "network":{"rules":[{"id":"https","effect":"allow","cidr":"0.0.0.0/0","protocol":"tcp","ports":null}],"dns":null}}}}}"#;
        let root: Root = serde_json::from_str(raw).unwrap();
        let encoded = serde_json::to_value(&root).unwrap();
        let rule = &encoded["gantry"]["profiles"]["developer"]["rules"][0];
        assert!(
            rule.get("server").is_none()
                && rule.get("tool").is_none()
                && rule["path"] == "/srv/src"
        );
        assert_eq!(
            encoded["gantry"]["profiles"]["developer"]["network"]["rules"][0]["ports"],
            serde_json::json!([])
        );
        assert_eq!(serde_json::from_value::<Root>(encoded).unwrap(), root);
    }

    #[test]
    fn edits_keep_ids_unique_and_track_removals() {
        let snapshot = demo();
        let document = snapshot.document.clone().unwrap();
        let added = apply_edit(
            &document,
            "developer",
            &Edit::Network {
                rule: NetworkRule {
                    id: "redis".into(),
                    effect: "allow".into(),
                    cidr: "10.30.0.0/16".into(),
                    protocol: "tcp".into(),
                    ports: vec![6379],
                },
                replacing: None,
            },
        )
        .unwrap();
        assert_eq!(
            added.profiles["developer"].network.rules.len(),
            document.profiles["developer"].network.rules.len() + 1
        );
        let duplicate = apply_edit(
            &document,
            "developer",
            &Edit::Rule {
                rule: Rule {
                    id: "https".into(),
                    effect: "allow".into(),
                    action: "mount.read".into(),
                    path: "/x".into(),
                    ..Default::default()
                },
                replacing: None,
            },
        );
        assert!(duplicate.unwrap_err().to_string().contains("already used"));
        let renamed = apply_edit(
            &document,
            "developer",
            &Edit::Rule {
                rule: Rule {
                    id: "src-read".into(),
                    effect: "deny".into(),
                    action: "mount.read".into(),
                    path: "/srv/src".into(),
                    ..Default::default()
                },
                replacing: Some("src-read".into()),
            },
        )
        .unwrap();
        assert_eq!(renamed.profiles["developer"].rules[0].effect, "deny");
        let removed = apply_edit(
            &document,
            "developer",
            &Edit::Remove {
                kind: ItemKind::Dns,
                id: "pypi.org".into(),
            },
        )
        .unwrap();
        assert!(
            !removed.profiles["developer"]
                .network
                .dns
                .contains(&"pypi.org".to_string())
        );
        assert!(
            apply_edit(
                &document,
                "developer",
                &Edit::Remove {
                    kind: ItemKind::Dns,
                    id: "nope".into()
                }
            )
            .is_err()
        );
        assert!(apply_edit(&document, "developer", &Edit::AddDns("github.com".into())).is_err());
        assert!(apply_edit(&document, "missing", &Edit::AddDns("x.org".into())).is_err());
        let missing_target = apply_edit(
            &document,
            "developer",
            &Edit::Rule {
                rule: Rule {
                    id: "t".into(),
                    effect: "allow".into(),
                    action: "mcp.tools.call".into(),
                    ..Default::default()
                },
                replacing: None,
            },
        );
        assert!(missing_target.is_err());
    }

    #[test]
    fn items_mark_changes_and_keep_removed_rules_visible() {
        let mut snapshot = demo();
        snapshot.draft.changes = vec![
            Change {
                profile: "developer".into(),
                kind: "network".into(),
                id: "staging-db".into(),
                change: "added".into(),
                effect: "loosens".into(),
                ..Default::default()
            },
            Change {
                profile: "developer".into(),
                kind: "rule".into(),
                id: "linear-delete".into(),
                change: "removed".into(),
                effect: "tightens".into(),
                before: "allow mcp.tools.call linear · delete_issue".into(),
                summary: "allow mcp.tools.call linear · delete_issue".into(),
                ..Default::default()
            },
        ];
        let items = items(&snapshot, "developer");
        let staging = items.iter().find(|i| i.id == "staging-db").unwrap();
        assert_eq!(
            (staging.change.as_str(), staging.effect_of_change.as_str()),
            ("added", "loosens")
        );
        let removed = items.iter().find(|i| i.id == "linear-delete").unwrap();
        assert!(removed.removed());
        assert_eq!(
            (
                removed.kind.clone(),
                removed.action.as_str(),
                removed.selector.as_str()
            ),
            (ItemKind::Mcp, "mcp.tools.call", "linear · delete_issue")
        );
        assert_eq!(items.first().unwrap().kind, ItemKind::Network);
    }

    #[test]
    fn acknowledgements_count_only_hosts_offered_the_rollout() {
        let snapshot = demo();
        let now = crate::clock::now();
        let series = acknowledgements(&snapshot, now).unwrap();
        assert_eq!(series.generation, 43);
        assert_eq!(series.total, 11);
        // canary 3 + early 4 were offered g43; everyone is held on g42.
        assert_eq!(series.offered, 7);
        assert_eq!(series.steps.len(), 5);
        assert!(
            series
                .steps
                .windows(2)
                .all(|w| w[0].0 <= w[1].0 && w[1].1 == w[0].1 + 1)
        );
        assert_eq!(series.promotions.len(), 1);
        assert_eq!(series.promotions[0].1, "early");
        assert!(series.x(series.start) == 0.0 && series.x(now + 10) == 1.0);
        assert!(acknowledgements(&OrgSnapshot::default(), now).is_none());
    }

    #[test]
    fn diff_tree_expands_changes_and_collapses_the_rest() {
        let snapshot = demo();
        let lines = snapshot.diff().expect("the demo draft has changes");
        let text = |mark: Mark| {
            lines
                .iter()
                .filter(|l| l.mark == mark)
                .map(|l| l.text.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        };
        let (added, removed, same) = (text(Mark::Added), text(Mark::Removed), text(Mark::Same));
        assert!(
            added.contains(r#""id": "redis-cache""#) && added.contains("[6379]"),
            "{added}"
        );
        assert!(removed.contains(r#""id": "scratch-write""#), "{removed}");
        // Unchanged rules keep their ID; unchanged profiles collapse.
        assert!(same.contains(r#"{ "id": "https", … }"#), "{same}");
        assert!(same.contains(r#""ci": { … }"#), "{same}");
        assert!(!added.contains("staging-db") && !removed.contains("staging-db"));
        // Names are matched by value: a reordering is not a change.
        let before = serde_json::json!({"dns": ["a.org", "b.org"]});
        let after = serde_json::json!({"dns": ["b.org", "a.org", "c.org"]});
        let lines = diff_tree(Some(&before), &after);
        assert_eq!(lines.iter().filter(|l| l.mark != Mark::Same).count(), 1);
        assert!(lines.iter().any(|l| l.text == "… 2 unchanged"));
        // With no base, everything is new.
        assert!(
            diff_tree(None, &after)
                .iter()
                .all(|l| l.mark == Mark::Added)
        );
        assert!(
            OrgSnapshot {
                draft: Draft::default(),
                ..demo()
            }
            .diff()
            .is_none()
        );
    }

    #[test]
    fn helpers_encode_and_parse() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(&[0xfb, 0xff]), "+/8=");
        assert_eq!(parse_ports("443, 8443").unwrap(), vec![443, 8443]);
        assert!(parse_ports("0").is_err() && parse_ports("http").is_err());
        assert!(parse_ports("").unwrap().is_empty());
        assert!(validate_name("dev-mac-031").is_ok() && validate_name("../x").is_err());
        assert_eq!(
            short_fingerprint("sha256:9f2c0000000000000000a41b"),
            "9f2c00…a41b"
        );
        let snapshot = demo();
        assert_eq!(snapshot.next_ring().as_deref(), Some("everyone"));
        assert_eq!(snapshot.previous_generation(), Some(42));
        let revision = next_revision(
            &snapshot,
            crate::clock::parse("2026-09-23T10:00:00Z").unwrap(),
        );
        assert_eq!(revision, "2026-09-23.2");
    }

    #[test]
    fn fingerprints_match_the_service() {
        // An RSA public key and its fingerprint as the Go service computes it:
        // SHA-256 over x509.MarshalPKIXPublicKey.
        let pem = b"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+TMFH1mb0AqaYxQE93GK
cmmp6/v4fqI0HrSzhgLK/doLveV1jFu5Ul7tSJUjyZ3O1K7+Hvv056CggpPNRUKS
yoZ0N5JnxMBs0mkr+L1QIwLSVgEDoehjpm8LL39icujBkg2eh0uB+xuC0+reYNn1
N2fm1+hRLMefyl2WN9GATsIKR3dFVMNESNuUTrocHsIXWF5P+pxaEq03t95Fqs5i
NDS8Y1lDAvVP8oddOeWP3RtCpz7lxV52PXSjfAVl8Zdn1/Cws0vcnG8wyz56Hq9q
Tc3jBakzroIMkUNAT2gV/dkWaeBaVWtuHteXPh6A2xHY8T57IRBNiMC/9Gew3gqG
PwIDAQAB
-----END PUBLIC KEY-----
";
        assert_eq!(
            public_key_fingerprint(pem).unwrap(),
            "sha256:843485ac1762751a95183c95e8d1e45bbb84a271299c5a208695b0b8b71580a4"
        );
        assert!(public_key_fingerprint(b"not a key").is_err());
    }
}
