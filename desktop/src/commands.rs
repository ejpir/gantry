//! Typed write intents. No command can change its captured source or silently
//! replay after an ambiguous transport failure.
use crate::{api::ManagerClient, dashboard_wire::*};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSandbox {
    pub name: String,
    pub image: String,
    pub kernel: String,
    pub runtime: String,
    #[serde(rename = "memoryMiB")]
    pub memory_mib: u64,
    pub cpus: i64,
    #[serde(rename = "diskSizeMiB")]
    pub disk_size_mib: u64,
    pub rw: bool,
    pub net: bool,
    pub ssh: bool,
    pub dev_containers: bool,
    pub process_isolation: String,
}
#[derive(Clone, Debug)]
pub enum Command {
    Create(CreateSandbox),
    Configure(SandboxConfigRequest),
    Start(String),
    Stop(String),
    Delete(String),
    PullImage(String),
    Dashboard(Box<ActionRequest>),
    Share(ShareRequest),
    Port(String, PortRequest),
    Packets(String, PacketRequest),
    NetworkPolicy {
        sandbox: String,
        policy: String,
        default: bool,
        allow_local: bool,
    },
    /// A write to an organization's policy service.
    Org(crate::org::OrgCommand),
}
#[derive(Debug, Default)]
pub struct Outcome {
    pub message: String,
    pub packets: Option<(String, PacketSnapshot)>,
}
#[derive(Deserialize)]
pub struct Operation {
    pub id: String,
    pub state: String,
    #[serde(default)]
    pub error: String,
    #[serde(default)]
    pub progress: String,
    #[serde(default, deserialize_with = "crate::wire::null_vec")]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub configure: Option<ConfigureResult>,
}
#[derive(Deserialize)]
pub struct ConfigureResult {
    #[serde(rename = "restartRequired")]
    pub restart_required: bool,
}

pub fn name_path(name: &str) -> Result<String> {
    ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name != "."
            && name != ".."
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "Invalid sandbox name"
    );
    Ok(format!("/v1/sandboxes/{name}"))
}
impl Command {
    pub fn label(&self) -> &str {
        match self {
            Self::Create(_) => "Create sandbox",
            Self::Configure(_) => "Save settings",
            Self::Start(_) => "Start sandbox",
            Self::Stop(_) => "Stop sandbox",
            Self::Delete(_) => "Delete sandbox",
            Self::PullImage(_) => "Pull image",
            Self::Share(_) => "Configure mount",
            Self::Port(..) => "Publish port",
            Self::Packets(..) => "Packet capture",
            Self::NetworkPolicy { .. } => "Set network policy",
            Self::Dashboard(_) => "Apply configuration",
            Self::Org(command) => command.label(),
        }
    }
    pub fn subject(&self) -> String {
        match self {
            Self::Start(name) | Self::Stop(name) | Self::Delete(name) | Self::PullImage(name) => {
                name.clone()
            }
            Self::Create(r) => r.name.clone(),
            Self::Configure(r) => r.name.clone(),
            Self::Share(r) => format!("{} / {}", r.sandbox, r.tag),
            Self::Port(name, _) | Self::Packets(name, _) => name.clone(),
            Self::NetworkPolicy { sandbox, .. } => sandbox.clone(),
            Self::Org(command) => command.subject(),
            Self::Dashboard(r) => {
                let target = if let Some(v) = &r.rule {
                    format!("{} / {} / {}", v.sandbox, v.source, v.target)
                } else if let Some(v) = &r.mount {
                    format!("{} / {}", v.sandbox, v.tag)
                } else if let Some(v) = &r.secret_row {
                    format!("{} / {}", v.sandbox, v.name)
                } else if let Some(v) = &r.mcp_server {
                    format!("{} / {}", v.sandbox, v.name)
                } else if let Some(v) = &r.port {
                    format!("{} / {}", v.sandbox, v.spec)
                } else {
                    r.value.clone()
                };
                format!("{} · {target}", r.action)
            }
        }
    }
    fn secrets(&self) -> Vec<&str> {
        match self {
            Self::Dashboard(request) => request
                .secret
                .as_ref()
                .map(|s| s.value.expose())
                .into_iter()
                .chain(request.registry.as_ref().map(|r| r.secret.expose()))
                .collect(),
            _ => Vec::new(),
        }
    }
}

impl ManagerClient {
    /// Read captured packets after a cursor, as the live Packet Capture view
    /// does every second. Reads never change capture state, so unlike
    /// [`Self::execute`] this skips the control-capability round trip.
    pub fn read_packets(&self, name: &str, after: u64) -> Result<PacketSnapshot> {
        name_path(name)?;
        let request = PacketRequest {
            after,
            max_packets: 256,
            max_bytes: 262_144,
            ..Default::default()
        };
        self.request(
            "POST",
            &format!("/v1/dashboard/packets/{name}"),
            Some(&request),
            Duration::from_secs(15),
            &[],
        )
    }
    pub fn execute(&self, command: &Command) -> Result<Outcome> {
        self.execute_with_progress(command, |_| {})
    }
    pub fn execute_with_progress(
        &self,
        command: &Command,
        progress: impl Fn(&str),
    ) -> Result<Outcome> {
        if let Command::Org(command) = command {
            // Recheck what the endpoint is: an organization write never goes
            // to a manager, and a manager write never to a policy service.
            let (_, capabilities) = self.health()?;
            ensure!(
                capabilities.iter().any(|c| c == crate::org::CAPABILITY),
                "The selected connection is no longer an organization policy service; no write was sent."
            );
            progress(&format!(
                "Submitting {} · {}",
                command.label(),
                command.subject()
            ));
            return self.org_execute(command, progress);
        }
        self.require_control()?;
        progress(&format!(
            "Submitting {} · {}",
            command.label(),
            command.subject()
        ));
        let secrets = command.secrets();
        let timeout = Duration::from_secs(120);
        let action = |request: &ActionRequest| -> Result<ActionResult> {
            self.request(
                "POST",
                "/v1/dashboard/actions",
                Some(request),
                timeout,
                &secrets,
            )
        };
        let mut message = "Saved. The manager remains authoritative.".to_string();
        let operation = match command {
            Command::Create(request) => {
                name_path(&request.name)?;
                Some(self.request("POST", "/v1/sandboxes", Some(request), timeout, &secrets)?)
            }
            Command::Configure(request) => {
                let body = serde_json::json!({"memoryMiB":request.mem_mb,"cpus":request.vcpus,"processIsolation":request.process_isolation,"ssh":request.ssh,"devContainers":request.dev_containers});
                Some(self.request(
                    "PATCH",
                    &name_path(&request.name)?,
                    Some(&body),
                    timeout,
                    &secrets,
                )?)
            }
            Command::Start(name) | Command::Stop(name) | Command::Delete(name) => {
                let mut path = name_path(name)?;
                let method = match command {
                    Command::Start(_) => {
                        path.push_str("/start");
                        "POST"
                    }
                    Command::Stop(_) => {
                        path.push_str("/stop");
                        "POST"
                    }
                    _ => "DELETE",
                };
                Some(self.request::<Operation, ()>(method, &path, None, timeout, &secrets)?)
            }
            Command::PullImage(image) => Some(self.request(
                "POST",
                "/v1/images/pull",
                Some(&serde_json::json!({"ref":image})),
                timeout,
                &secrets,
            )?),
            Command::Dashboard(request) => {
                let result = action(request)?;
                if result.restart_required {
                    message="Saved for next boot. Restart required; the running allocation was not changed.".into();
                }
                if request.action == "prune-images" {
                    message = format!("Pruned {} images.", result.count);
                }
                if !result.warning.is_empty() && secrets.is_empty() {
                    message = self.safe_message(&result.warning, &secrets);
                }
                None
            }
            Command::Share(request) => {
                let result = action(&ActionRequest {
                    action: "plan-share".into(),
                    share: Some(request.clone()),
                    ..Default::default()
                })?;
                let plan = result.share_plan.ok_or_else(|| {
                    anyhow::anyhow!("Manager returned no share plan; nothing was applied")
                })?;
                ensure!(
                    plan.sandbox == request.sandbox && plan.tag == request.tag,
                    "Manager returned a different share target; nothing was applied"
                );
                action(&ActionRequest {
                    action: "configure-share".into(),
                    share_plan: Some(plan),
                    ..Default::default()
                })?;
                None
            }
            Command::Port(sandbox, request) => {
                name_path(sandbox)?;
                let result = action(&ActionRequest {
                    action: "plan-port".into(),
                    port_request: Some(request.clone()),
                    ..Default::default()
                })?;
                ensure!(
                    !result.port_spec.is_empty(),
                    "Manager returned no port plan; nothing was applied"
                );
                action(&ActionRequest {
                    action: "publish-port".into(),
                    port: Some(PortMutationRequest {
                        sandbox: sandbox.clone(),
                        spec: result.port_spec,
                    }),
                    ..Default::default()
                })?;
                None
            }
            Command::Packets(name, request) => {
                name_path(name)?;
                let packets = self.request(
                    "POST",
                    &format!("/v1/dashboard/packets/{name}"),
                    Some(request),
                    Duration::from_secs(15),
                    &secrets,
                )?;
                return Ok(Outcome {
                    message: "Packet capture refreshed. Payloads are held in memory only.".into(),
                    packets: Some((name.clone(), packets)),
                });
            }
            Command::NetworkPolicy {
                sandbox,
                policy,
                default,
                allow_local,
            } => {
                let body = if *default {
                    serde_json::json!({"default":true,"allowLocal":allow_local})
                } else {
                    let policy: serde_json::Value = serde_json::from_str(policy)
                        .map_err(|_| anyhow::anyhow!("Policy must be valid JSON"))?;
                    serde_json::json!({"policy":policy,"allowLocal":allow_local})
                };
                Some(self.request(
                    "PUT",
                    &format!("{}/net-policy", name_path(sandbox)?),
                    Some(&body),
                    timeout,
                    &secrets,
                )?)
            }
            Command::Org(_) => unreachable!("organization writes return above"),
        };
        if let Some(mut operation) = operation {
            let deadline = Instant::now() + Duration::from_secs(120);
            while operation.state == "running" && Instant::now() < deadline {
                progress(&self.safe_message(
                    &format!("Operation {} · {}", operation.id, operation.progress),
                    &secrets,
                ));
                ensure!(
                    !operation.id.is_empty()
                        && operation.id.len() <= 128
                        && operation
                            .id
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
                    "Manager returned an invalid operation ID"
                );
                std::thread::sleep(Duration::from_millis(500));
                operation = self.request::<Operation, ()>(
                    "GET",
                    &format!("/v1/operations/{}", operation.id),
                    None,
                    Duration::from_secs(5),
                    &secrets,
                )?;
            }
            ensure!(
                operation.state != "running",
                "Operation is still running on the manager. Refresh before retrying; the request was not replayed."
            );
            ensure!(
                operation.state == "succeeded",
                "Manager operation failed: {}",
                self.safe_message(&operation.error, &secrets)
            );
            message = if operation
                .configure
                .is_some_and(|config| config.restart_required)
            {
                "Saved for next boot. Restart required; running resources remain unchanged.".into()
            } else {
                format!("{} completed.", command.label())
            };
            if !operation.warnings.is_empty() {
                message.push_str(&format!(
                    " {}",
                    self.safe_message(&operation.warnings.join("; "), &secrets)
                ));
            }
        }
        Ok(Outcome {
            message,
            packets: None,
        })
    }
}
