use crate::config::{AppProfile, ManagerConfig, SubscriptionConfig};
use crate::domain::{ManagerState, Node, reconcile_selected};
use crate::dto::{CheckStatus, DoctorCheckDto, NodeDto, OperationResultDto, StatusDto};
use crate::events::ManagerEvent;
use crate::ports::{
    AppLaunchRequest, AppRouteTestRequest, Capability, DownloadRequest, DynBackendSet,
    ExecutionPlan, PlanAction, UpgradeTarget, XrayTestRequest,
};
use crate::probe::{NodeProbeOutcome, probe_all, probe_all_streaming};
use crate::render::render_xray_config;
use crate::routing::RoutingConfig;
use crate::subscription::parse_subscription;
use crate::{ManagerError, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::sync::mpsc::UnboundedReceiver;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Query {
    Status,
    Doctor { quick: bool },
    Nodes,
    CurrentNode,
    Routing,
    Assets,
    Core,
    ServiceLogs { lines: usize },
    ServiceStatus,
    ProxyShow,
    ProxyEnv,
    TunStatus,
    Subscriptions,
    RoutingValidate,
    RoutingPresets,
    NodeProbe { id: String },
    NodeProbeAll,
    RoutingExplain { name: Option<String> },
    AssetShow { id: String },
    CoreList,
    ProxyTest,
    TunShowRules,
    TunTest,
    AppList,
    MenuSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Operation {
    Install {
        user: Option<String>,
    },
    Repair,
    Uninstall,
    Purge,
    Apply,
    UpgradeAll,
    UpgradeCore,
    UpgradeAssets,
    UpgradeManager,
    SubscriptionRefresh {
        name: Option<String>,
    },
    NodeSelect {
        id: String,
    },
    RoutingApply,
    ServiceStart,
    ServiceStop,
    ServiceRestart,
    TunEnable,
    TunDisable,
    TunCleanup,
    DesktopProxyEnable {
        user: String,
    },
    DesktopProxyDisable {
        user: String,
    },
    AppRun {
        profile: Option<String>,
        command: Vec<String>,
    },
    AppTest {
        profile: String,
    },
    AppProfileRemove {
        name: String,
    },
    AppProfilePut {
        profile: AppProfile,
    },
    SubscriptionAdd {
        name: String,
        url: String,
    },
    SubscriptionRemove {
        name: String,
    },
    SubscriptionEnable {
        name: String,
        enabled: bool,
    },
    ConfigRollback,
    CoreRollback,
    AssetRollback,
    RoutingPreset {
        name: String,
    },
    RoutingSet {
        routing: RoutingConfig,
    },
}

impl Operation {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Install { .. } => "install",
            Self::Repair => "repair",
            Self::Uninstall => "uninstall",
            Self::Purge => "purge",
            Self::Apply => "apply",
            Self::UpgradeAll => "upgrade_all",
            Self::UpgradeCore => "upgrade_core",
            Self::UpgradeAssets => "upgrade_assets",
            Self::UpgradeManager => "upgrade_manager",
            Self::SubscriptionRefresh { .. } => "subscription_refresh",
            Self::NodeSelect { .. } => "node_select",
            Self::RoutingApply => "routing_apply",
            Self::ServiceStart => "service_start",
            Self::ServiceStop => "service_stop",
            Self::ServiceRestart => "service_restart",
            Self::TunEnable => "tun_enable",
            Self::TunDisable => "tun_disable",
            Self::TunCleanup => "tun_cleanup",
            Self::DesktopProxyEnable { .. } => "desktop_proxy_enable",
            Self::DesktopProxyDisable { .. } => "desktop_proxy_disable",
            Self::AppRun { .. } => "app_run",
            Self::AppTest { .. } => "app_test",
            Self::AppProfileRemove { .. } => "app_profile_remove",
            Self::AppProfilePut { .. } => "app_profile_put",
            Self::SubscriptionAdd { .. } => "subscription_add",
            Self::SubscriptionRemove { .. } => "subscription_remove",
            Self::SubscriptionEnable { enabled: true, .. } => "subscription_enable",
            Self::SubscriptionEnable { enabled: false, .. } => "subscription_disable",
            Self::ConfigRollback => "config_rollback",
            Self::CoreRollback => "core_rollback",
            Self::AssetRollback => "asset_rollback",
            Self::RoutingPreset { .. } => "routing_preset",
            Self::RoutingSet { .. } => "routing_set",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OperationOptions {
    pub dry_run: bool,
    pub assume_yes: bool,
}

pub struct ManagerService {
    config: ManagerConfig,
    state: RwLock<ManagerState>,
    backends: DynBackendSet,
}

pub struct ProbeSession {
    pub receiver: UnboundedReceiver<NodeProbeOutcome>,
    cancelled: Arc<AtomicBool>,
}

impl ProbeSession {
    pub fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

impl ManagerService {
    pub fn new(config: ManagerConfig, state: ManagerState, backends: DynBackendSet) -> Self {
        Self {
            config,
            state: RwLock::new(state),
            backends,
        }
    }

    pub async fn status(&self) -> Result<StatusDto> {
        let state = self.state.read().await;
        Ok(StatusDto {
            installed: state.current_core_version.is_some(),
            selected_node: state.selected_node_id.clone(),
            core_version: state.current_core_version.clone(),
            asset_generation: state.current_asset_generation.clone(),
            backends: self.backends.selections.clone(),
            capabilities: self.backends.capabilities.clone(),
        })
    }

    pub async fn is_elevated(&self) -> Result<bool> {
        self.backends.privilege.is_elevated().await
    }

    pub async fn start_node_probes(&self) -> Result<ProbeSession> {
        let nodes = self.load_nodes().await?;
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        tokio::spawn(probe_all_streaming(
            nodes,
            self.config.clone(),
            self.backends.xray.clone(),
            self.backends.events.clone(),
            cancelled.clone(),
            Some(sender),
        ));
        Ok(ProbeSession {
            receiver,
            cancelled,
        })
    }

    pub async fn query(&self, query: Query) -> Result<serde_json::Value> {
        match query {
            Query::Status => serde_json::to_value(self.status().await?)
                .map_err(|error| ManagerError::Other(error.to_string())),
            Query::Doctor { quick } => {
                let platform = self.backends.inspector.inspect().await?;
                let elevated = self.backends.privilege.is_elevated().await?;
                let mut checks = vec![
                    DoctorCheckDto {
                        id: "platform-backends".into(),
                        status: if self.backends.capabilities.iter().all(|item| item.supported) {
                            CheckStatus::Pass
                        } else {
                            CheckStatus::Warn
                        },
                        message: "platform capability discovery completed".into(),
                        remediation: self
                            .backends
                            .capabilities
                            .iter()
                            .any(|item| !item.supported)
                            .then(|| {
                                "satisfy backend requirements or select another compiled backend"
                                    .into()
                            }),
                    },
                    DoctorCheckDto {
                        id: "configuration".into(),
                        status: CheckStatus::Pass,
                        message: "configuration is valid".into(),
                        remediation: None,
                    },
                    DoctorCheckDto {
                        id: "platform".into(),
                        status: CheckStatus::Pass,
                        message: format!(
                            "{} / {} / {}",
                            platform.os,
                            platform.distribution.as_deref().unwrap_or("unknown"),
                            platform.init_system.as_deref().unwrap_or("unknown")
                        ),
                        remediation: None,
                    },
                    DoctorCheckDto {
                        id: "privileges".into(),
                        status: if elevated {
                            CheckStatus::Pass
                        } else {
                            CheckStatus::Warn
                        },
                        message: if elevated {
                            "running with administrative privileges".into()
                        } else {
                            "running without administrative privileges".into()
                        },
                        remediation: (!elevated).then(|| {
                            "elevate only when executing a privileged system operation".into()
                        }),
                    },
                ];
                if !quick {
                    match self.backends.package_advisor.missing_requirements().await {
                        Ok(missing) => checks.push(DoctorCheckDto {
                            id: "packages".into(),
                            status: if missing.is_empty() {
                                CheckStatus::Pass
                            } else {
                                CheckStatus::Fail
                            },
                            message: if missing.is_empty() {
                                "required platform commands are installed".into()
                            } else {
                                format!("missing commands: {}", missing.join(", "))
                            },
                            remediation: self.backends.package_advisor.install_hint(&missing),
                        }),
                        Err(ManagerError::PlatformUnsupported { .. }) => {
                            checks.push(DoctorCheckDto {
                                id: "packages".into(),
                                status: CheckStatus::Warn,
                                message: "package advice is unavailable".into(),
                                remediation: None,
                            });
                        }
                        Err(error) => return Err(error),
                    }
                    let service_active = match self.backends.service.is_active("xray.service").await
                    {
                        Ok(active) => Some(active),
                        Err(ManagerError::PlatformUnsupported { .. }) => None,
                        Err(error) => return Err(error),
                    };
                    checks.push(DoctorCheckDto {
                        id: "xray-service".into(),
                        status: match service_active {
                            Some(true) => CheckStatus::Pass,
                            Some(false) => CheckStatus::Fail,
                            None => CheckStatus::Warn,
                        },
                        message: "service state checked".into(),
                        remediation: Some(
                            "run `sudo xrayctl repair` if the service is unavailable".into(),
                        ),
                    });
                    let paths = self.paths().await?;
                    let executable_name = if cfg!(target_os = "windows") {
                        "xray.exe"
                    } else {
                        "xray"
                    };
                    let executable = paths.install_dir.join("core/current").join(executable_name);
                    let config_dir = paths.state_dir.join("current/conf.d");
                    let asset_dir = paths.install_dir.join("assets/current");
                    let mut missing_paths = Vec::new();
                    for path in [&executable, &config_dir, &asset_dir] {
                        if !self.backends.filesystem.exists(path).await? {
                            missing_paths.push(path.display().to_string());
                        }
                    }
                    for asset in &self.config.assets {
                        let path = asset_dir.join(&asset.filename);
                        if !self.backends.filesystem.exists(&path).await? {
                            missing_paths.push(path.display().to_string());
                        }
                    }
                    checks.push(DoctorCheckDto {
                        id: "installed-layout".into(),
                        status: if missing_paths.is_empty() {
                            CheckStatus::Pass
                        } else {
                            CheckStatus::Fail
                        },
                        message: if missing_paths.is_empty() {
                            "core, configuration, and assets are present".into()
                        } else {
                            format!("missing paths: {}", missing_paths.join(", "))
                        },
                        remediation: (!missing_paths.is_empty())
                            .then(|| "run `sudo xrayctl repair`".into()),
                    });
                    if missing_paths.is_empty() {
                        let validation = self
                            .backends
                            .xray
                            .test_config(&XrayTestRequest {
                                executable,
                                config_dir,
                                asset_dir,
                            })
                            .await;
                        checks.push(DoctorCheckDto {
                            id: "xray-config".into(),
                            status: if validation.is_ok() {
                                CheckStatus::Pass
                            } else {
                                CheckStatus::Fail
                            },
                            message: if validation.is_ok() {
                                "installed Xray configuration is valid".into()
                            } else {
                                "installed Xray configuration validation failed".into()
                            },
                            remediation: validation.is_err().then(|| {
                                "run `sudo xrayctl repair` and inspect the previous generation"
                                    .into()
                            }),
                        });
                    }
                    let selected = self.state.read().await.selected_node_id.clone();
                    if service_active == Some(true) && selected.is_some() {
                        let health = self.backends.xray.healthcheck(&self.config).await;
                        checks.push(DoctorCheckDto {
                            id: "proxy-health".into(),
                            status: if health.is_ok() {
                                CheckStatus::Pass
                            } else {
                                CheckStatus::Fail
                            },
                            message: if health.is_ok() {
                                "SOCKS and HTTP proxy healthchecks succeeded".into()
                            } else {
                                "proxy healthcheck failed".into()
                            },
                            remediation: health
                                .is_err()
                                .then(|| "inspect `xrayctl service logs` and roll back".into()),
                        });
                    }
                    if self.config.tun.enabled {
                        let interface_active = self
                            .backends
                            .tun
                            .status(&self.config.tun.interface_name)
                            .await
                            .unwrap_or(false);
                        let firewall_present = self.backends.firewall.show().await.is_ok();
                        let policy = self
                            .backends
                            .policy_routing
                            .show(&self.config)
                            .await
                            .unwrap_or_default();
                        let fail_closed = policy.contains("blackhole default")
                            && policy.contains("unreachable default");
                        checks.push(DoctorCheckDto {
                            id: "selective-tun".into(),
                            status: if interface_active && firewall_present && fail_closed {
                                CheckStatus::Pass
                            } else {
                                CheckStatus::Fail
                            },
                            message: format!(
                                "interface={}, firewall={}, fail_closed={}",
                                interface_active, firewall_present, fail_closed
                            ),
                            remediation: (!(interface_active && firewall_present && fail_closed))
                                .then(|| {
                                    "run `sudo xrayctl tun cleanup`, then `sudo xrayctl tun enable`"
                                        .into()
                                }),
                        });
                    }
                }
                Ok(serde_json::json!({
                    "checks": checks,
                    "backends": self.backends.selections,
                    "capabilities": self.backends.capabilities
                }))
            }
            Query::Nodes => serde_json::to_value(
                self.load_nodes()
                    .await?
                    .iter()
                    .map(NodeDto::from)
                    .collect::<Vec<_>>(),
            )
            .map_err(|error| ManagerError::Other(error.to_string())),
            Query::CurrentNode => {
                let state = self.state.read().await;
                Ok(serde_json::json!({"selected_node": state.selected_node_id}))
            }
            Query::Routing => {
                let (routing, path) = self.load_routing().await?;
                Ok(serde_json::json!({"path": path, "routing": routing}))
            }
            Query::Assets => {
                let state = self.state.read().await;
                Ok(serde_json::json!({
                    "current": state.current_asset_generation,
                    "previous": state.previous_asset_generation
                }))
            }
            Query::Core => {
                let state = self.state.read().await;
                Ok(serde_json::json!({
                    "current": state.current_core_version,
                    "previous": state.previous_core_version
                }))
            }
            Query::ServiceLogs { lines } => Ok(serde_json::json!({
                "logs": self.backends.service.logs("xray.service", lines).await?
            })),
            Query::ServiceStatus => Ok(serde_json::json!({
                "active": self.backends.service.is_active("xray.service").await?
            })),
            Query::ProxyShow => Ok(serde_json::json!({
                "listen": self.config.proxy.listen,
                "socks_port": self.config.proxy.socks_port,
                "http_port": self.config.proxy.http_port
            })),
            Query::ProxyEnv => Ok(serde_json::json!({
                "HTTP_PROXY": format!("http://{}:{}", self.config.proxy.listen, self.config.proxy.http_port),
                "HTTPS_PROXY": format!("http://{}:{}", self.config.proxy.listen, self.config.proxy.http_port),
                "ALL_PROXY": format!("socks5h://{}:{}", self.config.proxy.listen, self.config.proxy.socks_port),
                "NO_PROXY": "localhost,127.0.0.1,::1"
            })),
            Query::TunStatus => Ok(serde_json::json!({
                "supported": self.backends.capabilities.iter().any(|item| {
                    item.capability == crate::ports::Capability::Tun && item.supported
                }),
                "active": self.backends.tun.status(&self.config.tun.interface_name).await?
            })),
            Query::Subscriptions => {
                let subscriptions = self
                    .load_subscriptions()
                    .await?
                    .into_iter()
                    .map(|subscription| {
                        serde_json::json!({
                            "name": subscription.name,
                            "enabled": subscription.enabled,
                            "format": subscription.format
                        })
                    })
                    .collect::<Vec<_>>();
                Ok(serde_json::json!(subscriptions))
            }
            Query::RoutingValidate => {
                let (_, path) = self.load_routing().await?;
                Ok(serde_json::json!({"valid": true, "path": path}))
            }
            Query::RoutingPresets => Ok(serde_json::json!([
                "global-proxy",
                "runet-blocked-only",
                "ru-direct"
            ])),
            Query::NodeProbe { id } => {
                let nodes = self.load_nodes().await?;
                let matches = nodes
                    .iter()
                    .filter(|node| node.id.as_str().starts_with(&id))
                    .cloned()
                    .collect::<Vec<_>>();
                let node = match matches.as_slice() {
                    [node] => node.clone(),
                    [] => {
                        return Err(ManagerError::InvalidNode(format!(
                            "node '{id}' was not found"
                        )));
                    }
                    _ => {
                        return Err(ManagerError::InvalidNode(format!(
                            "node ID prefix '{id}' is ambiguous"
                        )));
                    }
                };
                let result = self.backends.xray.probe(&node, &self.config).await?;
                Ok(serde_json::json!({"node": NodeDto::from(&node), "probe": result}))
            }
            Query::NodeProbeAll => {
                let outcomes = probe_all(
                    self.load_nodes().await?,
                    self.config.clone(),
                    self.backends.xray.clone(),
                    self.backends.events.clone(),
                    Arc::new(AtomicBool::new(false)),
                )
                .await;
                serde_json::to_value(outcomes)
                    .map_err(|error| ManagerError::Other(error.to_string()))
            }
            Query::RoutingExplain { name } => {
                let (routing, path) = self.load_routing().await?;
                Ok(serde_json::json!({
                    "path": path,
                    "node": name,
                    "default": routing.default_outbound,
                    "rules": routing.rules
                }))
            }
            Query::AssetShow { id } => {
                let asset = self
                    .config
                    .assets
                    .iter()
                    .find(|asset| asset.id == id)
                    .ok_or_else(|| {
                        ManagerError::InvalidConfig(format!("asset '{id}' was not found"))
                    })?;
                Ok(serde_json::json!({
                    "id": asset.id,
                    "filename": asset.filename,
                    "configured": true
                }))
            }
            Query::CoreList => {
                let state = self.state.read().await;
                Ok(serde_json::json!([
                    {"version": state.current_core_version, "role": "current"},
                    {"version": state.previous_core_version, "role": "previous"}
                ]))
            }
            Query::ProxyTest => {
                if !self.backends.service.is_active("xray.service").await? {
                    return Err(ManagerError::Other("xray.service is not active".into()));
                }
                self.backends.xray.healthcheck(&self.config).await?;
                Ok(serde_json::json!({
                    "ok": true,
                    "service_active": true,
                    "socks": format!("{}:{}", self.config.proxy.listen, self.config.proxy.socks_port),
                    "http": format!("{}:{}", self.config.proxy.listen, self.config.proxy.http_port)
                }))
            }
            Query::TunShowRules => Ok(serde_json::json!({
                "firewall": self.backends.firewall.show().await?,
                "policy_routing": self.backends.policy_routing.show(&self.config).await?,
                "routing_table": self.config.tun.routing_table,
                "packet_mark": self.config.tun.packet_mark
            })),
            Query::TunTest => {
                let policy_active = self
                    .backends
                    .service
                    .is_active("xray-tun-policy.service")
                    .await?;
                let interface_active = self
                    .backends
                    .tun
                    .status(&self.config.tun.interface_name)
                    .await?;
                let firewall_present = self.backends.firewall.show().await.is_ok();
                let policy = self.backends.policy_routing.show(&self.config).await?;
                let fail_closed_routes =
                    policy.contains("blackhole default") && policy.contains("unreachable default");
                Ok(serde_json::json!({
                    "ok": policy_active
                        && interface_active
                        && firewall_present
                        && self.config.tun.fail_closed
                        && fail_closed_routes,
                    "policy_active": policy_active,
                    "interface_active": interface_active,
                    "firewall_present": firewall_present,
                    "fail_closed": self.config.tun.fail_closed,
                    "fail_closed_routes": fail_closed_routes
                }))
            }
            Query::AppList => serde_json::to_value(self.load_app_profiles().await?)
                .map_err(|error| ManagerError::Other(error.to_string())),
            Query::MenuSettings => Ok(serde_json::json!({
                "probe_on_open": self.config.menu.probe_on_open,
                "latency_green_ms": self.config.menu.latency_green_ms,
                "latency_yellow_ms": self.config.menu.latency_yellow_ms
            })),
        }
    }

    async fn paths(&self) -> Result<crate::ports::ManagerPaths> {
        self.backends.layout.paths().await
    }

    async fn load_nodes(&self) -> Result<Vec<Node>> {
        let path = self.paths().await?.state_dir.join("nodes.json");
        if !self.backends.filesystem.exists(&path).await? {
            return Ok(Vec::new());
        }
        serde_json::from_slice(&self.backends.filesystem.read(&path).await?)
            .map_err(|error| ManagerError::Io(error.to_string()))
    }

    async fn write_nodes(&self, nodes: &[Node]) -> Result<()> {
        let path = self.paths().await?.state_dir.join("nodes.json");
        let bytes = serde_json::to_vec_pretty(nodes)
            .map_err(|error| ManagerError::Io(error.to_string()))?;
        self.backends
            .filesystem
            .write_atomic(&path, &bytes, Some(0o640))
            .await
    }

    async fn write_state(&self, state: &ManagerState) -> Result<()> {
        let path = self.paths().await?.state_dir.join("state.json");
        let bytes = serde_json::to_vec_pretty(state)
            .map_err(|error| ManagerError::Io(error.to_string()))?;
        self.backends
            .filesystem
            .write_atomic(&path, &bytes, Some(0o640))
            .await?;
        *self.state.write().await = state.clone();
        Ok(())
    }

    async fn reload_state(&self) -> Result<()> {
        let path = self.paths().await?.state_dir.join("state.json");
        let state = if self.backends.filesystem.exists(&path).await? {
            serde_json::from_slice(&self.backends.filesystem.read(&path).await?)
                .map_err(|error| ManagerError::Io(error.to_string()))?
        } else {
            ManagerState::default()
        };
        *self.state.write().await = state;
        Ok(())
    }

    async fn load_subscriptions(&self) -> Result<Vec<SubscriptionConfig>> {
        let directory = self.paths().await?.config_dir.join("subscriptions.d");
        let mut subscriptions = Vec::new();
        for path in self.backends.filesystem.list_files(&directory).await? {
            if path.extension().and_then(|value| value.to_str()) != Some("toml") {
                continue;
            }
            let bytes = self.backends.filesystem.read(&path).await?;
            let text =
                std::str::from_utf8(&bytes).map_err(|error| ManagerError::Io(error.to_string()))?;
            let subscription: SubscriptionConfig = toml::from_str(text)
                .map_err(|error| ManagerError::InvalidConfig(error.to_string()))?;
            subscription.validate()?;
            subscriptions.push(subscription);
        }
        subscriptions.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(subscriptions)
    }

    async fn write_subscription(&self, subscription: &SubscriptionConfig) -> Result<()> {
        subscription.validate()?;
        let path = self
            .paths()
            .await?
            .config_dir
            .join("subscriptions.d")
            .join(format!("{}.toml", subscription.name));
        let bytes = toml::to_string_pretty(subscription)
            .map_err(|error| ManagerError::InvalidConfig(error.to_string()))?;
        self.backends
            .filesystem
            .write_atomic(&path, bytes.as_bytes(), Some(0o600))
            .await
    }

    async fn subscription_path(&self, name: &str) -> Result<PathBuf> {
        validate_resource_name(name)?;
        Ok(self
            .paths()
            .await?
            .config_dir
            .join("subscriptions.d")
            .join(format!("{name}.toml")))
    }

    async fn load_app_profiles(&self) -> Result<Vec<AppProfile>> {
        let directory = self.paths().await?.config_dir.join("apps.d");
        let mut profiles = Vec::new();
        for path in self.backends.filesystem.list_files(&directory).await? {
            if path.extension().and_then(|value| value.to_str()) != Some("toml") {
                continue;
            }
            let bytes = self.backends.filesystem.read(&path).await?;
            let text = std::str::from_utf8(&bytes)
                .map_err(|error| ManagerError::InvalidConfig(error.to_string()))?;
            profiles.push(AppProfile::parse(text)?);
        }
        profiles.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(profiles)
    }

    async fn write_app_profile(&self, profile: &AppProfile) -> Result<()> {
        profile.validate()?;
        let encoded = toml::to_string_pretty(profile)
            .map_err(|error| ManagerError::InvalidConfig(error.to_string()))?;
        let path = self
            .paths()
            .await?
            .config_dir
            .join("apps.d")
            .join(format!("{}.toml", profile.name));
        self.backends
            .filesystem
            .write_atomic(&path, encoded.as_bytes(), Some(0o640))
            .await
    }

    async fn load_routing(&self) -> Result<(RoutingConfig, PathBuf)> {
        let path = self.paths().await?.config_dir.join("routing.toml");
        if !self.backends.filesystem.exists(&path).await? {
            return Ok((RoutingConfig::preset("global-proxy")?, path));
        }
        let bytes = self.backends.filesystem.read(&path).await?;
        let text =
            std::str::from_utf8(&bytes).map_err(|error| ManagerError::Io(error.to_string()))?;
        Ok((RoutingConfig::parse(text)?, path))
    }

    async fn write_routing_and_apply(&self, routing: &RoutingConfig) -> Result<()> {
        let encoded = toml::to_string_pretty(routing)
            .map_err(|error| ManagerError::InvalidConfig(error.to_string()))?;
        RoutingConfig::parse(&encoded)?;
        let paths = self.paths().await?;
        let path = paths.config_dir.join("routing.toml");
        let previous = if self.backends.filesystem.exists(&path).await? {
            Some(self.backends.filesystem.read(&path).await?)
        } else {
            None
        };
        self.backends
            .filesystem
            .write_atomic(&path, encoded.as_bytes(), Some(0o640))
            .await?;
        let selected_id = self.state.read().await.selected_node_id.clone();
        let selected = self.selected_node(selected_id.as_deref()).await?;
        if let Err(error) = self.apply_config(selected.as_ref()).await {
            if let Some(previous) = previous {
                self.backends
                    .filesystem
                    .write_atomic(&path, &previous, Some(0o640))
                    .await?;
            } else {
                self.backends
                    .filesystem
                    .remove_owned(&path, &paths.config_dir)
                    .await?;
            }
            return Err(error);
        }
        Ok(())
    }

    async fn selected_node(&self, selected_id: Option<&str>) -> Result<Option<Node>> {
        let Some(selected_id) = selected_id else {
            return Ok(None);
        };
        Ok(self
            .load_nodes()
            .await?
            .into_iter()
            .find(|node| node.id.as_str() == selected_id))
    }

    async fn commit_generation_rollback(
        &self,
        current: &std::path::Path,
        previous: &std::path::Path,
        old_state: &ManagerState,
        mut rollback_state: ManagerState,
        component: &str,
    ) -> Result<()> {
        rollback_state.last_rollback_reason = Some(format!("manual {component} rollback"));
        let activation = async {
            self.write_state(&rollback_state).await?;
            self.backends.service.restart("xray.service").await?;
            if rollback_state.selected_node_id.is_some() {
                self.backends.xray.healthcheck(&self.config).await?;
                rollback_state.last_successful_healthcheck =
                    Some(self.backends.clock.unix_timestamp().to_string());
                self.write_state(&rollback_state).await?;
            }
            Ok(())
        }
        .await;
        if let Err(error) = activation {
            let _ = self
                .backends
                .filesystem
                .rollback_generation(current, previous)
                .await;
            self.write_state(old_state).await?;
            let _ = self.backends.service.restart("xray.service").await;
            return Err(error);
        }
        Ok(())
    }

    async fn apply_config(&self, selected: Option<&Node>) -> Result<String> {
        let paths = self.paths().await?;
        let (routing, _) = self.load_routing().await?;
        let fragments_dir = paths.config_dir.join("fragments.d");
        let mut fragments = Vec::new();
        for path in self.backends.filesystem.list_files(&fragments_dir).await? {
            if path.extension().and_then(|value| value.to_str()) == Some("json") {
                let value = serde_json::from_slice(&self.backends.filesystem.read(&path).await?)
                    .map_err(|error| ManagerError::InvalidConfig(error.to_string()))?;
                fragments.push(value);
            }
        }
        let rendered = render_xray_config(&self.config, selected, &routing, fragments)?;
        static GENERATION_COUNTER: AtomicU64 = AtomicU64::new(0);
        let generation = format!(
            "{}-{}-{}",
            self.backends.clock.unix_timestamp(),
            std::process::id(),
            GENERATION_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let generations_root = paths.state_dir.join("generations");
        let candidate = generations_root.join(&generation);
        let config_dir = candidate.join("conf.d");
        self.backends.filesystem.create_dir_all(&config_dir).await?;
        self.backends
            .filesystem
            .set_permissions(&candidate, 0o750)
            .await?;
        self.backends
            .filesystem
            .set_permissions(&config_dir, 0o750)
            .await?;
        for (name, value) in rendered {
            let bytes = serde_json::to_vec_pretty(&value)
                .map_err(|error| ManagerError::InvalidConfig(error.to_string()))?;
            self.backends
                .filesystem
                .write_atomic(&config_dir.join(name), &bytes, Some(0o640))
                .await?;
        }
        self.backends
            .events
            .emit(ManagerEvent::ConfigValidationStarted);
        let executable_name = if cfg!(target_os = "windows") {
            "xray.exe"
        } else {
            "xray"
        };
        let validation = self
            .backends
            .xray
            .test_config(&XrayTestRequest {
                executable: paths.install_dir.join("core/current").join(executable_name),
                config_dir,
                asset_dir: paths.install_dir.join("assets/current"),
            })
            .await;
        if let Err(error) = validation {
            self.backends
                .events
                .emit(ManagerEvent::ConfigValidationFailed {
                    code: error.code().into(),
                });
            let _ = self
                .backends
                .filesystem
                .remove_owned(&candidate, &generations_root)
                .await;
            return Err(error);
        }
        self.backends
            .events
            .emit(ManagerEvent::ConfigValidationSucceeded);
        if let Err(error) = self
            .backends
            .identity
            .set_ownership(&candidate, "xray", "xray", true)
            .await
        {
            let _ = self
                .backends
                .filesystem
                .remove_owned(&candidate, &generations_root)
                .await;
            return Err(error);
        }
        let current = paths.state_dir.join("current");
        let previous = paths.state_dir.join("previous");
        let previous_state = self.state.read().await.clone();
        let old_current = previous_state
            .current_config_generation
            .as_ref()
            .map(|generation| generations_root.join(generation));
        let old_previous = previous_state
            .previous_config_generation
            .as_ref()
            .map(|generation| generations_root.join(generation));
        if let Err(error) = self
            .backends
            .filesystem
            .switch_generation(&current, &previous, &candidate)
            .await
        {
            let _ = self
                .backends
                .filesystem
                .remove_owned(&candidate, &generations_root)
                .await;
            return Err(error);
        }
        let mut state = previous_state.clone();
        state.previous_config_generation = state.current_config_generation.take();
        state.current_config_generation = Some(generation.clone());
        state.selected_node_id = selected.map(|node| node.id.as_str().into());
        if let Err(error) = self.write_state(&state).await {
            let _ = self
                .backends
                .filesystem
                .restore_generation(
                    &current,
                    &previous,
                    old_current.as_deref(),
                    old_previous.as_deref(),
                )
                .await;
            let _ = self
                .backends
                .filesystem
                .remove_owned(&candidate, &generations_root)
                .await;
            return Err(error);
        }
        self.backends
            .events
            .emit(ManagerEvent::ServiceRestartStarted);
        let activation = async {
            if self.config.tun.enabled {
                self.backends
                    .service
                    .enable("xray-tun-policy.service")
                    .await?;
                self.backends
                    .service
                    .start("xray-tun-policy.service")
                    .await?;
            } else {
                let _ = self.backends.service.stop("xray-tun-policy.service").await;
                self.backends.policy_routing.disable(&self.config).await?;
                self.backends.firewall.disable().await?;
                self.backends
                    .service
                    .disable("xray-tun-policy.service")
                    .await?;
            }
            self.backends.service.enable("xray.service").await?;
            self.backends.service.restart("xray.service").await?;
            if selected.is_some() {
                self.backends.xray.healthcheck(&self.config).await?;
            }
            Ok::<(), ManagerError>(())
        }
        .await;
        if let Err(error) = activation {
            self.backends.events.emit(ManagerEvent::RollbackStarted {
                reason: error.to_string(),
            });
            self.backends
                .filesystem
                .restore_generation(
                    &current,
                    &previous,
                    old_current.as_deref(),
                    old_previous.as_deref(),
                )
                .await?;
            let mut restored_state = previous_state;
            restored_state.last_rollback_reason =
                Some("configuration activation or healthcheck failed".into());
            self.write_state(&restored_state).await?;
            let _ = self.backends.service.restart("xray.service").await;
            let _ = self
                .backends
                .filesystem
                .remove_owned(&candidate, &generations_root)
                .await;
            self.backends.events.emit(ManagerEvent::RollbackSucceeded);
            return Err(error);
        }
        self.backends
            .events
            .emit(ManagerEvent::ServiceRestartSucceeded);
        if selected.is_some() {
            let mut healthy_state = self.state.read().await.clone();
            healthy_state.last_successful_healthcheck =
                Some(self.backends.clock.unix_timestamp().to_string());
            healthy_state.last_rollback_reason = None;
            self.write_state(&healthy_state).await?;
        }
        let _ = self
            .backends
            .filesystem
            .prune_generations(
                &paths.state_dir.join("generations"),
                &paths.state_dir.join("current"),
                &paths.state_dir.join("previous"),
                self.config.general.keep_generations,
            )
            .await;
        Ok(generation)
    }

    async fn refresh_subscriptions(&self, requested: Option<&str>) -> Result<Vec<String>> {
        if let Some(name) = requested {
            validate_resource_name(name)?;
        }
        let subscriptions = self.load_subscriptions().await?;
        if requested.is_some()
            && !subscriptions
                .iter()
                .any(|subscription| Some(subscription.name.as_str()) == requested)
        {
            return Err(ManagerError::InvalidConfig(format!(
                "subscription '{}' was not found",
                requested.unwrap_or_default()
            )));
        }
        let mut nodes = self.load_nodes().await?;
        let old_selected = {
            let selected_id = self.state.read().await.selected_node_id.clone();
            selected_id.and_then(|selected_id| {
                nodes
                    .iter()
                    .find(|node| node.id.as_str() == selected_id)
                    .cloned()
            })
        };
        let mut warnings = Vec::new();
        for subscription in subscriptions.into_iter().filter(|subscription| {
            subscription.enabled && requested.is_none_or(|name| name == subscription.name.as_str())
        }) {
            let artifact = self
                .backends
                .downloader
                .download(DownloadRequest {
                    url: subscription.url.clone(),
                    max_bytes: self.config.general.max_subscription_size_mb * 1024 * 1024,
                    timeout: Duration::from_secs(self.config.general.request_timeout_seconds),
                    max_redirects: 5,
                })
                .await?;
            self.backends.events.emit(ManagerEvent::DownloadProgress {
                id: format!("subscription:{}", subscription.name),
                downloaded: artifact.bytes.len() as u64,
                total: Some(artifact.bytes.len() as u64),
            });
            let parsed = parse_subscription(&artifact.bytes, &subscription.name)?;
            warnings.extend(
                parsed
                    .nodes
                    .iter()
                    .flat_map(|node| node.warnings.iter().cloned())
                    .map(|warning| format!("{}: {warning}", subscription.name)),
            );
            warnings.extend(
                parsed
                    .warnings
                    .into_iter()
                    .map(|warning| format!("{}: {warning}", subscription.name)),
            );
            nodes.retain(|node| node.subscription != subscription.name);
            nodes.extend(parsed.nodes);
        }
        nodes.sort_by(|left, right| left.name.cmp(&right.name));
        self.write_nodes(&nodes).await?;
        if let Some(old_selected) = old_selected {
            if let Some(replacement) = reconcile_selected(&old_selected, &old_selected.id, &nodes) {
                if replacement.id != old_selected.id {
                    let mut state = self.state.read().await.clone();
                    state.selected_node_id = Some(replacement.id.as_str().into());
                    self.write_state(&state).await?;
                    warnings.push(format!(
                        "selected node '{}' was reconciled by subscription and name; run `xrayctl apply` to activate refreshed credentials",
                        old_selected.name
                    ));
                }
            } else {
                warnings.push(format!(
                    "selected node '{}' disappeared or became ambiguous; the running configuration and saved selection were left unchanged",
                    old_selected.name
                ));
            }
        }
        Ok(warnings)
    }

    pub async fn plan(&self, operation: &Operation) -> Result<ExecutionPlan> {
        self.plan_internal(operation, true).await
    }

    async fn plan_internal(
        &self,
        operation: &Operation,
        enforce_capabilities: bool,
    ) -> Result<ExecutionPlan> {
        if matches!(operation, Operation::TunEnable) && !self.config.tun.enabled {
            return Err(ManagerError::InvalidConfig(
                "TUN is disabled in config.toml; set tun.enabled = true and run `xrayctl apply`"
                    .into(),
            ));
        }
        let mut capabilities = required_capabilities(operation);
        if self.config.tun.enabled
            && matches!(
                operation,
                Operation::Apply
                    | Operation::NodeSelect { .. }
                    | Operation::RoutingApply
                    | Operation::RoutingPreset { .. }
                    | Operation::RoutingSet { .. }
                    | Operation::ConfigRollback
            )
        {
            capabilities.extend([
                Capability::Firewall,
                Capability::PolicyRouting,
                Capability::Tun,
            ]);
        }
        if !self.config.tun.enabled
            && matches!(operation, Operation::Install { .. } | Operation::Repair)
        {
            capabilities.retain(|capability| {
                !matches!(
                    capability,
                    Capability::Firewall | Capability::PolicyRouting | Capability::Tun
                )
            });
        }
        capabilities.sort();
        capabilities.dedup();
        for capability in capabilities {
            if enforce_capabilities && !self.bootstrap_can_restore(operation, capability) {
                self.ensure_capability(capability)?;
            }
        }
        let backend_ids = self
            .backends
            .selections
            .iter()
            .map(|selection| (selection.capability, selection.backend_id.clone()))
            .collect();
        match operation {
            Operation::Install { user } => {
                let mut plan = self.backends.installer.plan_install(&self.config).await?;
                self.add_platform_requirements(&mut plan).await?;
                if let Some(user) = user {
                    validate_resource_name(user)?;
                    plan.actions.push(PlanAction::AddIdentityToGroup {
                        identity: user.clone(),
                        group: "xray-manager".into(),
                    });
                }
                Ok(plan)
            }
            Operation::Repair => {
                let mut plan = self.backends.installer.plan_repair(&self.config).await?;
                self.add_platform_requirements(&mut plan).await?;
                Ok(plan)
            }
            Operation::Uninstall => self.backends.installer.plan_uninstall(false).await,
            Operation::Purge => self.backends.installer.plan_uninstall(true).await,
            Operation::UpgradeAll => {
                self.backends
                    .installer
                    .plan_upgrade(&self.config, UpgradeTarget::All)
                    .await
            }
            Operation::UpgradeCore => {
                self.backends
                    .installer
                    .plan_upgrade(&self.config, UpgradeTarget::Core)
                    .await
            }
            Operation::UpgradeAssets => {
                self.backends
                    .installer
                    .plan_upgrade(&self.config, UpgradeTarget::Assets)
                    .await
            }
            Operation::UpgradeManager => {
                self.backends
                    .installer
                    .plan_upgrade(&self.config, UpgradeTarget::Manager)
                    .await
            }
            Operation::ServiceStart => Ok(ExecutionPlan {
                operation: operation.name().into(),
                backend_ids,
                actions: vec![PlanAction::StartService {
                    name: "xray.service".into(),
                }],
            }),
            Operation::ServiceStop => Ok(ExecutionPlan {
                operation: operation.name().into(),
                backend_ids,
                actions: vec![PlanAction::StopService {
                    name: "xray.service".into(),
                }],
            }),
            Operation::ServiceRestart => Ok(ExecutionPlan {
                operation: operation.name().into(),
                backend_ids,
                actions: vec![PlanAction::RestartService {
                    name: "xray.service".into(),
                }],
            }),
            Operation::TunEnable => Ok(ExecutionPlan {
                operation: operation.name().into(),
                backend_ids,
                actions: vec![
                    PlanAction::ConfigureFirewall {
                        backend: selected_backend(&self.backends, Capability::Firewall),
                    },
                    PlanAction::ConfigureRoute {
                        backend: selected_backend(&self.backends, Capability::PolicyRouting),
                        table: self.config.tun.routing_table,
                    },
                    PlanAction::StartService {
                        name: "xray-tun-policy.service".into(),
                    },
                    PlanAction::RestartService {
                        name: "xray.service".into(),
                    },
                ],
            }),
            Operation::TunDisable | Operation::TunCleanup => Ok(ExecutionPlan {
                operation: operation.name().into(),
                backend_ids,
                actions: vec![PlanAction::StopService {
                    name: "xray-tun-policy.service".into(),
                }],
            }),
            Operation::DesktopProxyEnable { user } => Ok(ExecutionPlan {
                operation: operation.name().into(),
                backend_ids,
                actions: vec![PlanAction::ConfigureDesktopProxy {
                    backend: selected_backend(&self.backends, Capability::DesktopProxy),
                    user: user.clone(),
                    enabled: true,
                }],
            }),
            Operation::DesktopProxyDisable { user } => Ok(ExecutionPlan {
                operation: operation.name().into(),
                backend_ids,
                actions: vec![PlanAction::ConfigureDesktopProxy {
                    backend: selected_backend(&self.backends, Capability::DesktopProxy),
                    user: user.clone(),
                    enabled: false,
                }],
            }),
            Operation::AppRun { profile, command } => Ok(ExecutionPlan {
                operation: operation.name().into(),
                backend_ids,
                actions: vec![PlanAction::LaunchApplication {
                    executable: command
                        .first()
                        .cloned()
                        .or_else(|| profile.clone())
                        .unwrap_or_else(|| "<profile>".into()),
                    routed: true,
                }],
            }),
            Operation::AppTest { profile } => {
                validate_resource_name(profile)?;
                Ok(ExecutionPlan {
                    operation: operation.name().into(),
                    backend_ids,
                    actions: vec![PlanAction::LaunchApplication {
                        executable: format!("<route-ip-check:{profile}>"),
                        routed: true,
                    }],
                })
            }
            Operation::SubscriptionAdd { name, .. }
            | Operation::SubscriptionEnable { name, .. } => Ok(ExecutionPlan {
                operation: operation.name().into(),
                backend_ids,
                actions: vec![PlanAction::WriteFile {
                    path: self.subscription_path(name).await?,
                    mode: 0o600,
                    description: "subscription configuration (URL redacted)".into(),
                }],
            }),
            Operation::SubscriptionRemove { name } => Ok(ExecutionPlan {
                operation: operation.name().into(),
                backend_ids,
                actions: vec![PlanAction::RemoveOwnedPath {
                    path: self.subscription_path(name).await?,
                }],
            }),
            Operation::AppProfileRemove { name } => Ok(ExecutionPlan {
                operation: {
                    validate_resource_name(name)?;
                    operation.name().into()
                },
                backend_ids,
                actions: vec![PlanAction::RemoveOwnedPath {
                    path: self
                        .paths()
                        .await?
                        .config_dir
                        .join("apps.d")
                        .join(format!("{name}.toml")),
                }],
            }),
            Operation::AppProfilePut { profile } => {
                profile.validate()?;
                Ok(ExecutionPlan {
                    operation: operation.name().into(),
                    backend_ids,
                    actions: vec![PlanAction::WriteFile {
                        path: self
                            .paths()
                            .await?
                            .config_dir
                            .join("apps.d")
                            .join(format!("{}.toml", profile.name)),
                        mode: 0o640,
                        description: "selective application profile".into(),
                    }],
                })
            }
            Operation::SubscriptionRefresh { .. } => Ok(ExecutionPlan {
                operation: operation.name().into(),
                backend_ids,
                actions: vec![
                    PlanAction::DownloadArtifact {
                        id: "subscriptions".into(),
                        destination: self.paths().await?.state_dir.join("nodes.json"),
                    },
                    PlanAction::ApplyConfiguration {
                        description: "reconcile the selected node without exposing credentials"
                            .into(),
                    },
                ],
            }),
            Operation::Apply
            | Operation::NodeSelect { .. }
            | Operation::RoutingApply
            | Operation::RoutingPreset { .. }
            | Operation::RoutingSet { .. } => Ok(ExecutionPlan {
                operation: operation.name().into(),
                backend_ids,
                actions: vec![
                    PlanAction::ApplyConfiguration {
                        description: "render and validate an Xray configuration generation".into(),
                    },
                    PlanAction::RestartService {
                        name: "xray.service".into(),
                    },
                ],
            }),
            Operation::ConfigRollback | Operation::CoreRollback | Operation::AssetRollback => {
                Ok(ExecutionPlan {
                    operation: operation.name().into(),
                    backend_ids,
                    actions: vec![PlanAction::RestartService {
                        name: "xray.service".into(),
                    }],
                })
            }
        }
    }

    fn ensure_capability(&self, capability: Capability) -> Result<()> {
        let status = self
            .backends
            .capabilities
            .iter()
            .find(|status| status.capability == capability);
        if status.is_some_and(|status| status.supported) {
            return Ok(());
        }
        let reason = status
            .and_then(|status| status.reason.as_deref())
            .unwrap_or("no compiled backend");
        Err(ManagerError::PlatformUnsupported {
            capability,
            platform: std::env::consts::OS.into(),
            backend: status.and_then(|status| status.backend_id.clone()),
            reason: reason.into(),
            recommendation: Some(format!(
                "Choose an available compiled backend with --backend {capability}=<id>"
            )),
        })
    }

    fn bootstrap_can_restore(&self, operation: &Operation, capability: Capability) -> bool {
        if !matches!(operation, Operation::Install { .. } | Operation::Repair)
            || capability == Capability::Install
            || capability == Capability::PackageAdvice
        {
            return false;
        }
        let status = self
            .backends
            .capabilities
            .iter()
            .find(|status| status.capability == capability);
        let selection = self
            .backends
            .selections
            .iter()
            .find(|selection| selection.capability == capability);
        status.is_some_and(|status| {
            !status.supported
                && status.backend_id.is_some()
                && status
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.starts_with("missing:"))
        }) && selection.is_some_and(|selection| {
            matches!(
                selection.source,
                crate::ports::SelectionSource::Automatic
                    | crate::ports::SelectionSource::InstalledState
            )
        })
    }

    async fn add_platform_requirements(&self, plan: &mut ExecutionPlan) -> Result<()> {
        let mut missing = match self.backends.package_advisor.missing_requirements().await {
            Ok(missing) => missing,
            Err(ManagerError::PlatformUnsupported { .. }) => return Ok(()),
            Err(error) => return Err(error),
        };
        // App namespace tooling is an optional capability and must not block a
        // proxy-only installation. Likewise, disabled TUN support must not
        // force the firewall and policy-routing packages onto the host.
        missing.retain(|requirement| {
            !matches!(requirement.as_str(), "mount" | "unshare")
                && (self.config.tun.enabled || !matches!(requirement.as_str(), "ip" | "nft"))
        });
        let packages = self.backends.package_advisor.packages_for(&missing);
        if !packages.is_empty() {
            plan.actions
                .insert(0, PlanAction::RequirePackages { packages });
        }
        Ok(())
    }

    pub async fn execute(
        &self,
        operation: Operation,
        options: OperationOptions,
    ) -> Result<OperationResultDto> {
        let name = operation.name().to_owned();
        self.backends.events.emit(ManagerEvent::OperationStarted {
            operation: name.clone(),
        });
        match self.execute_inner(operation, options).await {
            Ok(result) => {
                self.backends
                    .events
                    .emit(ManagerEvent::OperationFinished { operation: name });
                Ok(result)
            }
            Err(error) => {
                self.backends.events.emit(ManagerEvent::OperationFailed {
                    operation: name,
                    code: error.code().into(),
                });
                Err(error)
            }
        }
    }

    async fn execute_inner(
        &self,
        operation: Operation,
        options: OperationOptions,
    ) -> Result<OperationResultDto> {
        let name = operation.name().to_owned();
        let is_diagnostic = matches!(operation, Operation::AppTest { .. });
        if matches!(operation, Operation::UpgradeManager)
            && self.config.core.manager_repository.is_none()
        {
            return Err(ManagerError::ManagerReleaseSourceNotConfigured);
        }
        if matches!(operation, Operation::Purge) && !options.dry_run && !options.assume_yes {
            return Err(ManagerError::InvalidConfig(
                "purge requires explicit confirmation".into(),
            ));
        }
        let plan = self.plan_internal(&operation, !options.dry_run).await?;
        if !options.dry_run
            && operation_requires_administrator(&operation)
            && !self.backends.privilege.is_elevated().await?
        {
            return Err(ManagerError::PrivilegeRequired);
        }
        if !options.dry_run
            && let Some(packages) = plan.actions.iter().find_map(|action| match action {
                PlanAction::RequirePackages { packages } => Some(packages),
                _ => None,
            })
        {
            let hint = self
                .backends
                .package_advisor
                .install_hint(packages)
                .unwrap_or_else(|| format!("install packages: {}", packages.join(", ")));
            return Err(ManagerError::PlatformUnsupported {
                capability: Capability::Install,
                platform: std::env::consts::OS.into(),
                backend: self
                    .backends
                    .selections
                    .iter()
                    .find(|selection| selection.capability == Capability::Install)
                    .map(|selection| selection.backend_id.clone()),
                reason: "required packages are missing".into(),
                recommendation: Some(format!(
                    "Install them explicitly, then repeat the command: {hint}"
                )),
            });
        }
        let _operation_guard = if !options.dry_run
            && !matches!(
                operation,
                Operation::AppRun { .. } | Operation::AppTest { .. }
            ) {
            Some(
                self.backends
                    .filesystem
                    .acquire_lock(&self.paths().await?.runtime_dir.join("manager.lock"))
                    .await?,
            )
        } else {
            None
        };
        let mut warnings = Vec::new();
        let mut data = None;
        let is_install = matches!(&operation, Operation::Install { .. });
        if !options.dry_run {
            match operation {
                Operation::Install { .. }
                | Operation::Repair
                | Operation::Uninstall
                | Operation::Purge
                | Operation::UpgradeAll
                | Operation::UpgradeCore
                | Operation::UpgradeAssets
                | Operation::UpgradeManager => {
                    self.backends.installer.apply(&plan).await?;
                    self.reload_state().await?;
                }
                Operation::ServiceStart => self.backends.service.start("xray.service").await?,
                Operation::ServiceStop => self.backends.service.stop("xray.service").await?,
                Operation::ServiceRestart => {
                    self.backends.service.restart("xray.service").await?;
                }
                Operation::SubscriptionAdd { name, url } => {
                    let subscription = SubscriptionConfig {
                        name,
                        enabled: true,
                        url,
                        format: "auto".into(),
                    };
                    self.write_subscription(&subscription).await?;
                }
                Operation::SubscriptionRemove { name } => {
                    let selected_id = self.state.read().await.selected_node_id.clone();
                    if let Some(selected_id) = selected_id
                        && self.load_nodes().await?.iter().any(|node| {
                            node.id.as_str() == selected_id && node.subscription == name
                        })
                    {
                        return Err(ManagerError::InvalidConfig(
                            "cannot remove a subscription containing the selected node; select another node first".into(),
                        ));
                    }
                    let path = self.subscription_path(&name).await?;
                    let root = path.parent().ok_or_else(|| {
                        ManagerError::Io("subscription path has no parent".into())
                    })?;
                    self.backends.filesystem.remove_owned(&path, root).await?;
                    let mut nodes = self.load_nodes().await?;
                    nodes.retain(|node| node.subscription != name);
                    self.write_nodes(&nodes).await?;
                }
                Operation::SubscriptionEnable { name, enabled } => {
                    let path = self.subscription_path(&name).await?;
                    let bytes = self.backends.filesystem.read(&path).await?;
                    let text = std::str::from_utf8(&bytes)
                        .map_err(|error| ManagerError::InvalidConfig(error.to_string()))?;
                    let mut subscription: SubscriptionConfig = toml::from_str(text)
                        .map_err(|error| ManagerError::InvalidConfig(error.to_string()))?;
                    subscription.enabled = enabled;
                    self.write_subscription(&subscription).await?;
                }
                Operation::SubscriptionRefresh { ref name } => {
                    warnings = self.refresh_subscriptions(name.as_deref()).await?;
                }
                Operation::NodeSelect { ref id } => {
                    let nodes = self.load_nodes().await?;
                    let matches = nodes
                        .iter()
                        .filter(|node| node.id.as_str().starts_with(id))
                        .collect::<Vec<_>>();
                    let selected = match matches.as_slice() {
                        [selected] => *selected,
                        [] => {
                            return Err(ManagerError::InvalidNode(format!(
                                "node '{id}' was not found"
                            )));
                        }
                        _ => {
                            return Err(ManagerError::InvalidNode(format!(
                                "node ID prefix '{id}' is ambiguous"
                            )));
                        }
                    };
                    if selected.protocol == crate::domain::Protocol::Hysteria2
                        && !selected.warnings.is_empty()
                    {
                        return Err(ManagerError::Validation(format!(
                            "Hysteria2 node has unconfirmed parameters: {}",
                            selected.warnings.join(", ")
                        )));
                    }
                    self.apply_config(Some(selected)).await?;
                }
                Operation::Apply | Operation::RoutingApply => {
                    let selected_id = self.state.read().await.selected_node_id.clone();
                    let selected = self.selected_node(selected_id.as_deref()).await?;
                    self.apply_config(selected.as_ref()).await?;
                }
                Operation::RoutingPreset { ref name } => {
                    let preset = RoutingConfig::preset(name)?;
                    self.write_routing_and_apply(&preset).await?;
                }
                Operation::RoutingSet { ref routing } => {
                    self.write_routing_and_apply(routing).await?;
                }
                Operation::ConfigRollback => {
                    let paths = self.paths().await?;
                    let current = paths.state_dir.join("current");
                    let previous = paths.state_dir.join("previous");
                    let old_state = self.state.read().await.clone();
                    self.backends
                        .filesystem
                        .rollback_generation(&current, &previous)
                        .await?;
                    let mut state = old_state.clone();
                    std::mem::swap(
                        &mut state.current_config_generation,
                        &mut state.previous_config_generation,
                    );
                    self.commit_generation_rollback(
                        &current,
                        &previous,
                        &old_state,
                        state,
                        "configuration",
                    )
                    .await?;
                }
                Operation::CoreRollback => {
                    let paths = self.paths().await?;
                    let current = paths.install_dir.join("core/current");
                    let previous = paths.install_dir.join("core/previous");
                    let old_state = self.state.read().await.clone();
                    self.backends
                        .filesystem
                        .rollback_generation(&current, &previous)
                        .await?;
                    let mut state = old_state.clone();
                    std::mem::swap(
                        &mut state.current_core_version,
                        &mut state.previous_core_version,
                    );
                    self.commit_generation_rollback(&current, &previous, &old_state, state, "core")
                        .await?;
                }
                Operation::AssetRollback => {
                    let paths = self.paths().await?;
                    let current = paths.install_dir.join("assets/current");
                    let previous = paths.install_dir.join("assets/previous");
                    let old_state = self.state.read().await.clone();
                    self.backends
                        .filesystem
                        .rollback_generation(&current, &previous)
                        .await?;
                    let mut state = old_state.clone();
                    std::mem::swap(
                        &mut state.current_asset_generation,
                        &mut state.previous_asset_generation,
                    );
                    self.commit_generation_rollback(
                        &current, &previous, &old_state, state, "assets",
                    )
                    .await?;
                }
                Operation::TunEnable => {
                    self.backends.firewall.enable(&self.config).await?;
                    if let Err(error) = self.backends.policy_routing.enable(&self.config).await {
                        let _ = self.backends.firewall.disable().await;
                        return Err(error);
                    }
                    if let Err(error) = self
                        .backends
                        .service
                        .enable("xray-tun-policy.service")
                        .await
                    {
                        let _ = self.backends.policy_routing.disable(&self.config).await;
                        let _ = self.backends.firewall.disable().await;
                        return Err(error);
                    }
                    if let Err(error) = self.backends.service.start("xray-tun-policy.service").await
                    {
                        let _ = self.backends.policy_routing.disable(&self.config).await;
                        let _ = self.backends.firewall.disable().await;
                        return Err(error);
                    }
                    if let Err(error) = self.backends.service.restart("xray.service").await {
                        let _ = self.backends.service.stop("xray-tun-policy.service").await;
                        let _ = self.backends.policy_routing.disable(&self.config).await;
                        let _ = self.backends.firewall.disable().await;
                        return Err(error);
                    }
                }
                Operation::TunDisable | Operation::TunCleanup => {
                    let _ = self.backends.service.stop("xray-tun-policy.service").await;
                    self.backends.policy_routing.disable(&self.config).await?;
                    self.backends.firewall.disable().await?;
                    self.backends
                        .service
                        .disable("xray-tun-policy.service")
                        .await?;
                }
                Operation::DesktopProxyEnable { ref user } => {
                    self.backends
                        .desktop_proxy
                        .enable(user, &self.config)
                        .await?;
                    warnings.push(
                        "KDE applications may need to be restarted before the proxy change is visible"
                            .into(),
                    );
                }
                Operation::DesktopProxyDisable { ref user } => {
                    self.backends.desktop_proxy.disable(user).await?;
                    warnings.push(
                        "KDE applications may need to be restarted before the proxy change is visible"
                            .into(),
                    );
                }
                Operation::AppRun {
                    ref profile,
                    ref command,
                } => {
                    if !self
                        .backends
                        .service
                        .is_active("xray-tun-policy.service")
                        .await?
                    {
                        return Err(ManagerError::Other(
                            "selective TUN policy is not active; run `sudo xrayctl tun enable`"
                                .into(),
                        ));
                    }
                    if !self
                        .backends
                        .tun
                        .status(&self.config.tun.interface_name)
                        .await?
                    {
                        return Err(ManagerError::Other(format!(
                            "TUN interface {} is not active",
                            self.config.tun.interface_name
                        )));
                    }
                    let profile = if let Some(name) = profile {
                        Some(
                            self.load_app_profiles()
                                .await?
                                .into_iter()
                                .find(|candidate| candidate.name == *name)
                                .ok_or_else(|| {
                                    ManagerError::InvalidConfig(format!(
                                        "app profile '{name}' was not found"
                                    ))
                                })?,
                        )
                    } else {
                        None
                    };
                    let launch_command = if command.is_empty() {
                        profile
                            .as_ref()
                            .map(|profile| profile.command.clone())
                            .unwrap_or_default()
                    } else {
                        command.clone()
                    };
                    if launch_command.is_empty() {
                        return Err(ManagerError::InvalidConfig(
                            "app run requires a profile or command".into(),
                        ));
                    }
                    let exit_code = self
                        .backends
                        .app_runner
                        .run(AppLaunchRequest {
                            command: launch_command,
                            user: String::new(),
                            override_dns: profile
                                .as_ref()
                                .is_some_and(|profile| profile.override_dns),
                            clear_proxy_environment: profile
                                .as_ref()
                                .is_none_or(|profile| profile.clear_proxy_environment),
                            working_directory: profile
                                .as_ref()
                                .and_then(|profile| profile.working_directory.clone()),
                            environment: profile
                                .map(|profile| profile.environment)
                                .unwrap_or_default(),
                        })
                        .await?;
                    if exit_code != 0 {
                        return Err(ManagerError::Other(format!(
                            "application exited with status {exit_code}"
                        )));
                    }
                }
                Operation::AppTest { ref profile } => {
                    if !self
                        .backends
                        .service
                        .is_active("xray-tun-policy.service")
                        .await?
                    {
                        return Err(ManagerError::Other(
                            "selective TUN policy is not active; run `sudo xrayctl tun enable`"
                                .into(),
                        ));
                    }
                    if !self
                        .backends
                        .tun
                        .status(&self.config.tun.interface_name)
                        .await?
                    {
                        return Err(ManagerError::Other(format!(
                            "TUN interface {} is not active",
                            self.config.tun.interface_name
                        )));
                    }
                    validate_resource_name(profile)?;
                    let profile = self
                        .load_app_profiles()
                        .await?
                        .into_iter()
                        .find(|candidate| candidate.name == *profile)
                        .ok_or_else(|| {
                            ManagerError::InvalidConfig(format!(
                                "app profile '{profile}' was not found"
                            ))
                        })?;
                    let result = self
                        .backends
                        .app_runner
                        .test_route(AppRouteTestRequest {
                            user: String::new(),
                            override_dns: profile.override_dns,
                            url: "https://api.ipify.org".into(),
                            timeout: Duration::from_secs(
                                self.config.general.request_timeout_seconds,
                            ),
                        })
                        .await?;
                    data = Some(
                        serde_json::to_value(result)
                            .map_err(|error| ManagerError::Other(error.to_string()))?,
                    );
                }
                Operation::AppProfileRemove { ref name } => {
                    validate_resource_name(name)?;
                    let directory = self.paths().await?.config_dir.join("apps.d");
                    self.backends
                        .filesystem
                        .remove_owned(&directory.join(format!("{name}.toml")), &directory)
                        .await?;
                }
                Operation::AppProfilePut { ref profile } => {
                    self.write_app_profile(profile).await?;
                }
            }
            if is_install && self.state.read().await.selected_node_id.is_none() {
                warnings.push(
                    "Xray is running with a validated safe blackhole outbound; add and refresh a subscription, then select a node"
                        .into(),
                );
            }
        }
        Ok(OperationResultDto {
            operation: name,
            changed: !options.dry_run && !is_diagnostic,
            plan: options.dry_run.then_some(plan),
            data,
            warnings,
        })
    }
}

fn validate_resource_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(ManagerError::InvalidConfig(
            "resource name may contain only ASCII letters, digits, '-' and '_'".into(),
        ));
    }
    Ok(())
}

fn selected_backend(backends: &DynBackendSet, capability: Capability) -> String {
    backends
        .selections
        .iter()
        .find(|selection| selection.capability == capability)
        .map(|selection| selection.backend_id.clone())
        .unwrap_or_else(|| "unavailable".into())
}

fn required_capabilities(operation: &Operation) -> Vec<Capability> {
    match operation {
        Operation::Install { .. } | Operation::Repair => vec![
            Capability::Install,
            Capability::PackageAdvice,
            Capability::Identity,
            Capability::Service,
            Capability::Firewall,
            Capability::PolicyRouting,
            Capability::Tun,
        ],
        Operation::Uninstall | Operation::Purge => Vec::new(),
        Operation::UpgradeAll | Operation::UpgradeCore | Operation::UpgradeAssets => {
            vec![Capability::Install, Capability::Service]
        }
        Operation::UpgradeManager => vec![Capability::Install],
        Operation::Apply
        | Operation::NodeSelect { .. }
        | Operation::RoutingApply
        | Operation::RoutingPreset { .. }
        | Operation::RoutingSet { .. }
        | Operation::ConfigRollback
        | Operation::CoreRollback
        | Operation::AssetRollback => vec![
            Capability::Install,
            Capability::Identity,
            Capability::Service,
        ],
        Operation::ServiceStart | Operation::ServiceStop | Operation::ServiceRestart => {
            vec![Capability::Service]
        }
        Operation::TunEnable | Operation::TunDisable | Operation::TunCleanup => vec![
            Capability::Firewall,
            Capability::PolicyRouting,
            Capability::Service,
            Capability::Tun,
        ],
        Operation::DesktopProxyEnable { .. } | Operation::DesktopProxyDisable { .. } => {
            vec![Capability::DesktopProxy]
        }
        Operation::AppRun { .. } | Operation::AppTest { .. } => {
            vec![Capability::AppRunner, Capability::MountIsolation]
        }
        Operation::SubscriptionRefresh { .. }
        | Operation::SubscriptionAdd { .. }
        | Operation::SubscriptionRemove { .. }
        | Operation::SubscriptionEnable { .. }
        | Operation::AppProfileRemove { .. }
        | Operation::AppProfilePut { .. } => Vec::new(),
    }
}

fn operation_requires_administrator(operation: &Operation) -> bool {
    !matches!(
        operation,
        Operation::SubscriptionRefresh { .. }
            | Operation::SubscriptionAdd { .. }
            | Operation::SubscriptionRemove { .. }
            | Operation::SubscriptionEnable { .. }
            | Operation::AppProfileRemove { .. }
            | Operation::AppProfilePut { .. }
    )
}
