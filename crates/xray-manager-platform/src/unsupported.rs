use async_trait::async_trait;
use std::collections::BTreeMap;
use std::path::Path;
use xray_manager_core::config::ManagerConfig;
use xray_manager_core::domain::Node;
use xray_manager_core::ports::{
    AppLaunchRequest, AppRouteTestRequest, AppRouteTestResult, AppRunner, Capability,
    DesktopProxyManager, ExecutionPlan, FirewallManager, IdentityManager, LayoutProvider,
    ManagerPaths, MountIsolation, PackageAdvisor, PlanAction, PlatformInfo, PlatformInspector,
    PlatformInstaller, PolicyRoutingManager, PrivilegeChecker, ProbeResult, ServiceManager,
    TunManager, UpgradeTarget, XrayRunner, XrayTestRequest,
};
use xray_manager_core::{ManagerError, Result};

#[derive(Debug, Clone)]
pub struct UnsupportedPlatform {
    pub platform: String,
}

impl UnsupportedPlatform {
    fn error(&self, capability: Capability) -> ManagerError {
        ManagerError::PlatformUnsupported {
            capability,
            platform: self.platform.clone(),
            backend: None,
            reason: "no runtime backend is implemented for this platform".into(),
            recommendation: Some("select a backend implemented for this platform".into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LinuxPlanOnlyInstaller {
    pub platform: String,
}

impl LinuxPlanOnlyInstaller {
    fn unsupported(&self) -> ManagerError {
        ManagerError::PlatformUnsupported {
            capability: Capability::Install,
            platform: self.platform.clone(),
            backend: Some("linux-plan-only".into()),
            reason: "this backend can preview a Linux plan but cannot mutate this platform".into(),
            recommendation: Some("run the mutation on a supported Linux host".into()),
        }
    }
}

#[async_trait]
impl PlatformInstaller for LinuxPlanOnlyInstaller {
    async fn plan_install(&self, config: &ManagerConfig) -> Result<ExecutionPlan> {
        Ok(ExecutionPlan {
            operation: "install".into(),
            backend_ids: [
                (Capability::Install, "arch".into()),
                (Capability::Service, "systemd".into()),
                (Capability::Firewall, "nftables".into()),
                (Capability::PolicyRouting, "iproute2".into()),
                (Capability::Tun, "xray-linux-tun".into()),
            ]
            .into_iter()
            .collect(),
            actions: vec![
                PlanAction::EnsureIdentity {
                    name: "xray".into(),
                    system: true,
                },
                PlanAction::EnsureGroup {
                    name: "xray-manager".into(),
                },
                PlanAction::EnsureGroup {
                    name: "xray-tun".into(),
                },
                PlanAction::EnsureDirectory {
                    path: "/etc/xray-manager".into(),
                    mode: 0o2750,
                },
                PlanAction::WriteFile {
                    path: "/etc/systemd/system/xray.service".into(),
                    mode: 0o644,
                    description: "xray.service".into(),
                },
                PlanAction::DownloadArtifact {
                    id: "xray-core".into(),
                    destination: "/opt/xray-manager/core/versions".into(),
                },
                PlanAction::DownloadArtifact {
                    id: "assets".into(),
                    destination: "/opt/xray-manager/assets/generations".into(),
                },
                PlanAction::RunHealthcheck {
                    url: config.general.healthcheck_url.clone(),
                },
            ],
        })
    }

    async fn apply(&self, _plan: &ExecutionPlan) -> Result<()> {
        Err(self.unsupported())
    }

    async fn plan_repair(&self, config: &ManagerConfig) -> Result<ExecutionPlan> {
        let mut plan = self.plan_install(config).await?;
        plan.operation = "repair".into();
        Ok(plan)
    }

    async fn plan_uninstall(&self, purge: bool) -> Result<ExecutionPlan> {
        let mut actions = vec![
            PlanAction::StopService {
                name: "xray.service".into(),
            },
            PlanAction::RemoveService {
                name: "xray.service".into(),
            },
            PlanAction::RemoveOwnedPath {
                path: "/usr/local/bin/xrayctl".into(),
            },
        ];
        if purge {
            actions.extend(
                [
                    "/etc/xray-manager",
                    "/var/lib/xray-manager",
                    "/var/cache/xray-manager",
                    "/opt/xray-manager",
                ]
                .into_iter()
                .map(|path| PlanAction::RemoveOwnedPath { path: path.into() }),
            );
        }
        Ok(ExecutionPlan {
            operation: if purge { "purge" } else { "uninstall" }.into(),
            backend_ids: BTreeMap::from([(Capability::Install, "arch".into())]),
            actions,
        })
    }

    async fn plan_upgrade(
        &self,
        _config: &ManagerConfig,
        target: UpgradeTarget,
    ) -> Result<ExecutionPlan> {
        let (operation, id, destination) = match target {
            UpgradeTarget::All => ("upgrade_all", "xray-core-and-assets", "/opt/xray-manager"),
            UpgradeTarget::Core => (
                "upgrade_core",
                "xray-core",
                "/opt/xray-manager/core/versions",
            ),
            UpgradeTarget::Assets => (
                "upgrade_assets",
                "assets",
                "/opt/xray-manager/assets/generations",
            ),
            UpgradeTarget::Manager => ("upgrade_manager", "xray-manager", "/usr/local/bin/xrayctl"),
        };
        Ok(ExecutionPlan {
            operation: operation.into(),
            backend_ids: BTreeMap::from([(Capability::Install, "arch".into())]),
            actions: vec![PlanAction::DownloadArtifact {
                id: id.into(),
                destination: destination.into(),
            }],
        })
    }
}

#[async_trait]
impl LayoutProvider for UnsupportedPlatform {
    async fn paths(&self) -> Result<ManagerPaths> {
        let root = std::env::current_dir()
            .map_err(|error| ManagerError::Io(error.to_string()))?
            .join(".xray-manager");
        Ok(ManagerPaths {
            config_dir: root.join("config"),
            state_dir: root.join("state"),
            cache_dir: root.join("cache"),
            runtime_dir: root.join("run"),
            install_dir: root.join("opt"),
            executable: root.join("bin/xrayctl"),
        })
    }
}

#[async_trait]
impl PlatformInstaller for UnsupportedPlatform {
    async fn plan_install(&self, _config: &ManagerConfig) -> Result<ExecutionPlan> {
        Err(self.error(Capability::Install))
    }
    async fn apply(&self, _plan: &ExecutionPlan) -> Result<()> {
        Err(self.error(Capability::Install))
    }
    async fn plan_repair(&self, _config: &ManagerConfig) -> Result<ExecutionPlan> {
        Err(self.error(Capability::Install))
    }
    async fn plan_uninstall(&self, _purge: bool) -> Result<ExecutionPlan> {
        Err(self.error(Capability::Install))
    }
    async fn plan_upgrade(
        &self,
        _config: &ManagerConfig,
        _target: UpgradeTarget,
    ) -> Result<ExecutionPlan> {
        Err(self.error(Capability::Install))
    }
}

#[async_trait]
impl ServiceManager for UnsupportedPlatform {
    async fn enable(&self, _service: &str) -> Result<()> {
        Err(self.error(Capability::Service))
    }
    async fn disable(&self, _service: &str) -> Result<()> {
        Err(self.error(Capability::Service))
    }
    async fn start(&self, _service: &str) -> Result<()> {
        Err(self.error(Capability::Service))
    }
    async fn stop(&self, _service: &str) -> Result<()> {
        Err(self.error(Capability::Service))
    }
    async fn restart(&self, _service: &str) -> Result<()> {
        Err(self.error(Capability::Service))
    }
    async fn is_active(&self, _service: &str) -> Result<bool> {
        Err(self.error(Capability::Service))
    }
    async fn logs(&self, _service: &str, _lines: usize) -> Result<String> {
        Err(self.error(Capability::Service))
    }
}

#[async_trait]
impl PackageAdvisor for UnsupportedPlatform {
    async fn missing_requirements(&self) -> Result<Vec<String>> {
        Err(self.error(Capability::PackageAdvice))
    }

    fn packages_for(&self, _requirements: &[String]) -> Vec<String> {
        Vec::new()
    }

    fn install_hint(&self, _packages: &[String]) -> Option<String> {
        None
    }
}

#[async_trait]
impl IdentityManager for UnsupportedPlatform {
    async fn ensure_system_identity(&self, _user: &str, _groups: &[String]) -> Result<()> {
        Err(self.error(Capability::Identity))
    }

    async fn set_ownership(
        &self,
        _path: &Path,
        _user: &str,
        _group: &str,
        _recursive: bool,
    ) -> Result<()> {
        Err(self.error(Capability::Identity))
    }
}

#[async_trait]
impl FirewallManager for UnsupportedPlatform {
    async fn enable(&self, _config: &ManagerConfig) -> Result<()> {
        Err(self.error(Capability::Firewall))
    }

    async fn disable(&self) -> Result<()> {
        Err(self.error(Capability::Firewall))
    }

    async fn show(&self) -> Result<String> {
        Err(self.error(Capability::Firewall))
    }
}

#[async_trait]
impl PolicyRoutingManager for UnsupportedPlatform {
    async fn enable(&self, _config: &ManagerConfig) -> Result<()> {
        Err(self.error(Capability::PolicyRouting))
    }

    async fn attach_tun(&self, _config: &ManagerConfig) -> Result<()> {
        Err(self.error(Capability::PolicyRouting))
    }

    async fn detach_tun(&self, _config: &ManagerConfig) -> Result<()> {
        Err(self.error(Capability::PolicyRouting))
    }

    async fn disable(&self, _config: &ManagerConfig) -> Result<()> {
        Err(self.error(Capability::PolicyRouting))
    }

    async fn show(&self, _config: &ManagerConfig) -> Result<String> {
        Err(self.error(Capability::PolicyRouting))
    }
}

#[async_trait]
impl TunManager for UnsupportedPlatform {
    async fn status(&self, _interface: &str) -> Result<bool> {
        Err(self.error(Capability::Tun))
    }
}

#[async_trait]
impl AppRunner for UnsupportedPlatform {
    async fn run(&self, _request: AppLaunchRequest) -> Result<i32> {
        Err(self.error(Capability::AppRunner))
    }

    async fn test_route(&self, _request: AppRouteTestRequest) -> Result<AppRouteTestResult> {
        Err(self.error(Capability::AppRunner))
    }
}

#[async_trait]
impl MountIsolation for UnsupportedPlatform {
    async fn supported(&self) -> Result<bool> {
        Err(self.error(Capability::MountIsolation))
    }
}

#[async_trait]
impl DesktopProxyManager for UnsupportedPlatform {
    async fn enable(&self, _user: &str, _config: &ManagerConfig) -> Result<()> {
        Err(self.error(Capability::DesktopProxy))
    }

    async fn disable(&self, _user: &str) -> Result<()> {
        Err(self.error(Capability::DesktopProxy))
    }
}

#[async_trait]
impl PrivilegeChecker for UnsupportedPlatform {
    async fn is_elevated(&self) -> Result<bool> {
        Ok(false)
    }
}

#[async_trait]
impl PlatformInspector for UnsupportedPlatform {
    async fn inspect(&self) -> Result<PlatformInfo> {
        Ok(PlatformInfo {
            os: self.platform.clone(),
            distribution: None,
            init_system: None,
            desktop: None,
        })
    }
}

#[async_trait]
impl XrayRunner for UnsupportedPlatform {
    async fn version(&self, _executable: &Path) -> Result<String> {
        Err(self.error(Capability::Install))
    }
    async fn test_config(&self, _request: &XrayTestRequest) -> Result<()> {
        Err(self.error(Capability::Install))
    }
    async fn probe(&self, _node: &Node, _config: &ManagerConfig) -> Result<ProbeResult> {
        Err(self.error(Capability::Install))
    }

    async fn healthcheck(&self, _config: &ManagerConfig) -> Result<()> {
        Err(self.error(Capability::Install))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unsupported_mutations_never_report_success() {
        let backend = UnsupportedPlatform {
            platform: "test-os".into(),
        };
        assert!(matches!(
            backend.plan_install(&ManagerConfig::default()).await,
            Err(ManagerError::PlatformUnsupported {
                capability: Capability::Install,
                ..
            })
        ));
        assert!(matches!(
            backend.start("xray.service").await,
            Err(ManagerError::PlatformUnsupported {
                capability: Capability::Service,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn plan_only_installer_previews_but_never_applies() {
        let backend = LinuxPlanOnlyInstaller {
            platform: "windows".into(),
        };
        let plan = backend
            .plan_install(&ManagerConfig::default())
            .await
            .expect("Linux preview");
        assert!(!plan.actions.is_empty());
        assert!(matches!(
            backend.apply(&plan).await,
            Err(ManagerError::PlatformUnsupported { .. })
        ));
    }
}
