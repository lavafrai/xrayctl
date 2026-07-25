use async_trait::async_trait;
use xray_manager_core::Result;
use xray_manager_core::ports::{LayoutProvider, ManagerPaths};

#[derive(Debug, Clone, Default)]
pub struct LinuxFhsLayout;

#[async_trait]
impl LayoutProvider for LinuxFhsLayout {
    async fn paths(&self) -> Result<ManagerPaths> {
        Ok(ManagerPaths {
            config_dir: "/etc/xray-manager".into(),
            state_dir: "/var/lib/xray-manager".into(),
            cache_dir: "/var/cache/xray-manager".into(),
            runtime_dir: "/run/xray-manager".into(),
            install_dir: "/opt/xray-manager".into(),
            executable: "/usr/local/bin/xrayctl".into(),
        })
    }
}
