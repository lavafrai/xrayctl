use crate::portable::ProcessCommandRunner;
use async_trait::async_trait;
use xray_manager_core::ports::{CommandRunner, ServiceManager};
use xray_manager_core::{ManagerError, Result};

#[derive(Debug, Clone, Default)]
pub struct SystemdServiceManager {
    runner: ProcessCommandRunner,
}

impl SystemdServiceManager {
    async fn systemctl(&self, args: &[&str]) -> Result<String> {
        let args: Vec<String> = args.iter().map(ToString::to_string).collect();
        let output = self.runner.run("systemctl", &args).await?;
        if output.status == 0 {
            Ok(output.stdout)
        } else {
            Err(ManagerError::Other(output.stderr))
        }
    }
}

#[async_trait]
impl ServiceManager for SystemdServiceManager {
    async fn enable(&self, service: &str) -> Result<()> {
        self.systemctl(&["enable", service]).await.map(drop)
    }
    async fn disable(&self, service: &str) -> Result<()> {
        self.systemctl(&["disable", service]).await.map(drop)
    }
    async fn start(&self, service: &str) -> Result<()> {
        self.systemctl(&["start", service]).await.map(drop)
    }
    async fn stop(&self, service: &str) -> Result<()> {
        self.systemctl(&["stop", service]).await.map(drop)
    }
    async fn restart(&self, service: &str) -> Result<()> {
        self.systemctl(&["restart", service]).await.map(drop)
    }
    async fn is_active(&self, service: &str) -> Result<bool> {
        let args = vec!["is-active".into(), "--quiet".into(), service.into()];
        Ok(self.runner.run("systemctl", &args).await?.status == 0)
    }
    async fn logs(&self, service: &str, lines: usize) -> Result<String> {
        let args = vec![
            "-u".into(),
            service.into(),
            "-n".into(),
            lines.to_string(),
            "--no-pager".into(),
        ];
        let output = self.runner.run("journalctl", &args).await?;
        if output.status == 0 {
            Ok(output.stdout)
        } else {
            Err(ManagerError::Other(output.stderr))
        }
    }
}
