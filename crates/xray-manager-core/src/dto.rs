use crate::domain::{Node, Protocol};
use crate::ports::{BackendSelection, CapabilityStatus};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct NodeDto {
    pub id: String,
    pub subscription: String,
    pub name: String,
    pub protocol: Protocol,
    pub endpoint: String,
    pub support: &'static str,
    pub warnings: Vec<String>,
}

impl From<&Node> for NodeDto {
    fn from(node: &Node) -> Self {
        Self {
            id: node.id.short().into(),
            subscription: node.subscription.clone(),
            name: node.name.clone(),
            protocol: node.protocol,
            endpoint: format!("{}:{}", node.server, node.port),
            support: if node.protocol == Protocol::Hysteria2 && !node.warnings.is_empty() {
                "unsupported"
            } else if node.warnings.is_empty() {
                "supported"
            } else {
                "partial"
            },
            warnings: node.warnings.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusDto {
    pub installed: bool,
    pub selected_node: Option<String>,
    pub core_version: Option<String>,
    pub asset_generation: Option<String>,
    pub backends: Vec<BackendSelection>,
    pub capabilities: Vec<CapabilityStatus>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorCheckDto {
    pub id: String,
    pub status: CheckStatus,
    pub message: String,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize)]
pub struct OperationResultDto {
    pub operation: String,
    pub changed: bool,
    pub plan: Option<crate::ports::ExecutionPlan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct JsonEnvelope<T: Serialize> {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}
