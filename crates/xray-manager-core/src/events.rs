use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ManagerEvent {
    OperationStarted {
        operation: String,
    },
    DownloadProgress {
        id: String,
        downloaded: u64,
        total: Option<u64>,
    },
    NodeProbeStarted {
        node_id: String,
    },
    NodeProbeSucceeded {
        node_id: String,
        latency_ms: u64,
    },
    NodeProbeFailed {
        node_id: String,
        error: String,
    },
    NodeProbeCancelled {
        node_id: String,
    },
    ConfigValidationStarted,
    ConfigValidationSucceeded,
    ConfigValidationFailed {
        code: String,
    },
    ServiceRestartStarted,
    ServiceRestartSucceeded,
    RollbackStarted {
        reason: String,
    },
    RollbackSucceeded,
    OperationFinished {
        operation: String,
    },
    OperationFailed {
        operation: String,
        code: String,
    },
}
