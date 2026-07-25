use crate::config::ManagerConfig;
use crate::domain::Node;
use crate::events::ManagerEvent;
use crate::ports::{EventSink, ProbeResult, XrayRunner};
use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Semaphore;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinSet;

#[derive(Debug, Serialize)]
pub struct NodeProbeOutcome {
    pub node_id: String,
    pub result: ProbeResult,
}

pub async fn probe_all(
    nodes: Vec<Node>,
    config: ManagerConfig,
    runner: Arc<dyn XrayRunner>,
    events: Arc<dyn EventSink>,
    cancelled: Arc<AtomicBool>,
) -> Vec<NodeProbeOutcome> {
    probe_all_streaming(nodes, config, runner, events, cancelled, None).await
}

pub async fn probe_all_streaming(
    nodes: Vec<Node>,
    config: ManagerConfig,
    runner: Arc<dyn XrayRunner>,
    events: Arc<dyn EventSink>,
    cancelled: Arc<AtomicBool>,
    sender: Option<UnboundedSender<NodeProbeOutcome>>,
) -> Vec<NodeProbeOutcome> {
    let semaphore = Arc::new(Semaphore::new(config.menu.probe_concurrency.max(1)));
    let mut tasks = JoinSet::new();
    for node in nodes {
        let semaphore = semaphore.clone();
        let runner = runner.clone();
        let events = events.clone();
        let cancelled = cancelled.clone();
        let config = config.clone();
        tasks.spawn(async move {
            let id = node.id.as_str().to_owned();
            let permit = semaphore.acquire_owned().await;
            if permit.is_err() || cancelled.load(Ordering::Relaxed) {
                events.emit(ManagerEvent::NodeProbeCancelled {
                    node_id: id.clone(),
                });
                return NodeProbeOutcome {
                    node_id: id,
                    result: ProbeResult {
                        latency_ms: None,
                        error: Some("cancelled".into()),
                    },
                };
            }
            let _permit = permit.ok();
            events.emit(ManagerEvent::NodeProbeStarted {
                node_id: id.clone(),
            });
            match runner.probe(&node, &config).await {
                Ok(result) => {
                    if let Some(latency_ms) = result.latency_ms {
                        events.emit(ManagerEvent::NodeProbeSucceeded {
                            node_id: id.clone(),
                            latency_ms,
                        });
                    } else {
                        events.emit(ManagerEvent::NodeProbeFailed {
                            node_id: id.clone(),
                            error: result
                                .error
                                .clone()
                                .unwrap_or_else(|| "probe failed".into()),
                        });
                    }
                    NodeProbeOutcome {
                        node_id: id,
                        result,
                    }
                }
                Err(error) => {
                    let message = error.to_string();
                    events.emit(ManagerEvent::NodeProbeFailed {
                        node_id: id.clone(),
                        error: message.clone(),
                    });
                    NodeProbeOutcome {
                        node_id: id,
                        result: ProbeResult {
                            latency_ms: None,
                            error: Some(message),
                        },
                    }
                }
            }
        });
    }
    let mut outcomes = Vec::new();
    while let Some(result) = tasks.join_next().await {
        if let Ok(outcome) = result {
            if let Some(sender) = &sender {
                let _ = sender.send(NodeProbeOutcome {
                    node_id: outcome.node_id.clone(),
                    result: outcome.result.clone(),
                });
            }
            outcomes.push(outcome);
        }
    }
    outcomes
}
