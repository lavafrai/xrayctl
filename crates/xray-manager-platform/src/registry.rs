use async_trait::async_trait;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use xray_manager_core::config::ManagerConfig;
use xray_manager_core::ports::{
    BackendComponent, BackendDescriptor, BackendPreferences, BackendProbe, BackendSelection,
    Capability, CapabilityStatus, SelectionSource,
};
use xray_manager_core::{ManagerError, Result};

#[async_trait]
pub trait BackendFactory: Send + Sync {
    fn descriptor(&self) -> BackendDescriptor;
    async fn probe(&self) -> Result<BackendProbe>;
    fn create(
        &self,
        capability: Capability,
        config: &ManagerConfig,
        selections: &[BackendSelection],
    ) -> Result<BackendComponent> {
        let _ = (capability, config, selections);
        Err(ManagerError::Other(format!(
            "backend '{}' has no adapter factory",
            self.descriptor().id
        )))
    }
}

#[derive(Default)]
pub struct BackendRegistry {
    factories: Vec<Arc<dyn BackendFactory>>,
}

impl BackendRegistry {
    pub fn register<F>(&mut self, factory: F)
    where
        F: BackendFactory + 'static,
    {
        self.factories.push(Arc::new(factory));
    }

    pub fn descriptors(&self) -> Vec<BackendDescriptor> {
        self.factories
            .iter()
            .map(|factory| factory.descriptor())
            .collect()
    }

    pub async fn resolve(
        &self,
        preferences: &BackendPreferences,
        required: &BTreeSet<Capability>,
    ) -> Result<(Vec<BackendSelection>, Vec<CapabilityStatus>)> {
        let mut available = BTreeMap::<String, (BackendDescriptor, BackendProbe)>::new();
        for factory in &self.factories {
            let descriptor = factory.descriptor();
            let mut probe = factory.probe().await?;
            if descriptor.contract_version != 1 {
                probe.available = false;
                probe.reason = Some(format!(
                    "backend contract {} is incompatible with required contract 1",
                    descriptor.contract_version
                ));
            }
            if available
                .insert(descriptor.id.clone(), (descriptor.clone(), probe))
                .is_some()
            {
                return Err(ManagerError::Other(format!(
                    "duplicate backend ID '{}'",
                    descriptor.id
                )));
            }
        }
        let mut selections = Vec::new();
        let mut statuses = Vec::new();
        for capability in required {
            let explicit = [
                (SelectionSource::Cli, preferences.cli.get(capability)),
                (SelectionSource::Config, preferences.config.get(capability)),
                (
                    SelectionSource::InstalledState,
                    preferences.installed.get(capability),
                ),
            ]
            .into_iter()
            .find_map(|(source, id)| id.filter(|id| id.as_str() != "auto").map(|id| (source, id)));

            let selected = if let Some((source, id)) = explicit {
                let (descriptor, probe) =
                    available
                        .get(id)
                        .ok_or_else(|| ManagerError::PlatformUnsupported {
                            capability: *capability,
                            platform: std::env::consts::OS.into(),
                            backend: Some((*id).clone()),
                            reason: format!("requested backend '{id}' is not compiled in"),
                            recommendation: Some(format!(
                                "choose a backend listed by doctor for {capability}"
                            )),
                        })?;
                if !descriptor.capabilities.contains(capability) {
                    return Err(ManagerError::PlatformUnsupported {
                        capability: *capability,
                        platform: descriptor.platform.clone(),
                        backend: Some(descriptor.id.clone()),
                        reason: probe.reason.clone().unwrap_or_else(|| {
                            format!("backend '{}' is unavailable", descriptor.id)
                        }),
                        recommendation: Some(format!(
                            "choose a backend that provides {capability}"
                        )),
                    });
                }
                if !probe.available && source != SelectionSource::InstalledState {
                    return Err(ManagerError::PlatformUnsupported {
                        capability: *capability,
                        platform: descriptor.platform.clone(),
                        backend: Some(descriptor.id.clone()),
                        reason: probe.reason.clone().unwrap_or_else(|| {
                            format!("backend '{}' is unavailable", descriptor.id)
                        }),
                        recommendation: Some(
                            "satisfy the backend requirements or choose another backend".into(),
                        ),
                    });
                }
                Some((source, descriptor, probe))
            } else {
                let detected = available
                    .values()
                    .filter(|(descriptor, probe)| {
                        probe.available && descriptor.capabilities.contains(capability)
                    })
                    .min_by(|(left, _), (right, _)| left.id.cmp(&right.id))
                    .map(|(descriptor, probe)| (SelectionSource::Automatic, descriptor, probe));
                detected.or_else(|| {
                    available
                        .values()
                        .filter(|(descriptor, _)| {
                            descriptor.contract_version == 1
                                && descriptor.capabilities.contains(capability)
                        })
                        .min_by(|(left, _), (right, _)| left.id.cmp(&right.id))
                        .map(|(descriptor, probe)| (SelectionSource::Automatic, descriptor, probe))
                })
            };

            if let Some((source, descriptor, probe)) = selected {
                selections.push(BackendSelection {
                    capability: *capability,
                    backend_id: descriptor.id.clone(),
                    source,
                });
                statuses.push(CapabilityStatus {
                    capability: *capability,
                    supported: probe.available,
                    backend_id: Some(descriptor.id.clone()),
                    reason: probe.reason.clone(),
                });
            } else {
                statuses.push(CapabilityStatus {
                    capability: *capability,
                    supported: false,
                    backend_id: None,
                    reason: Some("no available backend".into()),
                });
            }
        }
        Ok((selections, statuses))
    }

    pub fn instantiate(
        &self,
        selections: &[BackendSelection],
        config: &ManagerConfig,
    ) -> Result<Vec<BackendComponent>> {
        selections
            .iter()
            .map(|selection| {
                let factory = self
                    .factories
                    .iter()
                    .find(|factory| factory.descriptor().id == selection.backend_id)
                    .ok_or_else(|| ManagerError::PlatformUnsupported {
                        capability: selection.capability,
                        platform: std::env::consts::OS.into(),
                        backend: Some(selection.backend_id.clone()),
                        reason: format!(
                            "selected backend '{}' is not compiled in",
                            selection.backend_id
                        ),
                        recommendation: Some(
                            "restore the installed backend or select a compiled replacement".into(),
                        ),
                    })?;
                factory.create(selection.capability, config, selections)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestFactory {
        descriptor: BackendDescriptor,
        available: bool,
    }

    #[async_trait]
    impl BackendFactory for TestFactory {
        fn descriptor(&self) -> BackendDescriptor {
            self.descriptor.clone()
        }

        async fn probe(&self) -> Result<BackendProbe> {
            Ok(BackendProbe {
                available: self.available,
                reason: (!self.available).then(|| "missing binary".into()),
            })
        }
    }

    fn factory(id: &str, available: bool) -> TestFactory {
        TestFactory {
            descriptor: BackendDescriptor {
                id: id.into(),
                contract_version: 1,
                capabilities: [Capability::Service].into_iter().collect(),
                platform: "test".into(),
                requirements: Vec::new(),
            },
            available,
        }
    }

    #[tokio::test]
    async fn cli_precedes_config_and_state() {
        let mut registry = BackendRegistry::default();
        registry.register(factory("a", true));
        registry.register(factory("b", true));
        let preferences = BackendPreferences {
            cli: [(Capability::Service, "b".into())].into_iter().collect(),
            config: [(Capability::Service, "a".into())].into_iter().collect(),
            installed: [(Capability::Service, "a".into())].into_iter().collect(),
        };
        let (selected, _) = registry
            .resolve(&preferences, &[Capability::Service].into_iter().collect())
            .await
            .expect("registry should resolve");
        assert_eq!(selected[0].backend_id, "b");
        assert_eq!(selected[0].source, SelectionSource::Cli);
    }

    #[tokio::test]
    async fn unavailable_explicit_backend_is_an_error() {
        let mut registry = BackendRegistry::default();
        registry.register(factory("a", false));
        let preferences = BackendPreferences {
            cli: [(Capability::Service, "a".into())].into_iter().collect(),
            ..BackendPreferences::default()
        };
        let result = registry
            .resolve(&preferences, &[Capability::Service].into_iter().collect())
            .await;
        assert!(matches!(
            result,
            Err(ManagerError::PlatformUnsupported { .. })
        ));
    }

    #[tokio::test]
    async fn unavailable_saved_backend_is_retained_for_recovery_operations() {
        let mut registry = BackendRegistry::default();
        registry.register(factory("saved", false));
        let (selected, statuses) = registry
            .resolve(
                &BackendPreferences {
                    installed: [(Capability::Service, "saved".into())]
                        .into_iter()
                        .collect(),
                    ..BackendPreferences::default()
                },
                &[Capability::Service].into_iter().collect(),
            )
            .await
            .expect("saved backend must remain addressable");
        assert_eq!(selected[0].backend_id, "saved");
        assert!(!statuses[0].supported);
        assert_eq!(statuses[0].backend_id.as_deref(), Some("saved"));
    }

    #[tokio::test]
    async fn config_precedes_saved_selection_and_saved_precedes_auto() {
        let mut registry = BackendRegistry::default();
        registry.register(factory("auto-first", true));
        registry.register(factory("configured", true));
        registry.register(factory("saved", true));
        let required = [Capability::Service].into_iter().collect();
        let configured = registry
            .resolve(
                &BackendPreferences {
                    config: [(Capability::Service, "configured".into())]
                        .into_iter()
                        .collect(),
                    installed: [(Capability::Service, "saved".into())]
                        .into_iter()
                        .collect(),
                    ..BackendPreferences::default()
                },
                &required,
            )
            .await
            .expect("configured selection");
        assert_eq!(configured.0[0].backend_id, "configured");
        assert_eq!(configured.0[0].source, SelectionSource::Config);

        let saved = registry
            .resolve(
                &BackendPreferences {
                    installed: [(Capability::Service, "saved".into())]
                        .into_iter()
                        .collect(),
                    ..BackendPreferences::default()
                },
                &required,
            )
            .await
            .expect("saved selection");
        assert_eq!(saved.0[0].backend_id, "saved");
        assert_eq!(saved.0[0].source, SelectionSource::InstalledState);
    }

    #[tokio::test]
    async fn missing_capability_is_reported_without_false_success() {
        let registry = BackendRegistry::default();
        let (selected, statuses) = registry
            .resolve(
                &BackendPreferences::default(),
                &[Capability::Tun].into_iter().collect(),
            )
            .await
            .expect("missing capability is a status");
        assert!(selected.is_empty());
        assert_eq!(statuses.len(), 1);
        assert!(!statuses[0].supported);
        assert!(statuses[0].backend_id.is_none());
    }

    #[tokio::test]
    async fn unavailable_automatic_backend_remains_instantiable_for_bootstrap() {
        let mut registry = BackendRegistry::default();
        registry.register(factory("bootstrap", false));
        let (selected, statuses) = registry
            .resolve(
                &BackendPreferences::default(),
                &[Capability::Service].into_iter().collect(),
            )
            .await
            .expect("compiled backend remains selectable for package bootstrap");
        assert_eq!(selected[0].backend_id, "bootstrap");
        assert_eq!(selected[0].source, SelectionSource::Automatic);
        assert!(!statuses[0].supported);
        assert_eq!(statuses[0].backend_id.as_deref(), Some("bootstrap"));
    }

    #[tokio::test]
    async fn incompatible_explicit_backend_is_rejected() {
        let mut registry = BackendRegistry::default();
        registry.register(factory("service-only", true));
        let result = registry
            .resolve(
                &BackendPreferences {
                    cli: [(Capability::Tun, "service-only".into())]
                        .into_iter()
                        .collect(),
                    ..BackendPreferences::default()
                },
                &[Capability::Tun].into_iter().collect(),
            )
            .await;
        assert!(matches!(
            result,
            Err(ManagerError::PlatformUnsupported { .. })
        ));
    }

    #[tokio::test]
    async fn incompatible_contract_is_unavailable_before_instantiation() {
        let mut registry = BackendRegistry::default();
        let mut incompatible = factory("future", true);
        incompatible.descriptor.contract_version = 2;
        registry.register(incompatible);
        let result = registry
            .resolve(
                &BackendPreferences {
                    cli: [(Capability::Service, "future".into())]
                        .into_iter()
                        .collect(),
                    ..BackendPreferences::default()
                },
                &[Capability::Service].into_iter().collect(),
            )
            .await;
        assert!(matches!(
            result,
            Err(ManagerError::PlatformUnsupported { .. })
        ));
    }
}
