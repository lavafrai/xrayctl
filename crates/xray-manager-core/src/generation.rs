use crate::Result;
use crate::events::ManagerEvent;
use crate::ports::{Clock, EventSink, FileSystem, XrayRunner, XrayTestRequest};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub struct GenerationService<F, X, C, E> {
    filesystem: F,
    xray: X,
    clock: C,
    events: E,
    counter: AtomicU64,
}

impl<F, X, C, E> GenerationService<F, X, C, E>
where
    F: FileSystem,
    X: XrayRunner,
    C: Clock,
    E: EventSink,
{
    pub fn new(filesystem: F, xray: X, clock: C, events: E) -> Self {
        Self {
            filesystem,
            xray,
            clock,
            events,
            counter: AtomicU64::new(0),
        }
    }

    pub async fn apply(
        &self,
        generations: &Path,
        current: &Path,
        previous: &Path,
        executable: PathBuf,
        assets: PathBuf,
        files: &[(String, Vec<u8>)],
    ) -> Result<PathBuf> {
        let candidate = generations.join(format!(
            "{}-{}",
            self.clock.unix_timestamp(),
            self.counter.fetch_add(1, Ordering::Relaxed)
        ));
        let config_dir = candidate.join("conf.d");
        self.filesystem.create_dir_all(&config_dir).await?;
        for (name, bytes) in files {
            self.filesystem
                .write_atomic(&config_dir.join(name), bytes, Some(0o640))
                .await?;
        }
        self.events.emit(ManagerEvent::ConfigValidationStarted);
        self.xray
            .test_config(&XrayTestRequest {
                executable,
                config_dir,
                asset_dir: assets,
            })
            .await?;
        self.events.emit(ManagerEvent::ConfigValidationSucceeded);
        self.filesystem
            .switch_generation(current, previous, &candidate)
            .await?;
        Ok(candidate)
    }
}
