use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio_util::sync::CancellationToken;

/// Lightweight task manager for background loops.
///
/// - Ensures the task starts only once
/// - Provides a cancellation token for graceful shutdown
pub struct TaskManager {
    started: AtomicBool,
    shutdown: CancellationToken,
}

impl TaskManager {
    pub fn new() -> Self {
        Self {
            started: AtomicBool::new(false),
            shutdown: CancellationToken::new(),
        }
    }

    pub fn start<F, Fut>(&self, task: F) -> bool
    where
        F: FnOnce(CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        if self
            .started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }

        if tokio::runtime::Handle::try_current().is_err() {
            self.started.store(false, Ordering::Release);
            return false;
        }

        let token = self.shutdown.clone();
        tokio::spawn(async move {
            task(token).await;
        });
        true
    }

    pub fn stop(&self) {
        self.shutdown.cancel();
    }
}

impl Default for TaskManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TaskManager {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}