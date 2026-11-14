//! Optional inspector projection and notifications.
use super::ContractManager;

impl ContractManager {
    /// Start the inspector server on `127.0.0.1:port` (see [`crate::inspector`]):
    /// it pushes a JSON snapshot of every managed instance to each connected
    /// client on every state change.
    ///
    /// # Errors
    ///
    /// Returns an error if the inspector cannot bind its loopback TCP listener.
    #[cfg(feature = "inspector")]
    pub fn enable_inspector(&mut self, port: u16) -> std::io::Result<()> {
        let state = std::sync::Arc::new(std::sync::Mutex::new(self.build_snapshot()));
        let notify = std::sync::Arc::new(std::sync::Condvar::new());
        crate::inspector::start_inspector_server(
            std::sync::Arc::clone(&state),
            std::sync::Arc::clone(&notify),
            port,
        )?;
        self.inspector_state = Some(state);
        self.inspector_notify = Some(notify);
        Ok(())
    }

    #[cfg(feature = "inspector")]
    pub(super) fn build_snapshot(&self) -> crate::inspector::ManagerSnapshot {
        crate::inspector::ManagerSnapshot {
            timestamp_ms: crate::inspector::now_ms(),
            instances: self
                .instances
                .iter()
                .enumerate()
                .map(|(i, inst)| {
                    crate::inspector::snapshot_instance(i, &inst.borrow(), self.network)
                })
                .collect(),
        }
    }

    /// Refresh the shared snapshot and wake the inspector's client threads.
    /// Called after every instance-state mutation; a no-op unless enabled.
    #[cfg(feature = "inspector")]
    pub(super) fn notify_inspector(&self) {
        if let (Some(state), Some(notify)) = (&self.inspector_state, &self.inspector_notify) {
            let snapshot = self.build_snapshot();
            *state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = snapshot;
            notify.notify_all();
        }
    }
}
