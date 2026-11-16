use std::sync::Arc;

use crate::postgres::PgState;

/// Live PostgreSQL Data API resources. `stores` and `blocking_operations` are
/// retained for API compatibility and stay zero: this backend has no local stores
/// or blocking SQL workers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RdsDataStats {
    pub stores: usize,
    pub open_connections: usize,
    pub blocking_operations: usize,
    pub transactions: usize,
}

#[derive(Clone)]
pub struct RdsDataHandle {
    pub(crate) state: Arc<PgState>,
}

impl RdsDataHandle {
    pub fn statistics(&self) -> RdsDataStats {
        self.state.statistics()
    }

    pub async fn shutdown(&self) {
        self.state.shutdown().await;
    }
}
