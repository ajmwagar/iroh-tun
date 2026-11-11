//! What this tunnel is actually doing, written for the daemon that owns it.
//!
//! The daemon spawns this process, publishes the `iroh-tun` observation and owns
//! its expiry. It cannot see this process's route table, so the child reports it
//! instead of the daemon guessing. A missing or stale document is the signal that
//! the tunnel is not routing, which is why nothing here is best-effort: a status
//! write that fails is a startup error, not a warning.

use std::path::Path;

use serde::Serialize;

use crate::Route;

#[derive(Serialize)]
pub struct RouteStatus {
    pub prefix: String,
    pub peer: String,
}

#[derive(Serialize)]
pub struct Status {
    pub schema_version: u32,
    pub endpoint_id: String,
    pub tun: String,
    pub mtu: u16,
    pub observed_at: u64,
    pub routes: Vec<RouteStatus>,
    /// Consecutive failed catalog reads. Non-zero means the route table below is
    /// the last good one, not the current fleet.
    pub refresh_failures: u32,
}

impl Status {
    pub fn new(
        endpoint_id: String,
        tun: &str,
        mtu: u16,
        routes: &[Route],
        refresh_failures: u32,
    ) -> Self {
        Self {
            schema_version: 1,
            endpoint_id,
            tun: tun.to_owned(),
            mtu,
            observed_at: now(),
            routes: routes
                .iter()
                .map(|route| RouteStatus {
                    prefix: format!("{}/{}", route.addr, route.len),
                    peer: route.peer.to_string(),
                })
                .collect(),
            refresh_failures,
        }
    }
}

/// Write the document where the daemon reads it, atomically: a half-written
/// status is indistinguishable from a wedged tunnel.
pub fn write(path: &Path, status: &Status) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, serde_json::to_vec_pretty(status)?)?;
    std::fs::rename(temporary, path)
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
