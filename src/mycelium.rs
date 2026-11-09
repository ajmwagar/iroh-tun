//! Routes from the fleet, not from flags.
//!
//! The source of truth is `mycelium services --json`: every node running this
//! tunnel publishes an observation whose endpoints are `iroh://<endpoint-id>`
//! and whose attributes carry the overlay prefixes it answers for. Shelling out
//! keeps the dependency one-way and the failure obvious, which is the same
//! choice `mycelium-gateway` makes for its own catalog.

use std::net::SocketAddr;
use std::str::FromStr;

use anyhow::{Context, Result};
use iroh::EndpointId;
use serde::Deserialize;

use crate::Route;

/// One observation, as much of it as a tunnel needs.
#[derive(Debug, Deserialize)]
struct Observation {
    value: Value,
}

#[derive(Debug, Deserialize)]
struct Value {
    kind: String,
    #[serde(default)]
    endpoints: Vec<String>,
    #[serde(default)]
    attributes: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct Catalog {
    #[serde(default)]
    observations: Vec<Observation>,
}

/// Build routes from a `mycelium services --json` document.
///
/// An observation contributes a route for every prefix in `attributes.overlay`
/// (comma or whitespace separated). Address hints in `attributes.addresses`
/// are kept so a peer can be dialled without an address lookup.
/// What a catalog contributes: routes, and the address hints that came with
/// them so a peer can be dialled without a lookup.
pub type Learned = (Vec<Route>, Vec<(EndpointId, Vec<SocketAddr>)>);

pub fn routes_from_json(document: &str, kind: &str) -> Result<Learned> {
    let catalog: Catalog = serde_json::from_str(document).context("parse mycelium services")?;
    let mut routes = Vec::new();
    let mut hints = Vec::new();
    for observation in catalog.observations {
        if !kind_matches(&observation.value.kind, kind) {
            continue;
        }
        let peer = observation
            .value
            .attributes
            .get("endpoint_id")
            .map(String::as_str)
            .or_else(|| {
                observation
                    .value
                    .endpoints
                    .first()
                    .and_then(|e| e.strip_prefix("iroh://"))
            });
        let Some(peer) = peer else { continue };
        let Ok(peer) = EndpointId::from_str(peer.trim()) else {
            continue;
        };
        let addrs: Vec<SocketAddr> = observation
            .value
            .attributes
            .get("addresses")
            .into_iter()
            .flat_map(|list| list.split([',', ' ']))
            .filter_map(|addr| addr.trim().parse().ok())
            .collect();
        if !addrs.is_empty() {
            hints.push((peer, addrs));
        }
        let Some(overlay) = observation.value.attributes.get("overlay") else {
            continue;
        };
        for prefix in overlay.split([',', ' ']).filter(|p| !p.trim().is_empty()) {
            // Reuse the one prefix parser there is, rather than a second one
            // that could disagree with it.
            match Route::parse(&format!("{peerspec}={peer}", peerspec = prefix.trim())) {
                Ok(route) => routes.push(route),
                Err(error) => eprintln!("iroh-tun: skipping overlay {prefix}: {error}"),
            }
        }
    }
    Ok((routes, hints))
}

/// `iroh-tun` also accepts `iroh-tun/1` and `tun`, so a publisher choosing a
/// qualified kind does not have to match byte for byte.
fn kind_matches(observed: &str, wanted: &str) -> bool {
    observed == wanted
        || observed.strip_prefix(wanted) == Some("/1")
        || observed.starts_with(&format!("{wanted}/"))
}
