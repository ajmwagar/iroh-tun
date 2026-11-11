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

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact shape `myceliumd` publishes for its own tunnel: two overlay
    /// prefixes, and attributes the consumer does not read. The daemon cannot
    /// import this test, so the fixture is the contract.
    #[test]
    fn learns_from_the_shape_the_daemon_publishes() {
        let peer = iroh::SecretKey::generate().public();
        let document = format!(
            r#"{{"schema_version":1,"observations":[{{"service_id":"service/neo/iroh-tun","value":{{"kind":"iroh-tun","endpoints":["iroh://{peer}"],"protocols":["quic"],"formats":[],"attributes":{{"node_id":"neo","endpoint_id":"{peer}","overlay":"10.42.0.0/24,192.168.10.0/24","tun":"utun220","mtu":"1280","routes":"1"}}}}}}]}}"#
        );
        let (routes, hints) = routes_from_json(&document, "iroh-tun").unwrap();
        assert_eq!(routes.len(), 2);
        assert!(routes.iter().all(|route| route.peer == peer));
        let v4 = routes
            .iter()
            .find(|route| route.addr.is_ipv4())
            .expect("the IPv4 overlay prefix is a route");
        assert_eq!(v4.len, 24);
        assert!(v4.contains("10.42.0.7".parse().unwrap()).is_some());
        assert!(hints.is_empty(), "no address hints were published");
    }

    /// A node with no prefix is still a peer: it publishes an identity and
    /// nothing else. That must not become a route to nowhere.
    #[test]
    fn an_identity_without_prefixes_yields_no_routes() {
        let peer = iroh::SecretKey::generate().public();
        let document = format!(
            r#"{{"observations":[{{"value":{{"kind":"iroh-tun","endpoints":["iroh://{peer}"],"attributes":{{"endpoint_id":"{peer}","tun":"utun220"}}}}}}]}}"#
        );
        let (routes, hints) = routes_from_json(&document, "iroh-tun").unwrap();
        assert!(routes.is_empty());
        assert!(hints.is_empty());
    }
}
