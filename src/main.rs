//! Minimal L3 tunnel: one IP packet per iroh QUIC datagram.
//!
//! Datagrams only. A stream would retransmit and order IP packets, so the
//! inner TCP would fight the outer congestion control ("TCP meltdown").
//! iroh supplies identity, NAT punch, relay fallback and migration; this crate
//! supplies only the IP plane: a tun device, a route table, and validation.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use clap::Parser;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

mod mycelium;
mod status;

const ALPN: &[u8] = b"iroh-tun/1";

#[derive(Parser)]
#[command(version, about = "IP over iroh datagrams")]
struct Args {
    /// tun device name (`utunN` on macOS, `tunN` on Linux).
    #[arg(long)]
    tun: String,
    /// Interface MTU. Kept below `max_datagram_size()`; 1280 is the IPv6 floor.
    #[arg(long, default_value_t = 1280)]
    mtu: u16,
    /// `prefix=endpoint-id` handed in by hand. Repeatable.
    #[arg(long = "route", value_name = "PREFIX=ID")]
    routes: Vec<String>,
    /// Learn routes from `mycelium services --json` instead of flags.
    #[arg(long, value_name = "BIN")]
    mycelium: Option<String>,
    /// Service kind a node publishes to join this overlay.
    #[arg(long, default_value = "iroh-tun")]
    service_kind: String,
    /// Re-read the catalog this often. A node that joins later is invisible
    /// until the next beat.
    #[arg(long, default_value_t = 15)]
    refresh_secs: u64,
    /// Dial this peer on startup instead of waiting to be dialled.
    #[arg(long)]
    connect: Option<String>,
    /// `endpoint-id@ip:port`, repeatable. Dial this peer at a known address
    /// instead of asking a discovery service where it is.
    #[arg(long = "peer", value_name = "ID@ADDR")]
    peers: Vec<String>,
    /// Bind the iroh endpoint here, so a peer can be handed this address
    /// before the process starts.
    #[arg(long, value_name = "IP:PORT")]
    listen: Option<std::net::SocketAddr>,
    /// 64 hex chars. A fixed key keeps this node's id across restarts; without
    /// it every run is a new identity and every peer's route goes stale.
    #[arg(long, value_name = "HEX")]
    secret: Option<String>,
    /// Write what this tunnel is doing here, atomically, every beat. The daemon
    /// that spawns this process reads it and publishes the observation; without
    /// it the daemon has an identity but no evidence of routing.
    #[arg(long, value_name = "PATH")]
    status_file: Option<std::path::PathBuf>,
    /// Print the endpoint id this `--secret` produces, then exit.
    #[arg(long)]
    print_id: bool,
}

/// A prefix a peer owns. Longest match wins.
#[derive(Clone, Copy)]
struct Route {
    addr: IpAddr,
    len: u8,
    peer: EndpointId,
}

impl Route {
    fn parse(spec: &str) -> Result<Self> {
        let (prefix, id) = spec
            .split_once('=')
            .context("route is PREFIX=ENDPOINT_ID")?;
        let (addr, len) = match prefix.split_once('/') {
            Some((addr, len)) => (addr, len.parse::<u8>().context("prefix length")?),
            None => (prefix, if prefix.contains(':') { 128 } else { 32 }),
        };
        let addr = IpAddr::from_str(addr).with_context(|| format!("prefix {prefix}"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if len > max {
            bail!("prefix {prefix} is longer than {max} bits");
        }
        Ok(Self {
            addr,
            len,
            peer: EndpointId::from_str(id).with_context(|| format!("endpoint id {id}"))?,
        })
    }

    fn contains(&self, ip: IpAddr) -> Option<u8> {
        match (self.addr, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let mask = if self.len == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.len)
                };
                (u32::from(a) & mask == u32::from(b) & mask).then_some(self.len)
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let mask = if self.len == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.len)
                };
                (u128::from(a) & mask == u128::from(b) & mask).then_some(self.len)
            }
            _ => None,
        }
    }
}

/// Destination address of an IP packet, if it is one we can route.
fn destination(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))),
        6 if packet.len() >= 40 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[24..40]);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// Source address, checked against the peer that sent the packet.
fn source(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        ))),
        6 if packet.len() >= 40 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[8..24]);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// An IPv4 "fragmentation needed" message quoting the oversized packet.
///
/// Dropping silently is the classic way to make a tunnel look slow: every TCP
/// flow stalls at its first full-size segment and no one learns why.
fn icmp_frag_needed(original: &[u8], mtu: u16) -> Option<Vec<u8>> {
    if original.len() < 20 || original[0] >> 4 != 4 {
        return None;
    }
    let mut out = vec![0u8; 20 + 8 + 28];
    let total = out.len() as u16;
    out[0] = 0x45;
    out[2..4].copy_from_slice(&total.to_be_bytes());
    out[8] = 64; // ttl
    out[9] = 1; // ICMP
    out[12..16].copy_from_slice(&original[16..20]); // reply from the packet's destination
    out[16..20].copy_from_slice(&original[12..16]); // ...to its source
    out[20] = 3; // destination unreachable
    out[21] = 4; // fragmentation needed
    out[26..28].copy_from_slice(&mtu.to_be_bytes());
    let quote = original.len().min(28);
    out[28..28 + quote].copy_from_slice(&original[..quote]);
    // The kernel checks this on every packet it takes off a tun. A wrong (or
    // missing) header checksum means the notice is discarded without a trace,
    // which is indistinguishable from the original packet simply vanishing.
    let header = checksum(&out[..20]);
    out[10..12].copy_from_slice(&header.to_be_bytes());
    let sum = checksum(&out[20..]);
    out[22..24].copy_from_slice(&sum.to_be_bytes());
    Some(out)
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]);
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn parse_secret(hex: &str) -> Result<iroh::SecretKey> {
    if hex.len() != 64 {
        bail!("a secret is 64 hex characters, got {}", hex.len());
    }
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .with_context(|| format!("secret byte {index}"))?;
    }
    Ok(iroh::SecretKey::from_bytes(&bytes))
}

fn parse_peer(spec: &str) -> Result<(EndpointId, iroh::EndpointAddr)> {
    let (id, addr) = spec
        .split_once('@')
        .context("peer is ENDPOINT_ID@IP:PORT")?;
    let id = EndpointId::from_str(id).with_context(|| format!("endpoint id {id}"))?;
    let addr: std::net::SocketAddr = addr.parse().with_context(|| format!("address {addr}"))?;
    Ok((
        id,
        iroh::EndpointAddr::from_parts(id, [iroh::TransportAddr::Ip(addr)]),
    ))
}

/// Publish this process's own view of itself.
///
/// Absent `--status-file` keeps a hand-run tunnel silent. A configured file that
/// cannot be written is fatal at startup: the daemon would otherwise publish an
/// identity with no evidence of routing behind it.
fn write_status(
    path: Option<&std::path::Path>,
    endpoint_id: &str,
    tun: &str,
    mtu: u16,
    routes: &[Route],
    failures: u32,
) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    status::write(
        path,
        &status::Status::new(endpoint_id.to_owned(), tun, mtu, routes, failures),
    )
    .with_context(|| format!("write status {}", path.display()))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber_init();
    let args = Args::parse();
    if let Some(hex) = &args.secret {
        if args.print_id {
            println!("{}", parse_secret(hex)?.public());
            return Ok(());
        }
    }
    // A node that learns routes from the catalog needs none handed in by hand.
    // Requiring one made the first node in a fleet unable to start: it has no
    // peer to point at, so it never publishes its kind, so no second node ever
    // has anything to learn and the overlay cannot bootstrap itself.
    if args.routes.is_empty() && args.mycelium.is_none() {
        bail!("at least one --route PREFIX=ENDPOINT_ID, or --mycelium to learn them");
    }
    let mut routes: Vec<Route> = args
        .routes
        .iter()
        .map(|spec| Route::parse(spec))
        .collect::<Result<_>>()?;
    let mut hints: BTreeMap<EndpointId, Vec<std::net::SocketAddr>> = BTreeMap::new();
    if let Some(bin) = &args.mycelium {
        let output = std::process::Command::new(bin)
            .args(["services", "--json"])
            .output()
            .with_context(|| format!("run {bin} services --json"))?;
        if !output.status.success() {
            bail!("{bin} services --json failed: {}", String::from_utf8_lossy(&output.stderr));
        }
        let (learned, addresses) =
            mycelium::routes_from_json(&String::from_utf8_lossy(&output.stdout), &args.service_kind)?;
        eprintln!(
            "iroh-tun: {} routes from {} (kind {})",
            learned.len(),
            bin,
            args.service_kind
        );
        routes.extend(learned);
        hints.extend(addresses);
    }
    // Zero routes is a valid starting state for a node that learns from the
    // catalog. The first node in a fleet has no peer to route to yet, and it
    // has to run before it can publish the kind that lets a second node learn
    // it. Refusing here means the overlay can never bootstrap itself.
    if routes.is_empty() {
        if args.mycelium.is_none() {
            bail!("no routes: pass --route PREFIX=ID, or --mycelium with a service kind");
        }
        eprintln!("iroh-tun: no peers yet; publishing and waiting for the catalog to fill");
    }
    let learned = routes;
    let routes: std::sync::Arc<tokio::sync::RwLock<Vec<Route>>> =
        std::sync::Arc::new(tokio::sync::RwLock::new(learned));
    let hints: std::sync::Arc<tokio::sync::RwLock<BTreeMap<EndpointId, Vec<std::net::SocketAddr>>>> =
        std::sync::Arc::new(tokio::sync::RwLock::new(hints));

    let mut config = tun::Configuration::default();
    config.tun_name(&args.tun).mtu(args.mtu).up();
    let tun =
        tun::create_as_async(&config).with_context(|| format!("open tun device {}", args.tun))?;
    let (mut tun_read, mut tun_write) = tokio::io::split(tun);
    let mut builder = Endpoint::builder(presets::N0).alpns(vec![ALPN.to_vec()]);
    if let Some(listen) = args.listen {
        builder = builder.bind_addr(listen).context("bind address")?;
    }
    if let Some(hex) = &args.secret {
        builder = builder.secret_key(parse_secret(hex)?);
    }
    let endpoint = builder.bind().await.context("bind iroh endpoint")?;
    println!("iroh-tun: {} on {}", endpoint.id(), args.tun);
    // What we are reachable *as*, before anything tries to dial us. Without this
    // a failed cross-host dial is indistinguishable from a host that never
    // published itself, and those need opposite fixes.
    eprintln!("iroh-tun: reachable at {:?}", endpoint.addr());
    let endpoint_id = endpoint.id().to_string();
    // Report before serving: a tunnel that binds but cannot describe itself is
    // invisible to the daemon, and invisible is indistinguishable from down.
    write_status(
        args.status_file.as_deref(),
        &endpoint_id,
        &args.tun,
        args.mtu,
        &routes.read().await,
        0,
    )?;

    // One writer owns the tun; readers hand it finished packets.
    let (to_tun, mut from_peers) = mpsc::channel::<Vec<u8>>(256);
    tokio::spawn(async move {
        while let Some(packet) = from_peers.recv().await {
            if let Err(error) = tun_write.write_all(&packet).await {
                eprintln!("iroh-tun: write {}: {error}", packet.len());
            }
        }
    });

    let endpoint_for_accept = endpoint.clone();
    let writer = to_tun.clone();
    let routes_for_accept = routes.clone();
    // The connections, shared. An accepted connection is a working path to that
    // peer and must be offered to the send side; keeping only outbound dials here
    // meant a reply re-dialled a peer that had just reached us, which works on
    // loopback (every dial succeeds) and fails exactly the one time it matters —
    // across two hosts behind NAT, where only one direction can dial.
    let peers: std::sync::Arc<tokio::sync::Mutex<BTreeMap<EndpointId, iroh::endpoint::Connection>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(BTreeMap::new()));
    let peers_for_accept = peers.clone();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint_for_accept.accept().await {
            let to_tun = writer.clone();
            let routes = routes_for_accept.clone();
            let peers = peers_for_accept.clone();
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let peer = conn.remote_id();
                eprintln!("iroh-tun: peer {peer} connected (inbound)");
                peers.lock().await.insert(peer, conn.clone());
                let max = conn.max_datagram_size().unwrap_or(1200);
                let mut dropped_spoofed = 0u32;
                while let Ok(packet) = conn.read_datagram().await {
                    let packet = packet.to_vec();
                    if packet.len() > max {
                        eprintln!("iroh-tun: {peer} sent {} > {max}", packet.len());
                        continue;
                    }
                    // A peer may only speak for the prefixes it was given. The
                    // guard is dropped before the next await so a refresh is
                    // never blocked by an idle connection.
                    let Some(src) = source(&packet) else { continue };
                    let allowed = {
                        let table = routes.read().await;
                        table
                            .iter()
                            .any(|r| r.peer == peer && r.contains(src).is_some())
                    };
                    if !allowed {
                        // Once per peer: a misconfigured route table otherwise
                        // prints a line per packet and hides everything else.
                        dropped_spoofed += 1;
                        if dropped_spoofed == 1 {
                            eprintln!("iroh-tun: {peer} spoofed {src}; dropping");
                        }
                        continue;
                    }
                    if to_tun.send(packet).await.is_err() {
                        break;
                    }
                }
                eprintln!(
                    "iroh-tun: peer {peer} disconnected (dropped {dropped_spoofed} unauthorized)"
                );
            });
        }
    });

    // The beat: re-read the catalog on a fixed period. A failed read keeps the
    // previous table and says so, rather than silently serving stale routes as
    // if they were fresh.
    if let Some(bin) = args.mycelium.clone() {
        let routes = routes.clone();
        let hints = hints.clone();
        let kind = args.service_kind.clone();
        let period = std::time::Duration::from_secs(args.refresh_secs.max(1));
        let status_file = args.status_file.clone();
        let tun = args.tun.clone();
        let mtu = args.mtu;
        let endpoint_id = endpoint_id.clone();
        // Deterministic stagger: this node always wakes at the same offset into
        // the beat. Random placement would let two consumers collide and then
        // stay collided, which is invisible until it is a load problem.
        let mut hash: u64 = 0xcbf29ce484222325;
        for byte in endpoint.id().to_string().bytes() {
            hash = (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3);
        }
        let stagger = period.mul_f64((hash % 1000) as f64 / 1000.0);
        tokio::spawn(async move {
            tokio::time::sleep(stagger).await;
            let mut failures: u32 = 0;
            loop {
                // Coalesce: one read per period, never a queue. If a read is
                // slow the next one starts late rather than piling up.
                let delay = if failures == 0 {
                    period
                } else {
                    // Backoff with jitter on failure: a hub outage must not turn
                    // every node into a fixed-period retry metronome.
                    let backoff = period
                        .saturating_mul(1u32 << failures.min(6))
                        .min(std::time::Duration::from_secs(300));
                    let jitter_ms = (std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| u64::from(d.subsec_millis()))
                        .unwrap_or(0))
                        % (backoff.as_millis().max(2) as u64);
                    backoff + std::time::Duration::from_millis(jitter_ms / 4)
                };
                tokio::time::sleep(delay).await;
                let outcome = std::process::Command::new(&bin)
                    .args(["services", "--json"])
                    .output()
                    .map_err(|error| format!("{bin}: {error}"))
                    .and_then(|output| {
                        if output.status.success() {
                            Ok(output)
                        } else {
                            Err(format!("{bin} exited {}", output.status))
                        }
                    })
                    .and_then(|output| {
                        mycelium::routes_from_json(&String::from_utf8_lossy(&output.stdout), &kind)
                            .map_err(|error| error.to_string())
                    });
                match outcome {
                    Ok((learned, addresses)) => {
                        failures = 0;
                        let live: std::collections::BTreeSet<EndpointId> =
                            learned.iter().map(|route| route.peer).collect();
                        let mut table = hints.write().await;
                        // A hint for a peer that no longer owns a prefix is dead
                        // weight: forgetting it is what makes a departed node
                        // depart rather than linger as an address nobody routes to.
                        table.retain(|peer, _| live.contains(peer));
                        table.extend(addresses);
                        drop(table);
                        let table = learned;
                        *routes.write().await = table.clone();
                        // Report after the table is replaced, never before: a
                        // status that describes routes the tunnel has not
                        // installed is worse than a stale one.
                        if let Err(error) = write_status(
                            status_file.as_deref(),
                            &endpoint_id,
                            &tun,
                            mtu,
                            &table,
                            failures,
                        ) {
                            eprintln!("iroh-tun: status: {error}");
                        }
                    }
                    Err(error) => {
                        failures = failures.saturating_add(1);
                        let table = routes.read().await.clone();
                        eprintln!(
                            "iroh-tun: refresh failed ({error}), keeping {} routes, attempt {failures}",
                            table.len()
                        );
                        // The daemon needs to see a failing beat too: a tunnel
                        // serving a stale table looks identical to a healthy
                        // one from the outside.
                        if let Err(error) = write_status(
                            status_file.as_deref(),
                            &endpoint_id,
                            &tun,
                            mtu,
                            &table,
                            failures,
                        ) {
                            eprintln!("iroh-tun: status: {error}");
                        }
                    }
                }
            }
        });
    }

    for spec in &args.peers {
        let (peer, addr) = parse_peer(spec)?;
        let conn = endpoint
            .connect(addr, ALPN)
            .await
            .with_context(|| format!("dial {peer}"))?;
        eprintln!("iroh-tun: dialed {peer} at a given address");
        peers.lock().await.insert(peer, conn);
    }
    if let Some(id) = args.connect.as_deref() {
        let peer = EndpointId::from_str(id).context("connect endpoint id")?;
        let conn = endpoint
            .connect(peer, ALPN)
            .await
            .with_context(|| format!("dial {peer}"))?;
        eprintln!("iroh-tun: dialed {peer}");
        peers.lock().await.insert(peer, conn);
    }

    let mut buffer = vec![0u8; args.mtu as usize];
    // A destination with no route is a configuration answer, not noise: say it
    // once per address rather than once per packet.
    let mut unrouteable: std::collections::BTreeSet<IpAddr> = std::collections::BTreeSet::new();
    loop {
        let n = tun_read.read(&mut buffer).await.context("read tun")?;
        let packet = &buffer[..n];
        let Some(dst) = destination(packet) else {
            if unrouteable.insert(IpAddr::V4(Ipv4Addr::UNSPECIFIED)) {
                eprintln!("iroh-tun: {n} byte packet is not IPv4 or IPv6");
            }
            continue;
        };
        let route = {
            let table = routes.read().await;
            table
                .iter()
                .filter(|r| r.contains(dst).is_some())
                .max_by_key(|r| r.len)
                .copied()
        };
        let Some(route) = route else {
            if unrouteable.insert(dst) {
                eprintln!("iroh-tun: no route for {dst}; that packet is dropped");
            }
            continue;
        };
        let hint = hints.read().await.get(&route.peer).cloned();
        let conn = {
            let mut map = peers.lock().await;
            // A connection that has closed is not a connection: forget it before
            // dialling again, so the map cannot fill with dead peers.
            map.retain(|_, conn| conn.close_reason().is_none());
            match map.get(&route.peer) {
                Some(conn) => conn.clone(),
                None => {
                    // Prefer a published address hint over an address lookup: the
                    // fleet already knows where its nodes are.
                    let target = match hint {
                        Some(addrs) if !addrs.is_empty() => iroh::EndpointAddr::from_parts(
                            route.peer,
                            addrs.iter().copied().map(iroh::TransportAddr::Ip),
                        ),
                        _ => iroh::EndpointAddr::new(route.peer),
                    };
                    let conn = endpoint
                        .connect(target, ALPN)
                        .await
                        .with_context(|| format!("dial {} for {dst}", route.peer))?;
                    eprintln!("iroh-tun: dialed {} for {dst}", route.peer);
                    map.insert(route.peer, conn.clone());
                    conn
                }
            }
        };
        let max = conn.max_datagram_size().unwrap_or(1200);
        if n > max {
            if let Some(notice) = icmp_frag_needed(packet, max as u16) {
                let _ = to_tun.try_send(notice);
            }
            continue;
        }
        if let Err(error) = conn.send_datagram(bytes::Bytes::copy_from_slice(packet)) {
            eprintln!("iroh-tun: send {} bytes to {}: {error}", n, route.peer);
            peers.lock().await.remove(&route.peer);
        }
    }
}

fn tracing_subscriber_init() {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Endpoint ids are ed25519 public keys, so a test id has to be a real key
    /// point; arbitrary 32 bytes are rejected by the parser.
    fn id() -> EndpointId {
        iroh::SecretKey::generate().public()
    }

    #[test]
    fn a_route_only_answers_for_its_prefix() {
        let peer = id();
        let host = Route::parse(&format!("10.253.0.9/32={peer}")).expect("route");
        assert!(host.contains(IpAddr::V4(Ipv4Addr::new(10, 253, 0, 9))).is_some());
        assert!(
            host.contains(IpAddr::V4(Ipv4Addr::new(10, 253, 0, 10))).is_none(),
            "a /32 is one address"
        );

        let net = Route::parse(&format!("10.253.0.0/24={peer}")).expect("route");
        assert!(net.contains(IpAddr::V4(Ipv4Addr::new(10, 253, 0, 200))).is_some());
        assert!(net.contains(IpAddr::V4(Ipv4Addr::new(10, 253, 1, 1))).is_none());
        assert!(
            net.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)).is_none(),
            "a v4 prefix never matches a v6 address"
        );
    }

    #[test]
    fn ipv6_prefixes_match_bitwise() {
        let peer = id();
        let net = Route::parse(&format!("fd7a:115c:a1e0::/48={peer}")).expect("route");
        let inside: IpAddr = "fd7a:115c:a1e0:1001::9".parse().expect("v6");
        let outside: IpAddr = "fd7a:115c:a1e1::9".parse().expect("v6");
        assert!(net.contains(inside).is_some());
        assert!(net.contains(outside).is_none());
    }

    #[test]
    fn the_longest_prefix_wins() {
        let (wide, narrow) = (id(), id());
        let routes = [
            Route::parse(&format!("10.0.0.0/8={wide}")).expect("wide"),
            Route::parse(&format!("10.253.0.0/16={narrow}")).expect("narrow"),
        ];
        let pick = |ip: IpAddr| {
            routes
                .iter()
                .filter(|r| r.contains(ip).is_some())
                .max_by_key(|r| r.len)
                .map(|r| r.peer)
        };
        assert_eq!(pick("10.253.0.9".parse().expect("ip")), Some(narrow));
        assert_eq!(pick("10.9.0.1".parse().expect("ip")), Some(wide));
        assert_eq!(pick("192.0.2.1".parse().expect("ip")), None);
    }

    #[test]
    fn a_bad_route_is_refused_with_a_reason() {
        let peer = id();
        for bad in [
            format!("10.0.0.0/33={peer}"),
            format!("fd00::/129={peer}"),
            "10.0.0.0/8=not-an-endpoint-id".to_string(),
            "no-equals-sign".to_string(),
        ] {
            assert!(Route::parse(&bad).is_err(), "{bad} must be refused");
        }
        // A bare address is a host route, not a malformed prefix.
        let host = Route::parse(&format!("10.0.0.0={peer}")).expect("a bare address is a /32");
        assert!(host.contains("10.0.0.0".parse().expect("ip")).is_some());
        assert!(
            host.contains("10.0.0.1".parse().expect("ip")).is_none(),
            "a host route is one address"
        );
    }

    #[test]
    fn routes_and_addresses_come_from_the_catalog() {
        let peer = id();
        let catalog = format!(
            r#"{{"observations":[
                {{"value":{{"kind":"iroh-tun","endpoints":["iroh://{peer}"],
                  "attributes":{{"endpoint_id":"{peer}","overlay":"10.253.0.9/32",
                                "addresses":"10.253.0.9:7443"}}}}}},
                {{"value":{{"kind":"unibus","endpoints":["tcp://10.253.0.6:18890"],
                  "attributes":{{"endpoint_id":"{peer}","overlay":"10.9.0.0/24"}}}}}}
            ]}}"#
        );
        let (routes, hints) = mycelium::routes_from_json(&catalog, "iroh-tun").expect("catalog");
        assert_eq!(routes.len(), 1, "only the kind we asked for contributes routes");
        assert_eq!(routes[0].peer, peer);
        assert!(routes[0].contains("10.253.0.9".parse().expect("ip")).is_some());
        assert_eq!(hints.len(), 1, "the address hint travels with the route");
        assert_eq!(hints[0].1, vec!["10.253.0.9:7443".parse().unwrap()]);
    }

    #[test]
    fn packets_are_read_and_truncated_input_is_ignored() {
        let mut v4 = vec![0u8; 20];
        v4[0] = 0x45;
        v4[12..16].copy_from_slice(&[10, 0, 0, 1]);
        v4[16..20].copy_from_slice(&[10, 0, 0, 2]);
        assert_eq!(
            source(&v4),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(
            destination(&v4),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        );

        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        v6[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        v6[24..40].copy_from_slice(&"fd7a:115c:a1e0::9".parse::<Ipv6Addr>().expect("v6").octets());
        assert_eq!(source(&v6), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));

        assert_eq!(destination(&[0x45, 0, 0]), None, "a short packet is not a packet");
        assert_eq!(destination(&[]), None);
        assert_eq!(destination(&[0x90; 40]), None, "version 9 is not IP");
    }

    #[test]
    fn an_oversized_packet_produces_a_checksummed_notice() {
        let mut v4 = vec![0u8; 1500];
        v4[0] = 0x45;
        v4[9] = 6; // TCP
        v4[12..16].copy_from_slice(&[10, 0, 0, 1]);
        v4[16..20].copy_from_slice(&[10, 0, 0, 2]);

        let notice = icmp_frag_needed(&v4, 1200).expect("a v4 packet yields a notice");
        assert_eq!(notice[0] >> 4, 4);
        assert_eq!(notice[9], 1, "ICMP");
        assert_eq!(notice[20], 3, "destination unreachable");
        assert_eq!(notice[21], 4, "fragmentation needed");
        assert_eq!(u16::from_be_bytes([notice[26], notice[27]]), 1200);
        assert_eq!(
            &notice[28..56],
            &v4[..28],
            "the notice quotes the original header"
        );
        assert_eq!(
            checksum(&notice[20..]),
            0,
            "a correct ICMP checksum sums to zero with its field included"
        );
        assert_eq!(
            checksum(&notice[..20]),
            0,
            "and the IPv4 header checksum must be right, or the kernel drops it"
        );

        assert!(icmp_frag_needed(&[0x60; 100], 1200).is_none(), "v6 is not done yet");
    }
}
