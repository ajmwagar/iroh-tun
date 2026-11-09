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
    /// `prefix=endpoint-id`, repeatable. A peer may only send for its prefixes.
    #[arg(long = "route", value_name = "PREFIX=ID")]
    routes: Vec<String>,
    /// Dial this peer on startup instead of waiting to be dialled.
    #[arg(long)]
    connect: Option<String>,
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber_init();
    let args = Args::parse();
    if args.routes.is_empty() {
        bail!("at least one --route PREFIX=ENDPOINT_ID is required");
    }
    let routes: std::sync::Arc<Vec<Route>> = std::sync::Arc::new(
        args.routes
            .iter()
            .map(|spec| Route::parse(spec))
            .collect::<Result<_>>()?,
    );

    let mut config = tun::Configuration::default();
    config.tun_name(&args.tun).mtu(args.mtu).up();
    let tun =
        tun::create_as_async(&config).with_context(|| format!("open tun device {}", args.tun))?;
    let (mut tun_read, mut tun_write) = tokio::io::split(tun);
    let endpoint = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .context("bind iroh endpoint")?;
    println!("iroh-tun: {} on {}", endpoint.id(), args.tun);

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
    tokio::spawn(async move {
        while let Some(incoming) = endpoint_for_accept.accept().await {
            let to_tun = writer.clone();
            let routes = routes_for_accept.clone();
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let peer = conn.remote_id();
                let max = conn.max_datagram_size().unwrap_or(1200);
                while let Ok(packet) = conn.read_datagram().await {
                    let packet = packet.to_vec();
                    if packet.len() > max {
                        eprintln!("iroh-tun: {peer} sent {} > {max}", packet.len());
                        continue;
                    }
                    // A peer may only speak for the prefixes it was given.
                    let Some(src) = source(&packet) else { continue };
                    if !routes
                        .iter()
                        .any(|r| r.peer == peer && r.contains(src).is_some())
                    {
                        eprintln!("iroh-tun: {peer} spoofed {src}");
                        continue;
                    }
                    let _ = to_tun.send(packet).await;
                }
            });
        }
    });

    let mut peers: BTreeMap<EndpointId, iroh::endpoint::Connection> = BTreeMap::new();
    if let Some(id) = args.connect.as_deref() {
        let peer = EndpointId::from_str(id).context("connect endpoint id")?;
        let conn = endpoint
            .connect(peer, ALPN)
            .await
            .with_context(|| format!("dial {peer}"))?;
        peers.insert(peer, conn);
    }

    let mut buffer = vec![0u8; args.mtu as usize];
    loop {
        let n = tun_read.read(&mut buffer).await.context("read tun")?;
        let packet = &buffer[..n];
        let Some(dst) = destination(packet) else {
            continue;
        };
        let Some(route) = routes
            .iter()
            .filter(|r| r.contains(dst).is_some())
            .max_by_key(|r| r.len)
        else {
            continue;
        };
        let conn = match peers.get(&route.peer) {
            Some(conn) => conn,
            None => {
                let conn = endpoint
                    .connect(route.peer, ALPN)
                    .await
                    .with_context(|| format!("dial {}", route.peer))?;
                peers.insert(route.peer, conn);
                peers.get(&route.peer).expect("just inserted")
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
            eprintln!("iroh-tun: send {} bytes: {error}", n);
            peers.remove(&route.peer);
        }
    }
}

fn tracing_subscriber_init() {}
