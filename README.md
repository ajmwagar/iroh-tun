# iroh-tun

A minimal L3 tunnel: **one IP packet per iroh QUIC datagram**. No streams in the
data path, no WireGuard, no second encryption layer.

## Why not WireGuard-over-QUIC

WireGuard inside QUIC is two encryptions and two congestion controllers doing
one job. iroh already gives identity, NAT punch, relay fallback and migration;
the only thing missing is an IP plane, and that is a TUN device plus a route
table.

## The data path is four calls

```rust
let n   = tun.read(&mut buf)?;                    // one IP packet
let dst = dst_of(&buf[..n])?;                     // route lookup: prefix -> peer
let con = routes.connection(dst)?;                // iroh connection to that peer
con.send_datagram(buf[..n].to_vec().into())?;     // 1 packet, 1 datagram
// reverse: con.read_datagram().await? -> tun.write_all(&pkt)
```

## Five invariants

1. **Datagrams only.** A stream retransmits and orders; put IP packets in one and
   the inner TCP fights the outer congestion control ("TCP meltdown").
2. **MTU comes from `max_datagram_size()`.** Set the TUN below it (~1200). On an
   oversize packet, emit **ICMP packet-too-big** into the tun instead of dropping
   it, or every TCP flow over the tunnel silently stalls at 1500-byte segments.
3. **Authorize the source per packet.** An endpoint id owns a set of prefixes.
   Check on every inbound packet, not at handshake time, or any peer can spoof
   any overlay address.
4. **Routes come from discovery.** prefix -> node -> endpoint id, from Mycelium's
   topology. Adding a node must not mean editing every peer's config. The
   learned prefixes are also installed in the host route table (and removed
   when they leave), because a route the kernel does not have is a packet the
   tunnel never sees.
5. **Privileges stay in one place.** the tun fd needs root or `CAP_NET_ADMIN`;
   keep that in a small privileged helper rather than the whole process. The
   route table has the same requirement, so route installation lives beside the
   device, not in a user process.

## Out of scope

Key distribution (iroh endpoint ids are the identity), relay (built into iroh),
NAT traversal (same), multicast, and anything at L4+.

## Status

Usable. The data path, MTU notice, source authorization, learned route table and
kernel route installation are implemented. A clean shutdown removes the routes
it added; the next start also removes prefixes recorded in the previous status
document, so a crash does not accumulate them.

The process still needs the tun device and route table, so it runs as a
root-owned service in the Mycelium installer. Splitting those privileges into a
narrow fd-passing helper remains future work.
