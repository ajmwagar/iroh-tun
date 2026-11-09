//! Minimal L3 tunnel: one IP packet per iroh QUIC datagram.
//!
//! Datagrams only. A stream in this path would retransmit and order IP
//! packets, reintroducing TCP meltdown on top of the inner TCP flows.
fn main() -> anyhow::Result<()> {
    println!("iroh-tun: skeleton; data path is four calls (see README)");
    Ok(())
}
