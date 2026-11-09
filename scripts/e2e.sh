# End-to-end check between two processes on one machine.
#
# Needs root for the tun devices. Run with: sudo ./scripts/e2e.sh
#
# Topology: A owns 10.9.0.1/32, B owns 10.9.0.2/32, each tun is point-to-point
# and the kernel routes the peer's /32 into it. A ping then exercises
# tun -> route lookup -> iroh datagram -> source check -> tun -> kernel reply.
set -euo pipefail

BIN=${BIN:-./target/release/iroh-tun}
A_TUN=${A_TUN:-utun210}
B_TUN=${B_TUN:-utun211}
A_IP=10.9.0.1
B_IP=10.9.0.2
A_PORT=37001
B_PORT=37002
# Fixed secrets, so an endpoint id is known before the process starts and does
# not change when it restarts. Without this the bootstrap hands a peer a stale id.
A_SECRET=$(printf 'a%063d' 0)
B_SECRET=$(printf 'b%063d' 0)

[ "$(id -u)" = 0 ] || { echo "run with sudo: tun devices need root" >&2; exit 1; }
[ -x "$BIN" ] || { echo "build first: cargo build --release" >&2; exit 1; }

A_ID=$("$BIN" --tun unused --secret "$A_SECRET" --print-id)
B_ID=$("$BIN" --tun unused --secret "$B_SECRET" --print-id)
echo "A $A_ID on $A_IP, B $B_ID on $B_IP"

"$BIN" --tun "$B_TUN" --mtu 1280 --secret "$B_SECRET" \
  --listen "127.0.0.1:$B_PORT" --peer "$A_ID@127.0.0.1:$A_PORT" \
  --route "$A_IP/32=$A_ID" > /tmp/iroh-tun-b.log 2>&1 &
B_PID=$!
"$BIN" --tun "$A_TUN" --mtu 1280 --secret "$A_SECRET" \
  --listen "127.0.0.1:$A_PORT" --peer "$B_ID@127.0.0.1:$B_PORT" \
  --route "$B_IP/32=$B_ID" > /tmp/iroh-tun-a.log 2>&1 &
A_PID=$!

cleanup() { kill "$A_PID" "$B_PID" 2>/dev/null || true; }
trap cleanup EXIT

sleep 3
ifconfig "$A_TUN" inet "$A_IP" "$B_IP" up
ifconfig "$B_TUN" inet "$B_IP" "$A_IP" up
route -n add -host "$B_IP" -interface "$A_TUN" >/dev/null 2>&1 || true
route -n add -host "$A_IP" -interface "$B_TUN" >/dev/null 2>&1 || true

echo "pinging $B_IP through the tunnel..."
ping -c 3 -t 5 "$B_IP" || { echo "FAIL: see /tmp/iroh-tun-a.log and /tmp/iroh-tun-b.log" >&2; exit 1; }
echo "OK"
