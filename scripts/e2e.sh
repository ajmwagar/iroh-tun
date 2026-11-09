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

[ "$(id -u)" = 0 ] || { echo "run with sudo: tun devices need root" >&2; exit 1; }
[ -x "$BIN" ] || { echo "build first: cargo build --release" >&2; exit 1; }

start() { # name tun ip route-id
  "$BIN" --tun "$2" --mtu 1280 --route "$3/32=$4" > "/tmp/iroh-tun-$1.log" 2>&1 &
  echo $!
}

# Bootstrap: each side needs the other's endpoint id, which is printed at start.
PARKED=$(start parked "$A_TUN" 192.0.2.9 0000000000000000000000000000000000000000000000000000000000000000 2>/dev/null || true)
sleep 2
A_ID=$(grep -o 'iroh-tun: [0-9a-f]\{64\}' /tmp/iroh-tun-parked.log | awk '{print $2}' | head -1)
[ -n "$A_ID" ] || { echo "A never printed an endpoint id; see /tmp/iroh-tun-parked.log" >&2; kill "$PARKED" 2>/dev/null; exit 1; }
kill "$PARKED" 2>/dev/null || true

B_PID=$(start b "$B_TUN" "$A_IP" "$A_ID")
sleep 2
B_ID=$(grep -o 'iroh-tun: [0-9a-f]\{64\}' /tmp/iroh-tun-b.log | awk '{print $2}' | head -1)
[ -n "$B_ID" ] || { echo "B never printed an endpoint id" >&2; exit 1; }

A_PID=$(start a "$A_TUN" "$B_IP" "$B_ID")
sleep 2

cleanup() { kill "$A_PID" "$B_PID" 2>/dev/null || true; }
trap cleanup EXIT

ifconfig "$A_TUN" inet "$A_IP" "$B_IP" up
ifconfig "$B_TUN" inet "$B_IP" "$A_IP" up
route -n add -host "$B_IP" -interface "$A_TUN" >/dev/null 2>&1 || true
route -n add -host "$A_IP" -interface "$B_TUN" >/dev/null 2>&1 || true

echo "A $A_ID on $A_IP, B $B_ID on $B_IP"
echo "pinging $B_IP through the tunnel..."
ping -c 3 -t 5 "$B_IP" || { echo "FAIL: see /tmp/iroh-tun-a.log and /tmp/iroh-tun-b.log" >&2; exit 1; }
echo "OK"
