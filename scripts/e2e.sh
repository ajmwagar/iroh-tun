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
# Above the iroh datagram ceiling (about 1200) on purpose when MTU_TEST=1: that
# is the only way to make the kernel emit a packet the tunnel must refuse.
A_MTU=${A_MTU:-1280}
B_MTU=${B_MTU:-1280}
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

"$BIN" --tun "$B_TUN" --mtu "$B_MTU" --secret "$B_SECRET" \
  --listen "127.0.0.1:$B_PORT" --peer "$A_ID@127.0.0.1:$A_PORT" \
  --route "$A_IP/32=$A_ID" > /tmp/iroh-tun-b.log 2>&1 &
B_PID=$!
"$BIN" --tun "$A_TUN" --mtu "$A_MTU" --secret "$A_SECRET" \
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

if [ "${MTU_TEST:-0}" = 1 ]; then
  # A 1400-byte payload is bigger than one datagram can carry. With -D the
  # kernel may not fragment, so the only correct behaviour is a clean refusal
  # (ICMP fragmentation-needed), not silence and not a hang.
  echo
  echo "oversize, do-not-fragment (expect a refusal, not silence):"
  OUT=$(ping -c 2 -t 3 -s 1400 -D "$B_IP" 2>&1 || true)
  echo "$OUT"
  # A timeout here is a failure, not a pass: it means the packet vanished and
  # the fragmentation-needed notice never reached the kernel.
  if echo "$OUT" | grep -qi "too long\|mtu="; then
    echo "refused cleanly: the ICMP notice reached the kernel"
  else
    echo "FAIL: oversize packet neither arrived nor was refused" >&2
    exit 1
  fi

  echo
echo "after the refusal, a payload that fits must still work:"
  ping -c 2 -t 5 -s 900 "$B_IP" || {
    echo "FAIL: the tunnel did not recover from the oversize test" >&2
    exit 1
  }
  echo
echo "MTU behaviour OK: oversize refused, normal traffic survives"
fi

echo "OK"
