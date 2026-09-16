#!/bin/bash
# Two Norr nodes over the QUIC DATAGRAM carrier.
#
# The UDP path is covered by e2e_tunnel.sh. This exercises what is different
# about TCP: a listener rather than a bound socket, a stream rather than
# datagrams, a TLS handshake before anything can be sent, and a Noise handshake
# that has to wait for all of that.
set -u

NORR="${NORR:-/tmp/b/norr}"
PASS=0
FAIL=0

[ "$(uname -s)" = "Linux" ] || { echo "skip - not Linux"; exit 77; }
[ "$(id -u)" -eq 0 ] || { echo "skip - needs root"; exit 77; }
command -v ip >/dev/null 2>&1 || { echo "skip - iproute2 absent"; exit 77; }
command -v ping >/dev/null 2>&1 || { echo "skip - ping absent"; exit 77; }
[ -e /dev/net/tun ] || { echo "skip - /dev/net/tun absent"; exit 77; }
[ -x "$NORR" ] || { echo "skip - binary not found at $NORR"; exit 77; }
"$NORR" features 2>/dev/null | grep -qE "quic *[0-9]" || { echo "skip - no QUIC backend"; exit 77; }

ok()  { echo "ok   - $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL - $1"; FAIL=$((FAIL + 1)); }

cleanup() {
  for ns in quic-a quic-b; do
    ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null
  done
  sleep 0.2
  for ns in quic-a quic-b; do ip netns del "$ns" 2>/dev/null; done
}
trap cleanup EXIT
cleanup

ip netns add quic-a || exit 1
ip netns add quic-b || exit 1
ip link add ca netns quic-a type veth peer name cb netns quic-b
ip netns exec quic-a ip addr add 10.28.0.1/24 dev ca
ip netns exec quic-a ip link set ca up; ip netns exec quic-a ip link set lo up
ip netns exec quic-b ip addr add 10.28.0.2/24 dev cb
ip netns exec quic-b ip link set cb up; ip netns exec quic-b ip link set lo up

ip netns exec quic-b ping -c1 -W2 10.28.0.1 >/dev/null 2>&1 \
  && ok "carrier reachable" || { bad "carrier unreachable"; exit 1; }

mkdir -p /tmp/quice2e && cd /tmp/quice2e || exit 1
"$NORR" keygen >a.key 2>a.pub; "$NORR" keygen >b.key 2>b.pub
chmod 600 a.key b.key
A_PUB=$(awk '{print $2}' a.pub)
B_PUB=$(awk '{print $2}' b.pub)
PSK=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')

cat >a.toml <<EOF
[node]
listen_port = 51860
tun = "quicA"
[identity]
key_file = "/tmp/quice2e/a.key"
[transport]
mode = "quic"
[network]
address = "10.36.0.1/32"
[[peer]]
name = "b"
public_key = "$B_PUB"
preshared_key = "$PSK"
allowed_ips = "10.36.0.2/32"
EOF

cat >b.toml <<EOF
[node]
listen_port = 51861
tun = "quicB"
[identity]
key_file = "/tmp/quice2e/b.key"
[transport]
mode = "quic"
[network]
address = "10.36.0.2/32"
[[peer]]
name = "a"
public_key = "$A_PUB"
preshared_key = "$PSK"
endpoint = "10.28.0.1:51860"
allowed_ips = "10.36.0.1/32"
EOF

"$NORR" check a.toml >/dev/null 2>&1 && "$NORR" check b.toml >/dev/null 2>&1 \
  && ok "both configs validate" || bad "a config was rejected"

ip netns exec quic-a "$NORR" run /tmp/quice2e/a.toml >a.log 2>&1 &
ip netns exec quic-b "$NORR" run /tmp/quice2e/b.toml >b.log 2>&1 &
sleep 3

ip netns exec quic-a ip link show quicA >/dev/null 2>&1 \
  && ok "listener side created its TUN device" || bad "listener has no TUN"
ip netns exec quic-b ip link show quicB >/dev/null 2>&1 \
  && ok "dialing side created its TUN device" || bad "dialer has no TUN"

# The QUIC handshake has to finish before any DATAGRAM can carry a Norr frame,
# so a completed Noise handshake later is proof it did.
if ip netns exec quic-a ss -uln 2>/dev/null | grep -q 51860; then
  ok "QUIC socket bound"
else
  bad "no QUIC socket"
fi

ip netns exec quic-a ip addr add 10.36.0.1/32 dev quicA 2>/dev/null
ip netns exec quic-a ip link set quicA up
ip netns exec quic-a ip route add 10.36.0.2/32 dev quicA 2>/dev/null
ip netns exec quic-b ip addr add 10.36.0.2/32 dev quicB 2>/dev/null
ip netns exec quic-b ip link set quicB up
ip netns exec quic-b ip route add 10.36.0.1/32 dev quicB 2>/dev/null
sleep 4

if ip netns exec quic-b ping -c3 -W3 -I 10.36.0.2 10.36.0.1 >ping.log 2>&1; then
  ok "ICMP traversed the QUIC DATAGRAM carrier"
else
  bad "no ICMP over the QUIC carrier"
  tail -3 ping.log
fi

for ns in quic-a quic-b; do
  ip netns pids "$ns" 2>/dev/null | xargs -r kill -TERM 2>/dev/null
done
sleep 1

# Both sides must report a completed handshake: a tunnel that carried packets
# without one would mean the datapath accepted unauthenticated traffic.
grep -q "completed 1" a.log && grep -q "completed 1" b.log \
  && ok "both sides completed the Noise handshake" \
  || bad "a handshake did not complete"

echo "--- a ---"; cat a.log
echo "--- b ---"; cat b.log
echo
echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
