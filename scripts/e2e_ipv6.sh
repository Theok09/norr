#!/bin/bash
# The same tunnel over IPv6: an IPv6 carrier, and IPv6 addresses inside it.
#
# Every other end-to-end test runs on IPv4, so the v6 paths through address
# parsing, socket binding, routing and the datapath were reachable only by unit
# tests. This exercises them with real traffic.
set -u

NORR="${NORR:-/tmp/b/norr}"
PASS=0
FAIL=0

[ "$(uname -s)" = "Linux" ] || { echo "skip - not Linux"; exit 77; }
[ "$(id -u)" -eq 0 ] || { echo "skip - needs root for netns and TUN"; exit 77; }
command -v ip >/dev/null 2>&1 || { echo "skip - iproute2 not installed"; exit 77; }
command -v ping >/dev/null 2>&1 || { echo "skip - ping not installed"; exit 77; }
[ -e /dev/net/tun ] || { echo "skip - /dev/net/tun absent"; exit 77; }
[ -x "$NORR" ] || { echo "skip - binary not found at $NORR"; exit 77; }

ok()  { echo "ok   - $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL - $1"; FAIL=$((FAIL + 1)); }

cleanup() {
  ip netns pids norr-6a 2>/dev/null | xargs -r kill 2>/dev/null
  ip netns pids norr-6b 2>/dev/null | xargs -r kill 2>/dev/null
  sleep 0.2
  ip netns del norr-6a 2>/dev/null
  ip netns del norr-6b 2>/dev/null
}
trap cleanup EXIT

cleanup
ip netns add norr-6a || exit 1
ip netns add norr-6b || exit 1
ip link add v6a netns norr-6a type veth peer name v6b netns norr-6b || exit 1

# Unique local addresses: routable inside the namespaces and nowhere else.
ip netns exec norr-6a ip -6 addr add fd00:aa::1/64 dev v6a nodad
ip netns exec norr-6b ip -6 addr add fd00:aa::2/64 dev v6b nodad
ip netns exec norr-6a ip link set v6a up
ip netns exec norr-6b ip link set v6b up
ip netns exec norr-6a ip link set lo up
ip netns exec norr-6b ip link set lo up
sleep 0.5

ip netns exec norr-6a ping -6 -c1 -W2 fd00:aa::2 >/dev/null 2>&1 \
  && ok "IPv6 carrier reachable" || { bad "IPv6 carrier unreachable"; exit 1; }

mkdir -p /tmp/e2e-v6
cd /tmp/e2e-v6 || exit 1
"$NORR" keygen >a.key 2>a.pub || exit 1
"$NORR" keygen >b.key 2>b.pub || exit 1
chmod 600 a.key b.key
A_PUB=$(awk '{print $2}' a.pub)
B_PUB=$(awk '{print $2}' b.pub)
PSK=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')

# The endpoint is an IPv6 literal in brackets, and the tunnel addresses inside
# are IPv6 too - so both the carrier and the payload exercise the v6 path.
cat >a.toml <<EOF
[node]
role = "server"
listen_port = 51870
tun = "v6A"
[identity]
key_file = "/tmp/e2e-v6/a.key"
[network]
address = "fd00:bb::1/128"
[[peer]]
name = "b"
public_key = "$B_PUB"
preshared_key = "$PSK"
allowed_ips = "fd00:bb::2/128"
EOF

cat >b.toml <<EOF
[node]
role = "client"
listen_port = 51871
tun = "v6B"
[identity]
key_file = "/tmp/e2e-v6/b.key"
[network]
address = "fd00:bb::2/128"
[[peer]]
name = "a"
public_key = "$A_PUB"
preshared_key = "$PSK"
endpoint = "[fd00:aa::1]:51870"
allowed_ips = "fd00:bb::1/128"
EOF

"$NORR" check a.toml >/dev/null 2>&1 && ok "IPv6 config a validates" || bad "IPv6 config a rejected"
"$NORR" check b.toml >/dev/null 2>&1 && ok "IPv6 config b validates" || bad "IPv6 config b rejected"

ip netns exec norr-6a "$NORR" run /tmp/e2e-v6/a.toml >a.log 2>&1 &
ip netns exec norr-6b "$NORR" run /tmp/e2e-v6/b.toml >b.log 2>&1 &
sleep 2

ip netns exec norr-6a ip link show v6A >/dev/null 2>&1 \
  && ok "node a created its TUN device" || { bad "node a has no TUN"; cat a.log; }

ip netns exec norr-6a ip -6 addr add fd00:bb::1/128 dev v6A nodad 2>/dev/null
ip netns exec norr-6a ip link set v6A up
ip netns exec norr-6a ip -6 route add fd00:bb::2/128 dev v6A 2>/dev/null
ip netns exec norr-6b ip -6 addr add fd00:bb::2/128 dev v6B nodad 2>/dev/null
ip netns exec norr-6b ip link set v6B up
ip netns exec norr-6b ip -6 route add fd00:bb::1/128 dev v6B 2>/dev/null
sleep 2

LOSS=$(ip netns exec norr-6b ping -6 -c10 -i0.3 -W2 -I fd00:bb::2 fd00:bb::1 2>&1 \
       | awk -F'[,%]' '/packet loss/ {
            for (i = 1; i <= NF; ++i) if ($i ~ /packet loss/) printf "%d\n", $(i-1) + 0.5
          }')
[ "${LOSS:-100}" -eq 0 ] && ok "ICMPv6 crosses the tunnel at 0% loss" \
  || { bad "IPv6 tunnel lost ${LOSS:-?}% of traffic"; tail -5 a.log; tail -5 b.log; }

ip netns pids norr-6a 2>/dev/null | xargs -r kill -TERM 2>/dev/null
ip netns pids norr-6b 2>/dev/null | xargs -r kill -TERM 2>/dev/null
sleep 1

grep -q 'completed 1' a.log && ok "node a completed a handshake over IPv6" \
  || { bad "node a never completed a handshake"; cat a.log; }

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
