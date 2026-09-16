#!/bin/bash
# FEC across a deliberately lossy carrier.
#
# The point is not that the tunnel survives loss - it does that without FEC,
# by losing packets. The point is that parity reconstructs symbols the network
# dropped, so end-to-end loss is measurably lower than carrier loss. A run
# where the decoder recovers nothing is a failure even if pings succeed.
set -u

NORR="${NORR:-/tmp/b/norr}"
LOSS="${NORR_FEC_LOSS:-20}"
PASS=0
FAIL=0

[ "$(uname -s)" = "Linux" ] || { echo "skip - not Linux"; exit 77; }
[ "$(id -u)" -eq 0 ] || { echo "skip - needs root for netns and TUN"; exit 77; }
command -v ip >/dev/null 2>&1 || { echo "skip - iproute2 not installed"; exit 77; }
command -v ping >/dev/null 2>&1 || { echo "skip - ping not installed"; exit 77; }
command -v tc >/dev/null 2>&1 || { echo "skip - tc not installed"; exit 77; }
[ -e /dev/net/tun ] || { echo "skip - /dev/net/tun absent"; exit 77; }
[ -x "$NORR" ] || { echo "skip - binary not found at $NORR"; exit 77; }

ok()  { echo "ok   - $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL - $1"; FAIL=$((FAIL + 1)); }

cleanup() {
  ip netns pids norr-fa 2>/dev/null | xargs -r kill 2>/dev/null
  ip netns pids norr-fb 2>/dev/null | xargs -r kill 2>/dev/null
  sleep 0.2
  ip netns del norr-fa 2>/dev/null
  ip netns del norr-fb 2>/dev/null
}
trap cleanup EXIT

cleanup
ip netns add norr-fa || exit 1
ip netns add norr-fb || exit 1
ip link add vfa netns norr-fa type veth peer name vfb netns norr-fb || exit 1
ip netns exec norr-fa ip addr add 10.91.0.1/24 dev vfa
ip netns exec norr-fb ip addr add 10.91.0.2/24 dev vfb
ip netns exec norr-fa ip link set vfa up
ip netns exec norr-fb ip link set vfb up
ip netns exec norr-fa ip link set lo up
ip netns exec norr-fb ip link set lo up

mkdir -p /tmp/e2e-fec
cd /tmp/e2e-fec || exit 1
"$NORR" keygen >a.key 2>a.pub || exit 1
"$NORR" keygen >b.key 2>b.pub || exit 1
chmod 600 a.key b.key
A_PUB=$(awk '{print $2}' a.pub)
B_PUB=$(awk '{print $2}' b.pub)
PSK=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')

cat >a.toml <<EOF
[node]
role = "server"
listen_port = 51840
tun = "fecA"
[identity]
key_file = "/tmp/e2e-fec/a.key"
[fec]
mode = "moderate"
[network]
address = "10.98.0.1/32"
[[peer]]
name = "b"
public_key = "$B_PUB"
preshared_key = "$PSK"
allowed_ips = "10.98.0.2/32"
EOF

cat >b.toml <<EOF
[node]
role = "client"
listen_port = 51841
tun = "fecB"
[identity]
key_file = "/tmp/e2e-fec/b.key"
[fec]
mode = "moderate"
[network]
address = "10.98.0.2/32"
[[peer]]
name = "a"
public_key = "$A_PUB"
preshared_key = "$PSK"
endpoint = "10.91.0.1:51840"
allowed_ips = "10.98.0.1/32"
EOF

ip netns exec norr-fa "$NORR" run /tmp/e2e-fec/a.toml >a.log 2>&1 &
ip netns exec norr-fb "$NORR" run /tmp/e2e-fec/b.toml >b.log 2>&1 &
sleep 1.5

ip netns exec norr-fa ip addr add 10.98.0.1/32 dev fecA 2>/dev/null
ip netns exec norr-fa ip link set fecA up
ip netns exec norr-fa ip route add 10.98.0.2/32 dev fecA 2>/dev/null
ip netns exec norr-fb ip addr add 10.98.0.2/32 dev fecB 2>/dev/null
ip netns exec norr-fb ip link set fecB up
ip netns exec norr-fb ip route add 10.98.0.1/32 dev fecB 2>/dev/null
sleep 1.5

# With a clean carrier FEC must cost nothing: no loss, no reordering damage.
CLEAN=$(ip netns exec norr-fb ping -c10 -i0.2 -W1 -I 10.98.0.2 10.98.0.1 2>&1 \
        | awk -F'[,%]' '/packet loss/ {
             for (i = 1; i <= NF; ++i) if ($i ~ /packet loss/) printf "%d\n", $(i-1) + 0.5
           }')
[ "${CLEAN:-100}" -eq 0 ] && ok "clean carrier carries traffic with FEC on" \
  || bad "clean carrier lost ${CLEAN:-?}% with FEC on"

# Now break the carrier in both directions.
ip netns exec norr-fa tc qdisc add dev vfa root netem loss "${LOSS}%" || exit 1
ip netns exec norr-fb tc qdisc add dev vfb root netem loss "${LOSS}%" || exit 1

LOSSY=$(ip netns exec norr-fb ping -c60 -i0.2 -W1 -I 10.98.0.2 10.98.0.1 2>&1 \
        | awk -F'[,%]' '/packet loss/ {
             for (i = 1; i <= NF; ++i) if ($i ~ /packet loss/) printf "%d\n", $(i-1) + 0.5
           }')
echo "info - carrier loss ${LOSS}% each way, tunnel loss ${LOSSY:-?}%"

# A round trip crosses two lossy hops, so without recovery the expected loss is
# about 1-(1-p)^2: 36% at p=20. Anything near that means FEC did nothing.
[ "${LOSSY:-100}" -lt "$LOSS" ] \
  && ok "tunnel loss ${LOSSY}% is below the ${LOSS}% carrier loss" \
  || bad "tunnel loss ${LOSSY:-?}% shows no recovery"

ip netns pids norr-fa 2>/dev/null | xargs -r kill -TERM 2>/dev/null
ip netns pids norr-fb 2>/dev/null | xargs -r kill -TERM 2>/dev/null
sleep 1

# The counters are the proof that recovery happened rather than luck.
grep -q '^fec moderate' a.log && ok "node a reports its FEC mode" \
  || bad "node a reported no FEC stats"

RECOVERED=$(grep -oE 'recovered [0-9]+' a.log | grep -oE '[0-9]+')
[ "${RECOVERED:-0}" -gt 0 ] && ok "node a recovered ${RECOVERED} lost symbols" \
  || { bad "node a recovered nothing"; cat a.log; }

RECOVERED_B=$(grep -oE 'recovered [0-9]+' b.log | grep -oE '[0-9]+')
[ "${RECOVERED_B:-0}" -gt 0 ] && ok "node b recovered ${RECOVERED_B} lost symbols" \
  || { bad "node b recovered nothing"; cat b.log; }

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
