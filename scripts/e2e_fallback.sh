#!/bin/bash
# Automatic transport fallback when UDP is blocked.
#
# The tunnel starts on UDP. A firewall rule then drops Norr's UDP on the
# carrier, and the node is expected to notice and move to a carrier that still
# works, without the operator doing anything. A run where traffic resumes but
# the transport never changed is a failure: that would mean the firewall rule
# missed, not that fallback worked.
set -u

NORR="${NORR:-/tmp/b/norr}"
PASS=0
FAIL=0

[ "$(uname -s)" = "Linux" ] || { echo "skip - not Linux"; exit 77; }
[ "$(id -u)" -eq 0 ] || { echo "skip - needs root for netns and TUN"; exit 77; }
command -v ip >/dev/null 2>&1 || { echo "skip - iproute2 not installed"; exit 77; }
command -v ping >/dev/null 2>&1 || { echo "skip - ping not installed"; exit 77; }
command -v iptables >/dev/null 2>&1 || { echo "skip - iptables not installed"; exit 77; }
[ -e /dev/net/tun ] || { echo "skip - /dev/net/tun absent"; exit 77; }
[ -x "$NORR" ] || { echo "skip - binary not found at $NORR"; exit 77; }

ok()  { echo "ok   - $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL - $1"; FAIL=$((FAIL + 1)); }

cleanup() {
  ip netns pids norr-la 2>/dev/null | xargs -r kill 2>/dev/null
  ip netns pids norr-lb 2>/dev/null | xargs -r kill 2>/dev/null
  sleep 0.2
  ip netns del norr-la 2>/dev/null
  ip netns del norr-lb 2>/dev/null
}
trap cleanup EXIT

cleanup
ip netns add norr-la || exit 1
ip netns add norr-lb || exit 1
ip link add vla netns norr-la type veth peer name vlb netns norr-lb || exit 1
ip netns exec norr-la ip addr add 10.92.0.1/24 dev vla
ip netns exec norr-lb ip addr add 10.92.0.2/24 dev vlb
ip netns exec norr-la ip link set vla up
ip netns exec norr-lb ip link set vlb up
ip netns exec norr-la ip link set lo up
ip netns exec norr-lb ip link set lo up

mkdir -p /tmp/e2e-fb
cd /tmp/e2e-fb || exit 1
"$NORR" keygen >a.key 2>a.pub || exit 1
"$NORR" keygen >b.key 2>b.pub || exit 1
chmod 600 a.key b.key
A_PUB=$(awk '{print $2}' a.pub)
B_PUB=$(awk '{print $2}' b.pub)
PSK=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')

# Both sides run transport.mode = "auto", so both build every carrier they can.
cat >a.toml <<EOF
[node]
role = "server"
listen_port = 51860
tun = "fbA"
[identity]
key_file = "/tmp/e2e-fb/a.key"
[transport]
mode = "auto"
[network]
address = "10.97.0.1/32"
[[peer]]
name = "b"
public_key = "$B_PUB"
preshared_key = "$PSK"
endpoint = "10.92.0.2:51861"
allowed_ips = "10.97.0.2/32"
EOF

cat >b.toml <<EOF
[node]
role = "client"
listen_port = 51861
tun = "fbB"
[identity]
key_file = "/tmp/e2e-fb/b.key"
[transport]
mode = "auto"
[network]
address = "10.97.0.2/32"
[[peer]]
name = "a"
public_key = "$A_PUB"
preshared_key = "$PSK"
endpoint = "10.92.0.1:51860"
allowed_ips = "10.97.0.1/32"
EOF

ip netns exec norr-la "$NORR" run /tmp/e2e-fb/a.toml >a.log 2>&1 &
ip netns exec norr-lb "$NORR" run /tmp/e2e-fb/b.toml >b.log 2>&1 &
sleep 2

ip netns exec norr-la ip addr add 10.97.0.1/32 dev fbA 2>/dev/null
ip netns exec norr-la ip link set fbA up
ip netns exec norr-la ip route add 10.97.0.2/32 dev fbA 2>/dev/null
ip netns exec norr-lb ip addr add 10.97.0.2/32 dev fbB 2>/dev/null
ip netns exec norr-lb ip link set fbB up
ip netns exec norr-lb ip route add 10.97.0.1/32 dev fbB 2>/dev/null
sleep 2

ip netns exec norr-lb ping -c5 -i0.2 -W3 -I 10.97.0.2 10.97.0.1 >/dev/null 2>&1 \
  && ok "tunnel carries traffic on UDP" || bad "tunnel never came up on UDP"

# Block Norr's UDP in both directions. TCP on the same hosts stays open, which
# is what the fallback is supposed to find.
# Every UDP datagram between the two hosts, in both directions. Matching on a
# port would miss replies sent from an ephemeral source port.
ip netns exec norr-la iptables -A INPUT  -p udp -s 10.92.0.2 -j DROP
ip netns exec norr-la iptables -A OUTPUT -p udp -d 10.92.0.2 -j DROP
ip netns exec norr-lb iptables -A INPUT  -p udp -s 10.92.0.1 -j DROP
ip netns exec norr-lb iptables -A OUTPUT -p udp -d 10.92.0.1 -j DROP
echo "info - UDP blocked, waiting for the nodes to notice"

# Dead-peer detection has to expire the session and the retries have to
# accumulate before the health gate opens, so this is not instant.
SWITCHED=0
for _ in $(seq 1 40); do
  sleep 2
  if grep -q '^transport: switched to' a.log || grep -q '^transport: switched to' b.log; then
    SWITCHED=1
    break
  fi
done

if [ "$SWITCHED" -eq 1 ]; then
  ok "a node reported switching transport: $(grep -h '^transport: switched to' a.log b.log | head -1)"
else
  bad "neither node switched transport after 80s with UDP blocked"
fi

# The switch is only worth anything if traffic actually resumes on the new
# carrier.
RESUMED=0
for _ in $(seq 1 15); do
  if ip netns exec norr-lb ping -c3 -i0.3 -W2 -I 10.97.0.2 10.97.0.1 >/dev/null 2>&1; then
    RESUMED=1
    break
  fi
  sleep 2
done
[ "$RESUMED" -eq 1 ] && ok "traffic resumed after the fallback" \
  || { bad "traffic never resumed"; tail -5 a.log; tail -5 b.log; }

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
