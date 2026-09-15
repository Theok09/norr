#!/bin/bash
# Three Norr nodes: a hub with two spokes.
#
# The two-node test cannot catch anything that depends on telling peers apart:
# peer id assignment, per-peer routing, source validation between peers, or a
# session table holding more than one entry. Each of those is a place where a
# bug looks like a working tunnel until a second peer exists.
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

ok()  { echo "ok   - $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL - $1"; FAIL=$((FAIL + 1)); }

cleanup() {
  for ns in mp-hub mp-s1 mp-s2; do
    ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null
  done
  sleep 0.2
  for ns in mp-hub mp-s1 mp-s2; do ip netns del "$ns" 2>/dev/null; done
}
trap cleanup EXIT
cleanup

for ns in mp-hub mp-s1 mp-s2; do ip netns add "$ns" || exit 1; ip netns exec "$ns" ip link set lo up; done

# Each spoke gets its own veth to the hub, so the carrier is a real network
# rather than a shared segment that could mask an addressing mistake.
ip link add h1 netns mp-hub type veth peer name s1 netns mp-s1
ip link add h2 netns mp-hub type veth peer name s2 netns mp-s2
ip netns exec mp-hub ip addr add 10.70.1.1/24 dev h1
ip netns exec mp-hub ip addr add 10.70.2.1/24 dev h2
ip netns exec mp-hub ip link set h1 up
ip netns exec mp-hub ip link set h2 up
ip netns exec mp-s1 ip addr add 10.70.1.2/24 dev s1; ip netns exec mp-s1 ip link set s1 up
ip netns exec mp-s2 ip addr add 10.70.2.2/24 dev s2; ip netns exec mp-s2 ip link set s2 up

ip netns exec mp-s1 ping -c1 -W2 10.70.1.1 >/dev/null 2>&1 \
  && ok "spoke 1 carrier reachable" || { bad "spoke 1 carrier down"; exit 1; }
ip netns exec mp-s2 ping -c1 -W2 10.70.2.1 >/dev/null 2>&1 \
  && ok "spoke 2 carrier reachable" || { bad "spoke 2 carrier down"; exit 1; }

mkdir -p /tmp/mp && cd /tmp/mp || exit 1
for n in hub s1 s2; do
  "$NORR" keygen >"$n.key" 2>"$n.pub" || { bad "keygen $n"; exit 1; }
  chmod 600 "$n.key"
done
HUB=$(awk '{print $2}' hub.pub)
S1=$(awk '{print $2}' s1.pub)
S2=$(awk '{print $2}' s2.pub)
PSK1=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
PSK2=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')

cat >hub.toml <<EOF
[node]
listen_port = 51900
tun = "mpHub"
[identity]
key_file = "/tmp/mp/hub.key"
[network]
address = "10.71.0.1/32"
[[peer]]
name = "s1"
public_key = "$S1"
preshared_key = "$PSK1"
allowed_ips = "10.71.0.2/32"
[[peer]]
name = "s2"
public_key = "$S2"
preshared_key = "$PSK2"
allowed_ips = "10.71.0.3/32"
EOF

cat >s1.toml <<EOF
[node]
listen_port = 51901
tun = "mpS1"
[identity]
key_file = "/tmp/mp/s1.key"
[network]
address = "10.71.0.2/32"
[[peer]]
name = "hub"
public_key = "$HUB"
preshared_key = "$PSK1"
endpoint = "10.70.1.1:51900"
allowed_ips = "10.71.0.1/32, 10.71.0.3/32"
EOF

cat >s2.toml <<EOF
[node]
listen_port = 51902
tun = "mpS2"
[identity]
key_file = "/tmp/mp/s2.key"
[network]
address = "10.71.0.3/32"
[[peer]]
name = "hub"
public_key = "$HUB"
preshared_key = "$PSK2"
endpoint = "10.70.2.1:51900"
allowed_ips = "10.71.0.1/32, 10.71.0.2/32"
EOF

for n in hub s1 s2; do
  "$NORR" check "$n.toml" >/dev/null 2>&1 || { bad "config $n rejected"; exit 1; }
done
ok "all three configs validate"

ip netns exec mp-hub "$NORR" run /tmp/mp/hub.toml >hub.log 2>&1 &
ip netns exec mp-s1  "$NORR" run /tmp/mp/s1.toml  >s1.log  2>&1 &
ip netns exec mp-s2  "$NORR" run /tmp/mp/s2.toml  >s2.log  2>&1 &
sleep 1.5

grep -q "peers 2" hub.log && ok "hub loaded two peers" || bad "hub did not load two peers"

ip netns exec mp-hub ip addr add 10.71.0.1/32 dev mpHub 2>/dev/null
ip netns exec mp-hub ip link set mpHub up
ip netns exec mp-hub ip route add 10.71.0.2/32 dev mpHub 2>/dev/null
ip netns exec mp-hub ip route add 10.71.0.3/32 dev mpHub 2>/dev/null

ip netns exec mp-s1 ip addr add 10.71.0.2/32 dev mpS1 2>/dev/null
ip netns exec mp-s1 ip link set mpS1 up
ip netns exec mp-s1 ip route add 10.71.0.1/32 dev mpS1 2>/dev/null

ip netns exec mp-s2 ip addr add 10.71.0.3/32 dev mpS2 2>/dev/null
ip netns exec mp-s2 ip link set mpS2 up
ip netns exec mp-s2 ip route add 10.71.0.1/32 dev mpS2 2>/dev/null

sleep 1.5

ip netns exec mp-s1 ping -c3 -W3 -I 10.71.0.2 10.71.0.1 >p1.log 2>&1 \
  && ok "spoke 1 reaches the hub" || { bad "spoke 1 cannot reach the hub"; tail -3 p1.log; }
ip netns exec mp-s2 ping -c3 -W3 -I 10.71.0.3 10.71.0.1 >p2.log 2>&1 \
  && ok "spoke 2 reaches the hub" || { bad "spoke 2 cannot reach the hub"; tail -3 p2.log; }

# Both sessions must coexist. If peer ids or key ids collided, the second
# handshake would have evicted the first and one spoke would now be dead.
ip netns exec mp-s1 ping -c2 -W3 -I 10.71.0.2 10.71.0.1 >p3.log 2>&1 \
  && ok "spoke 1 still reachable after spoke 2 connected" \
  || { bad "spoke 2 evicted spoke 1's session"; tail -3 p3.log; }

# The hub routes between spokes: a packet from s1 to s2 is decrypted, matched
# against s2's prefix, and re-encrypted under s2's session.
#
# Each spoke's allowed_ips must cover the other spoke, or the hub refuses the
# packet as unauthorized for its ingress peer. That is source validation doing
# its job, so the configuration says so explicitly rather than the test
# working around it.
ip netns exec mp-s1 ip route add 10.71.0.3/32 dev mpS1 2>/dev/null
ip netns exec mp-s2 ip route add 10.71.0.2/32 dev mpS2 2>/dev/null
sleep 0.5
if ip netns exec mp-s1 ping -c3 -W3 -I 10.71.0.2 10.71.0.3 >p4.log 2>&1; then
  ok "spoke-to-spoke traffic routed through the hub"
else
  bad "hub did not route between spokes"
  tail -3 p4.log
fi

for ns in mp-hub mp-s1 mp-s2; do
  ip netns pids "$ns" 2>/dev/null | xargs -r kill -TERM 2>/dev/null
done
sleep 0.5
echo "--- hub ---"; cat hub.log
echo "--- s1 ---";  cat s1.log
echo "--- s2 ---";  cat s2.log

echo
echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
