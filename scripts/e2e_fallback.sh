#!/bin/bash
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

ip netns exec norr-la iptables -A INPUT  -p udp -s 10.92.0.2 -j DROP
ip netns exec norr-la iptables -A OUTPUT -p udp -d 10.92.0.2 -j DROP
ip netns exec norr-lb iptables -A INPUT  -p udp -s 10.92.0.1 -j DROP
ip netns exec norr-lb iptables -A OUTPUT -p udp -d 10.92.0.1 -j DROP
echo "info - UDP blocked, waiting for the nodes to notice"

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

if grep -q '^transport: switched to tcp-tls' b.log; then
  BEFORE=$(grep -c '^transport: switched to' b.log)
  ip netns exec norr-la iptables -A INPUT  -p tcp -s 10.92.0.2 -j DROP
  ip netns exec norr-la iptables -A OUTPUT -p tcp -d 10.92.0.2 -j DROP
  ip netns exec norr-lb iptables -A INPUT  -p tcp -s 10.92.0.1 -j DROP
  ip netns exec norr-lb iptables -A OUTPUT -p tcp -d 10.92.0.1 -j DROP
  ip netns exec norr-la iptables -D INPUT  -p udp -s 10.92.0.2 -j DROP
  ip netns exec norr-la iptables -D OUTPUT -p udp -d 10.92.0.2 -j DROP
  ip netns exec norr-lb iptables -D INPUT  -p udp -s 10.92.0.1 -j DROP
  ip netns exec norr-lb iptables -D OUTPUT -p udp -d 10.92.0.1 -j DROP
  echo "info - TCP now blocked and UDP restored; the TCP carrier can never become ready"

  LEFT=0
  for _ in $(seq 1 60); do
    sleep 2
    if [ "$(grep -c '^transport: switched to' b.log)" -gt "$BEFORE" ] &&
       tail -n 20 b.log | grep '^transport: switched to' | tail -1 | grep -qv 'tcp-tls'; then
      LEFT=1; break
    fi
  done
  [ "$LEFT" -eq 1 ] && ok "left a TCP carrier that could not connect: $(grep '^transport: switched to' b.log | tail -1)" \
    || bad "stayed on a TCP carrier that could not connect for 120s"

  BACK=0
  for _ in $(seq 1 15); do
    if ip netns exec norr-lb ping -c3 -i0.3 -W2 -I 10.97.0.2 10.97.0.1 >/dev/null 2>&1; then BACK=1; break; fi
    sleep 2
  done
  [ "$BACK" -eq 1 ] && ok "traffic resumed after leaving the dead TCP carrier" \
    || bad "traffic did not resume after TCP was blocked"
fi

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
