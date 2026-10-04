#!/bin/sh
NORR="${NORR:-$(pwd)/build/norr}"
QUICK="${QUICK:-$(cd "$(dirname "$0")" && pwd)/norr-quick}"
PASS=0
FAIL=0

[ "$(uname -s)" = "Linux" ] || { echo "skip - not Linux"; exit 77; }
[ "$(id -u)" -eq 0 ] || { echo "skip - needs root for netns and TUN"; exit 77; }
command -v ip >/dev/null 2>&1 || { echo "skip - iproute2 not installed"; exit 77; }
command -v iptables >/dev/null 2>&1 || { echo "skip - iptables not installed"; exit 77; }
command -v iperf3 >/dev/null 2>&1 || { echo "skip - iperf3 not installed"; exit 77; }
[ -e /dev/net/tun ] || { echo "skip - /dev/net/tun absent"; exit 77; }
[ -x "$NORR" ] || { echo "skip - binary not found at $NORR"; exit 77; }

ok()  { echo "ok   - $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL - $1"; FAIL=$((FAIL + 1)); }

cleanup() {
  for ns in fw-user fw-iran fw-abroad; do
    ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null
  done
  sleep 0.3
  for ns in fw-user fw-iran fw-abroad; do ip netns del "$ns" 2>/dev/null; done
}
trap cleanup EXIT
cleanup

for ns in fw-user fw-iran fw-abroad; do
  ip netns add "$ns" || exit 1
  ip netns exec "$ns" ip link set lo up
done
ip link add veth-u netns fw-user type veth peer name veth-i netns fw-iran || exit 1
ip link add veth-j netns fw-iran type veth peer name veth-a netns fw-abroad || exit 1
ip netns exec fw-user ip addr add 10.93.0.3/24 dev veth-u
ip netns exec fw-iran ip addr add 10.93.0.2/24 dev veth-i
ip netns exec fw-iran ip addr add 10.94.0.2/24 dev veth-j
ip netns exec fw-abroad ip addr add 10.94.0.1/24 dev veth-a
for pair in "fw-user veth-u" "fw-iran veth-i" "fw-iran veth-j" "fw-abroad veth-a"; do
  set -- $pair
  ip netns exec "$1" ip link set "$2" up
done
ip netns exec fw-abroad ip route add default via 10.94.0.2

WORK=$(mktemp -d)
cd "$WORK" || exit 1
"$NORR" keygen >i.key 2>i.pub
"$NORR" keygen >a.key 2>a.pub
chmod 600 i.key a.key
I_PUB=$(awk '{print $2}' i.pub)
A_PUB=$(awk '{print $2}' a.pub)

cat >iran.toml <<EOF
[node]
listen_port = 51820
tun = "fwiran"
[identity]
key_file = "$WORK/i.key"
[network]
address = "10.99.0.1/24"
[[peer]]
name = "abroad"
public_key = "$A_PUB"
allowed_ips = "10.99.0.2/32"
[[forward]]
name = "xray"
listen_port = 2052
target = "10.99.0.2:2052"
preserve_source = true
[[forward]]
name = "legacy"
listen_port = 2053
target = "10.99.0.2:2053"
protocol = "tcp"
EOF

cat >abroad.toml <<EOF
[node]
role = "client"
listen_port = 51821
tun = "fwabroad"
[identity]
key_file = "$WORK/a.key"
[network]
address = "10.99.0.2/24"
return_via_tunnel = true
[[peer]]
name = "iran"
public_key = "$I_PUB"
endpoint = "10.94.0.2:51820"
allowed_ips = "10.99.0.1/32, 0.0.0.0/0"
routes = false
EOF

NORR="$NORR" ip netns exec fw-iran sh "$QUICK" up "$WORK/iran.toml" >iran.log 2>&1 \
  && ok "Iran relay up with a forward on 2052" || { bad "Iran relay up"; cat iran.log; }
NORR="$NORR" ip netns exec fw-abroad sh "$QUICK" up "$WORK/abroad.toml" >abroad.log 2>&1 \
  && ok "foreign server up and dialling Iran" || { bad "foreign up"; cat abroad.log; }

ip netns exec fw-abroad iperf3 -s -p 2052 -D --logfile "$WORK/preserve.log" >/dev/null 2>&1
ip netns exec fw-abroad iperf3 -s -p 2053 -D --logfile "$WORK/nat.log" >/dev/null 2>&1
attempt=0
while [ "$attempt" -lt 30 ]; do
  ip netns exec fw-iran ping -c1 -W1 10.99.0.2 >/dev/null 2>&1 && break
  attempt=$((attempt + 1))
done

rate() { awk '/receiver/ { v = $7; u = $8 } END { if (u == "Gbits/sec") v *= 1000; else if (u == "Kbits/sec") v /= 1000; print v + 0 }'; }
moved() { awk -v v="$1" 'BEGIN { exit !(v > 0) }'; }

tcp=$(ip netns exec fw-user iperf3 -c 10.93.0.2 -p 2052 -t 3 -f m 2>/dev/null | rate)
moved "$tcp" && ok "user reaches the foreign service through Iran:2052 over TCP ($tcp Mbit/s)" \
  || bad "TCP forward failed"

udp=$(ip netns exec fw-user iperf3 -c 10.93.0.2 -p 2052 -u -b 50M -t 3 -f m 2>/dev/null | rate)
moved "$udp" && ok "UDP forward carries datagrams ($udp Mbit/s)" || bad "UDP forward failed"

grep -q "Accepted connection from 10.93.0.3" "$WORK/preserve.log" \
  && ok "the foreign service sees the real client address 10.93.0.3" \
  || { bad "real client address not preserved"; grep Accepted "$WORK/preserve.log"; }

[ "$(ip netns exec fw-abroad ip route show default)" = "default via 10.94.0.2 dev veth-a " ] \
  || [ "$(ip netns exec fw-abroad ip route show default)" = "default via 10.94.0.2 dev veth-a" ] \
  && ok "main routing table untouched on the foreign server" || bad "return path changed the main routing table"

ip netns exec fw-user iperf3 -c 10.93.0.2 -p 2053 -t 1 >/dev/null 2>&1
grep -q "Accepted connection from 10.99.0.1" "$WORK/nat.log" \
  && ok "a NAT forward shows the relay address instead" || bad "NAT forward did not translate"

ip netns exec fw-user iperf3 -c 10.93.0.2 -p 2054 -t 1 >/dev/null 2>&1 \
  && bad "a port that is not forwarded answered" || ok "only the configured ports are forwarded"

ip netns exec fw-iran iptables -t nat -S | grep -q "dport 2052" \
  && ok "forward installed as a kernel DNAT rule" || bad "no DNAT rule"

NORR="$NORR" ip netns exec fw-abroad sh "$QUICK" down "$WORK/abroad.toml" >/dev/null 2>&1
ip netns exec fw-abroad ip rule show | grep -q "lookup 51821" \
  && bad "return-path rule left behind" || ok "down removed the return path"
NORR="$NORR" ip netns exec fw-iran sh "$QUICK" down "$WORK/iran.toml" >/dev/null 2>&1
ip netns exec fw-iran iptables-save | grep -q "norr-fwiran" \
  && bad "rules left behind after down" || ok "down removed every forward rule"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
