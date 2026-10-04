#!/bin/sh
NORR="${NORR:-$(pwd)/build/norr}"
QUICK="${QUICK:-$(cd "$(dirname "$0")" && pwd)/norr-quick}"
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
  for ns in gw-client gw-exit gw-net; do
    ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null
  done
  sleep 0.3
  for ns in gw-client gw-exit gw-net; do ip netns del "$ns" 2>/dev/null; done
}
trap cleanup EXIT
cleanup

for ns in gw-client gw-exit gw-net; do
  ip netns add "$ns" || exit 1
  ip netns exec "$ns" ip link set lo up
done

ip link add veth-c netns gw-client type veth peer name veth-e netns gw-exit || exit 1
ip link add veth-x netns gw-exit type veth peer name veth-n netns gw-net || exit 1
ip netns exec gw-client ip addr add 10.90.0.1/24 dev veth-c
ip netns exec gw-exit ip addr add 10.90.0.2/24 dev veth-e
ip netns exec gw-exit ip addr add 10.91.0.2/24 dev veth-x
ip netns exec gw-net ip addr add 10.91.0.3/24 dev veth-n
ip netns exec gw-client ip link set veth-c up
ip netns exec gw-exit ip link set veth-e up
ip netns exec gw-exit ip link set veth-x up
ip netns exec gw-net ip link set veth-n up
ip netns exec gw-client ip route add default via 10.90.0.2
ip netns exec gw-exit ip route add default via 10.91.0.3

WORK=$(mktemp -d)
cd "$WORK" || exit 1
"$NORR" keygen >c.key 2>c.pub
"$NORR" keygen >e.key 2>e.pub
chmod 600 c.key e.key
C_PUB=$(awk '{print $2}' c.pub)
E_PUB=$(awk '{print $2}' e.pub)

cat >exit.toml <<EOF
[node]
role = "server"
listen_port = 51820
tun = "gwexit"
[identity]
key_file = "$WORK/e.key"
[network]
address = "10.99.0.1/24"
forward = true
[[peer]]
name = "client"
public_key = "$C_PUB"
allowed_ips = "10.99.0.2/32"
EOF

cat >client.toml <<EOF
[node]
role = "client"
listen_port = 51821
tun = "gwclient"
[identity]
key_file = "$WORK/c.key"
[network]
address = "10.99.0.2/24"
fwmark = 51820
[[peer]]
name = "exit"
public_key = "$E_PUB"
endpoint = "10.90.0.2:51820"
allowed_ips = "0.0.0.0/0"
EOF

NORR="$NORR" ip netns exec gw-client sh "$QUICK" up "$WORK/client.toml" >client.log 2>&1 \
  && ok "client up before the exit exists" || { bad "client up"; cat client.log; }

sleep 12

NORR="$NORR" ip netns exec gw-exit sh "$QUICK" up "$WORK/exit.toml" >exit.log 2>&1 \
  && ok "exit up twelve seconds later" || { bad "exit up"; cat exit.log; }

reached=no
attempt=0
while [ "$attempt" -lt 30 ]; do
  if ip netns exec gw-client ping -c1 -W1 10.99.0.1 >/dev/null 2>&1; then reached=yes; break; fi
  attempt=$((attempt + 1))
done
[ "$reached" = yes ] && ok "client redialled and reached the exit's tunnel address" \
  || bad "tunnel never came up after the exit started late"

ip netns exec gw-client ping -c3 -W2 10.91.0.3 >/dev/null 2>&1 \
  && ok "Internet host reached through the exit with NAT" \
  || bad "Internet host unreachable through the exit"

ip netns exec gw-net ip route show | grep -q 10.99.0 \
  && bad "test is invalid: the Internet host knows the tunnel subnet" \
  || ok "Internet host has no route to the tunnel, so the reply proves NAT"

ip netns exec gw-client ping -c1 -W2 10.90.0.2 >/dev/null 2>&1 \
  && ok "underlay still reachable: the tunnel's own traffic bypasses the default route" \
  || bad "underlay lost: routing loop"

ip netns exec gw-client ping -c2 -W2 -M do -s 1392 10.91.0.3 >/dev/null 2>&1 \
  && ok "full-size packet at MTU 1420 crosses without fragmentation" \
  || bad "1420-byte packet did not cross"

if [ "${NORR_E2E_BULK:-1}" = 1 ] && command -v iperf3 >/dev/null 2>&1; then
  ip netns exec gw-net iperf3 -s -D -1 >/dev/null 2>&1
  sleep 0.5
  up=$(ip netns exec gw-client iperf3 -c 10.91.0.3 -t 3 -f m 2>/dev/null | awk '/receiver/{print ($8 == "Gbits/sec") ? $7 * 1000 : ($8 == "Kbits/sec") ? $7 / 1000 : $7}')
  ip netns exec gw-net iperf3 -s -D -1 >/dev/null 2>&1
  sleep 0.5
  down=$(ip netns exec gw-client iperf3 -c 10.91.0.3 -t 3 -R -f m 2>/dev/null | awk '/receiver/{print ($8 == "Gbits/sec") ? $7 * 1000 : ($8 == "Kbits/sec") ? $7 / 1000 : $7}')
  moved() { [ -n "$1" ] && awk -v v="$1" 'BEGIN { exit !(v > 0) }'; }
  moved "$up" && ok "bulk TCP upload through the tunnel: $up Mbit/s" \
    || bad "bulk TCP upload failed"
  moved "$down" && ok "bulk TCP download through the tunnel: $down Mbit/s" \
    || bad "bulk TCP download failed"
fi

NORR="$NORR" ip netns exec gw-client sh "$QUICK" down "$WORK/client.toml" >/dev/null 2>&1
ip netns exec gw-client ip rule show | grep -q "fwmark" \
  && bad "policy rules left behind after down" || ok "down removed policy rules"

NORR="$NORR" ip netns exec gw-exit sh "$QUICK" down "$WORK/exit.toml" >/dev/null 2>&1
ip netns exec gw-exit iptables -t nat -S | grep -q norr- \
  && bad "NAT rules left behind after down" || ok "down removed NAT rules"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
