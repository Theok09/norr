#!/bin/bash
set -u

NORR="${NORR:-/tmp/b/norr}"
PASS=0
FAIL=0

[ "$(uname -s)" = "Linux" ] || { echo "skip - not Linux"; exit 77; }
[ "$(id -u)" -eq 0 ] || { echo "skip - needs root for netns and TUN"; exit 77; }
command -v ip >/dev/null 2>&1 || { echo "skip - iproute2 not installed"; exit 77; }
command -v ping >/dev/null 2>&1 || { echo "skip - ping not installed"; exit 77; }
command -v nc >/dev/null 2>&1 || { echo "skip - nc not installed"; exit 77; }
[ -e /dev/net/tun ] || { echo "skip - /dev/net/tun absent"; exit 77; }
[ -x "$NORR" ] || { echo "skip - binary not found at $NORR"; exit 77; }

ok()  { echo "ok   - $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL - $1"; FAIL=$((FAIL + 1)); }

cleanup() {
  ip netns pids i6-a 2>/dev/null | xargs -r kill 2>/dev/null
  ip netns pids i6-b 2>/dev/null | xargs -r kill 2>/dev/null
  sleep 0.2
  ip netns del i6-a 2>/dev/null
  ip netns del i6-b 2>/dev/null
}
trap cleanup EXIT

cleanup
ip netns add i6-a || exit 1
ip netns add i6-b || exit 1
ip link add iva netns i6-a type veth peer name ivb netns i6-b || exit 1

ip netns exec i6-a ip -6 addr add fd00:aa::1/64 dev iva nodad
ip netns exec i6-b ip -6 addr add fd00:aa::2/64 dev ivb nodad
ip netns exec i6-a ip link set iva up
ip netns exec i6-b ip link set ivb up
ip netns exec i6-a ip link set lo up
ip netns exec i6-b ip link set lo up
sleep 0.5

ip netns exec i6-a ping -6 -c1 -W2 fd00:aa::2 >/dev/null 2>&1 \
  && ok "IPv6 carrier reachable" || { bad "IPv6 carrier unreachable"; exit 1; }

mkdir -p /tmp/e2e-v6icmp
cd /tmp/e2e-v6icmp || exit 1
"$NORR" keygen >a.key 2>a.pub || exit 1
"$NORR" keygen >b.key 2>b.pub || exit 1
chmod 600 a.key b.key
A_PUB=$(awk '{print $2}' a.pub)
B_PUB=$(awk '{print $2}' b.pub)
PSK=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')

cat >a.toml <<EOF
[node]
role = "server"
listen_port = 9
tun = "i6A"
[identity]
key_file = "/tmp/e2e-v6icmp/a.key"
[transport]
mode = "icmp"
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
listen_port = 9
tun = "i6B"
[identity]
key_file = "/tmp/e2e-v6icmp/b.key"
[transport]
mode = "icmp"
[network]
address = "fd00:bb::2/128"
[[peer]]
name = "a"
public_key = "$A_PUB"
preshared_key = "$PSK"
endpoint = "[fd00:aa::1]:9"
allowed_ips = "fd00:bb::1/128"
EOF

"$NORR" check a.toml >/dev/null 2>&1 && ok "ICMPv6 config a validates" || bad "IPv6 config a rejected"
"$NORR" check b.toml >/dev/null 2>&1 && ok "ICMPv6 config b validates" || bad "IPv6 config b rejected"

ip netns exec i6-a sysctl -qw net.ipv6.icmp.echo_ignore_all=1 2>/dev/null || true
ip netns exec i6-a "$NORR" run /tmp/e2e-v6icmp/a.toml >a.log 2>&1 &
ip netns exec i6-b "$NORR" run /tmp/e2e-v6icmp/b.toml >b.log 2>&1 &
sleep 2

ip netns exec i6-a ip link show i6A >/dev/null 2>&1 \
  && ok "node a created its TUN device" || { bad "node a has no TUN"; cat a.log; }

ip netns exec i6-a ip -6 addr add fd00:bb::1/128 dev i6A nodad 2>/dev/null
ip netns exec i6-a ip link set i6A up
ip netns exec i6-a ip -6 route add fd00:bb::2/128 dev i6A 2>/dev/null
ip netns exec i6-b ip -6 addr add fd00:bb::2/128 dev i6B nodad 2>/dev/null
ip netns exec i6-b ip link set i6B up
ip netns exec i6-b ip -6 route add fd00:bb::1/128 dev i6B 2>/dev/null
sleep 2

ip netns exec i6-a nc -6 -lk -s fd00:bb::1 -p 7777 >/dev/null 2>&1 &
UP=0
for _ in $(seq 1 15); do
  if ip netns exec i6-b timeout 2 bash -c "echo > /dev/tcp/fd00:bb::1/7777" 2>/dev/null; then UP=1; break; fi
  sleep 1
done
[ "$UP" -eq 1 ] && ok "an ICMP-transport tunnel carries IPv6 traffic end to end" \
  || { bad "ICMPv6-transport tunnel carried no traffic"; tail -5 a.log; tail -5 b.log; }

ip netns pids i6-a 2>/dev/null | xargs -r kill -TERM 2>/dev/null
ip netns pids i6-b 2>/dev/null | xargs -r kill -TERM 2>/dev/null
sleep 1

grep -q 'completed 1' a.log && ok "node a completed a handshake over IPv6" \
  || { bad "node a never completed a handshake"; cat a.log; }

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
