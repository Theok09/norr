#!/bin/bash
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
"$NORR" features 2>/dev/null | grep -q "tls *gnutls" || { echo "skip - no TLS backend"; exit 77; }

ok()  { echo "ok   - $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL - $1"; FAIL=$((FAIL + 1)); }

cleanup() {
  for ns in tz-a tz-b; do
    ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null
  done
  sleep 0.2
  for ns in tz-a tz-b; do ip netns del "$ns" 2>/dev/null; done
}
trap cleanup EXIT
cleanup

ip netns add tz-a || exit 1
ip netns add tz-b || exit 1
ip link add ca netns tz-a type veth peer name cb netns tz-b
ip netns exec tz-a ip addr add 10.26.0.1/24 dev ca
ip netns exec tz-a ip link set ca up; ip netns exec tz-a ip link set lo up
ip netns exec tz-b ip addr add 10.26.0.2/24 dev cb
ip netns exec tz-b ip link set cb up; ip netns exec tz-b ip link set lo up

ip netns exec tz-b ping -c1 -W2 10.26.0.1 >/dev/null 2>&1 \
  && ok "carrier reachable" || { bad "carrier unreachable"; exit 1; }

mkdir -p /tmp/tzombie && cd /tmp/tzombie || exit 1
"$NORR" keygen >a.key 2>a.pub; "$NORR" keygen >b.key 2>b.pub
chmod 600 a.key b.key
A_PUB=$(awk '{print $2}' a.pub)
B_PUB=$(awk '{print $2}' b.pub)
PSK=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')

cat >a.toml <<EOF
[node]
listen_port = 51840
tun = "tcpA"
[identity]
key_file = "/tmp/tzombie/a.key"
[transport]
mode = "tcp-tls"
[network]
address = "10.34.0.1/32"
[[peer]]
name = "b"
public_key = "$B_PUB"
preshared_key = "$PSK"
allowed_ips = "10.34.0.2/32"
EOF

cat >b.toml <<EOF
[node]
listen_port = 51841
tun = "tcpB"
[identity]
key_file = "/tmp/tzombie/b.key"
[transport]
mode = "tcp-tls"
[network]
address = "10.34.0.2/32"
[[peer]]
name = "a"
public_key = "$A_PUB"
preshared_key = "$PSK"
endpoint = "10.26.0.1:51840"
allowed_ips = "10.34.0.1/32"
EOF

"$NORR" check a.toml >/dev/null 2>&1 && "$NORR" check b.toml >/dev/null 2>&1 \
  && ok "both configs validate" || bad "a config was rejected"

ip netns exec tz-a "$NORR" run /tmp/tzombie/a.toml >a.log 2>&1 &
ip netns exec tz-b "$NORR" run /tmp/tzombie/b.toml >b.log 2>&1 &
sleep 3

ip netns exec tz-a ip link show tcpA >/dev/null 2>&1 \
  && ok "listener side created its TUN device" || bad "listener has no TUN"
ip netns exec tz-b ip link show tcpB >/dev/null 2>&1 \
  && ok "dialing side created its TUN device" || bad "dialer has no TUN"

if ip netns exec tz-a ss -tn 2>/dev/null | grep -q 51840; then
  ok "TCP connection established"
else
  bad "no TCP connection"
fi

ip netns exec tz-a ip addr add 10.34.0.1/32 dev tcpA 2>/dev/null
ip netns exec tz-a ip link set tcpA up
ip netns exec tz-a ip route add 10.34.0.2/32 dev tcpA 2>/dev/null
ip netns exec tz-b ip addr add 10.34.0.2/32 dev tcpB 2>/dev/null
ip netns exec tz-b ip link set tcpB up
ip netns exec tz-b ip route add 10.34.0.1/32 dev tcpB 2>/dev/null
sleep 4

if ip netns exec tz-b ping -c3 -W3 -I 10.34.0.2 10.34.0.1 >ping.log 2>&1; then
  ok "ICMP traversed the TLS-protected TCP carrier"
else
  bad "no ICMP over the TCP carrier"
  tail -3 ping.log
fi

A_PID=$(ip netns pids tz-a | head -1)
kill -STOP "$A_PID"
echo "info - listener frozen; its kernel still ACKs, the peer is silent"

RESET=0
for _ in $(seq 1 60); do
  sleep 2
  if grep -qE "tcp carrier: (peer|connection) silent, reconnecting" b.log; then RESET=1; break; fi
done
[ "$RESET" -eq 1 ] && ok "dialer abandoned a live-but-silent TCP connection" \
  || bad "dialer stayed on the silent connection for 120s"

kill -CONT "$A_PID"

BACK=0
for _ in $(seq 1 20); do
  if ip netns exec tz-b ping -c2 -W2 -I 10.34.0.2 10.34.0.1 >/dev/null 2>&1; then BACK=1; break; fi
  sleep 2
done
[ "$BACK" -eq 1 ] && ok "tunnel recovered on a fresh connection" \
  || { bad "tunnel did not recover after the listener resumed"
         echo "--- a ss ---"; ip netns exec tz-a ss -tnp 2>/dev/null
         echo "--- b ss ---"; ip netns exec tz-b ss -tnp 2>/dev/null; }

for ns in tz-a tz-b; do
  ip netns pids "$ns" 2>/dev/null | xargs -r kill -TERM 2>/dev/null
done
sleep 1

grep -qE "completed [1-9]" a.log && grep -qE "completed [1-9]" b.log \
  && ok "both sides completed the Noise handshake" \
  || bad "a handshake did not complete"

echo "--- a ---"; cat a.log
echo "--- b ---"; cat b.log
echo
echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
