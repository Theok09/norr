#!/bin/bash
set -u

NORR="${NORR:-/tmp/b/norrd}"
PASS=0
FAIL=0

[ "$(uname -s)" = "Linux" ] || { echo "skip - not Linux"; exit 77; }
[ "$(id -u)" -eq 0 ] || { echo "skip - needs root"; exit 77; }
command -v ip >/dev/null 2>&1 || { echo "skip - iproute2 absent"; exit 77; }
command -v nc >/dev/null 2>&1 || { echo "skip - nc absent"; exit 77; }
[ -e /dev/net/tun ] || { echo "skip - /dev/net/tun absent"; exit 77; }
[ -x "$NORR" ] || { echo "skip - binary not found at $NORR"; exit 77; }

ok()  { echo "ok   - $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL - $1"; FAIL=$((FAIL + 1)); }

cleanup() {
  for ns in rp-a rp-b; do ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null; done
  sleep 0.2
  ip netns del rp-a 2>/dev/null
  ip netns del rp-b 2>/dev/null
}
trap cleanup EXIT
cleanup

ip netns add rp-a && ip netns add rp-b || exit 1
ip link add rva netns rp-a type veth peer name rvb netns rp-b || exit 1
ip netns exec rp-a ip addr add 10.27.0.1/24 dev rva
ip netns exec rp-b ip addr add 10.27.0.2/24 dev rvb
for ns in rp-a rp-b; do ip netns exec $ns ip link set lo up; done
ip netns exec rp-a ip link set rva up
ip netns exec rp-b ip link set rvb up

mkdir -p /tmp/rprobe && cd /tmp/rprobe || exit 1
"$NORR" keygen >a.key 2>a.pub
"$NORR" keygen >b.key 2>b.pub
"$NORR" keygen >r.key 2>r.pub
chmod 600 a.key b.key
A_PUB=$(awk '{print $2}' a.pub)
B_PUB=$(awk '{print $2}' b.pub)
R_PRIV=$(sed 's/^private //' r.key | tr -d '\n')
R_PUB=$(awk '{print $2}' r.pub)
PSK=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')

ip netns exec rp-a nc -lk 127.0.0.1 8443 >/dev/null 2>&1 &

cat >a.toml <<EOF
[node]
role = "server"
listen_port = 51870
tun = "rpA"
[identity]
key_file = "/tmp/rprobe/a.key"
[transport]
mode = "tcp-tls"
camouflage = "fake-tls"
sni = "www.example.com"
reality_private_key = "$R_PRIV"
reality_short_id = "0102030405060708"
reality_cover = "127.0.0.1:8443"
[network]
address = "10.35.0.1/32"
[[peer]]
name = "b"
public_key = "$B_PUB"
preshared_key = "$PSK"
allowed_ips = "10.35.0.2/32"
EOF

"$NORR" check a.toml >check.log 2>&1 && ok "REALITY server config validates" \
  || { bad "REALITY server config rejected"; cat check.log; exit 1; }

ip netns exec rp-a "$NORR" run /tmp/rprobe/a.toml >a.log 2>&1 &
sleep 2
A_PID=$(ip netns pids rp-a | xargs -r ps -o pid=,comm= -p | awk '$2=="norrd"{print $1}' | head -1)
[ -n "$A_PID" ] && ok "server running" || { bad "server did not start"; cat a.log; exit 1; }

for i in $(seq 1 20); do
  ip netns exec rp-b bash -c 'exec 3<>/dev/tcp/10.27.0.1/51870 && printf "\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00" >&3 && sleep 0.2 && exec 3>&-' 2>/dev/null
done
sleep 1

T1=$(awk '{print $14+$15}' /proc/$A_PID/stat)
sleep 5
T2=$(awk '{print $14+$15}' /proc/$A_PID/stat)
TICKS=$((T2 - T1))
echo "info - server used $TICKS ticks in 5s after 20 closed probes (500 = one full core)"
[ "$TICKS" -lt 100 ] && ok "rejected probes do not spin the CPU" \
  || bad "server is spinning after probes closed ($TICKS ticks / 5s)"

FDS=$(ls /proc/$A_PID/fd | wc -l)
echo "info - server holds $FDS fds"
[ "$FDS" -lt 40 ] && ok "closed probes do not leak descriptors" \
  || bad "server holds $FDS fds after probes closed"

echo
echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
