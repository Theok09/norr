#!/bin/bash
# Reproduces the camo (fake-TLS, bonded) sustained-flow stall in a netns, so it
# can be traced without touching production. Moves a few MB through the camo
# tunnel and checks real throughput, not just reachability.
set -u

NORR="${NORR:-/tmp/b/norrd}"
MB="${MB:-20}"
PASS=0; FAIL=0
[ "$(uname -s)" = "Linux" ] || { echo "skip - not Linux"; exit 77; }
[ "$(id -u)" -eq 0 ] || { echo "skip - needs root"; exit 77; }
command -v ip >/dev/null 2>&1 || { echo "skip - iproute2"; exit 77; }
command -v nc >/dev/null 2>&1 || { echo "skip - nc"; exit 77; }
[ -e /dev/net/tun ] || { echo "skip - no tun"; exit 77; }
[ -x "$NORR" ] || { echo "skip - no binary"; exit 77; }
ok(){ echo "ok   - $1"; PASS=$((PASS+1)); }
bad(){ echo "FAIL - $1"; FAIL=$((FAIL+1)); }

cleanup(){ for n in cb-a cb-b; do ip netns pids "$n" 2>/dev/null|xargs -r kill -9 2>/dev/null; done; sleep 0.2; ip netns del cb-a 2>/dev/null; ip netns del cb-b 2>/dev/null; }
trap cleanup EXIT; cleanup

ip netns add cb-a && ip netns add cb-b || exit 1
ip link add cba netns cb-a type veth peer name cbb netns cb-b || exit 1
ip netns exec cb-a ip addr add 10.40.0.1/24 dev cba; ip netns exec cb-a ip link set cba up; ip netns exec cb-a ip link set lo up
ip netns exec cb-b ip addr add 10.40.0.2/24 dev cbb; ip netns exec cb-b ip link set cbb up; ip netns exec cb-b ip link set lo up
# mimic the real Iran<->abroad path: ~95ms RTT, mild loss, bandwidth cap
if [ "${NETEM:-1}" = 1 ]; then
  ip netns exec cb-a tc qdisc add dev cba root netem delay 47ms loss 0.5% rate 500mbit 2>/dev/null
  ip netns exec cb-b tc qdisc add dev cbb root netem delay 47ms loss 0.5% rate 500mbit 2>/dev/null
fi

mkdir -p /tmp/camobulk && cd /tmp/camobulk
"$NORR" keygen >a.key 2>a.pub; "$NORR" keygen >b.key 2>b.pub; chmod 600 a.key b.key
A=$(awk '{print $2}' a.pub); B=$(awk '{print $2}' b.pub); PSK=$(head -c32 /dev/urandom|od -An -tx1|tr -d ' \n')

cat >a.toml <<EOF
[node]
role = "server"
listen_port = 51860
tun = "cbA"
[identity]
key_file = "/tmp/camobulk/a.key"
[transport]
mode = "tcp-tls"
camouflage = "fake-tls"
connections = 4
sni = "www.microsoft.com"
[network]
address = "10.44.0.1/30"
mtu = 1320
[[peer]]
name = "b"
public_key = "$B"
preshared_key = "$PSK"
allowed_ips = "10.44.0.2/32"
EOF
sed -e 's/role = "server"/role = "client"/' -e 's/listen_port = 51860/listen_port = 51861/' \
    -e 's#/a.key#/b.key#' -e 's/"cbA"/"cbB"/' -e 's/public_key = "'"$B"'"/public_key = "'"$A"'"/' \
    -e 's/10.44.0.1\/30/10.44.0.2\/30/' -e 's/10.44.0.2\/32/10.44.0.1\/32/' -e 's/name = "b"/name = "a"/' a.toml > b.toml
sed -i '/allowed_ips = "10.44.0.1\/32"/a endpoint = "10.40.0.1:51860"' b.toml

"$NORR" check a.toml >/dev/null 2>&1 && "$NORR" check b.toml >/dev/null 2>&1 && ok "camo configs validate" || { bad "config rejected"; "$NORR" check b.toml; exit 1; }

ip netns exec cb-a "$NORR" run /tmp/camobulk/a.toml >a.log 2>&1 &
ip netns exec cb-b "$NORR" run /tmp/camobulk/b.toml >b.log 2>&1 &
sleep 3
ip netns exec cb-a ip addr add 10.44.0.1/30 dev cbA 2>/dev/null; ip netns exec cb-a ip link set cbA up
ip netns exec cb-b ip addr add 10.44.0.2/30 dev cbB 2>/dev/null; ip netns exec cb-b ip link set cbB up
sleep 3

conns=$(ip netns exec cb-b ss -tnH "( dport = :51860 )" | wc -l)
[ "$conns" -ge 1 ] && ok "camo bonded connections up ($conns)" || bad "no camo connections"

# bulk: server (cb-a) sinks, client (cb-b) sends MB megabytes through the tunnel
ip netns exec cb-a sh -c 'nc -l -p 9000 >/dev/null 2>&1' &
sleep 1
t0=$(date +%s)
ip netns exec cb-b sh -c "head -c $((MB*1024*1024)) /dev/zero | timeout 30 nc -q2 10.44.0.1 9000" 2>/dev/null
t1=$(date +%s)
el=$((t1-t0)); [ "$el" -lt 1 ] && el=1
mbps=$(( MB * 8 / el ))
echo "info - pushed ${MB}MB in ${el}s = ${mbps} Mbit/s over camo"
[ "$mbps" -ge 5 ] && ok "camo carries a sustained flow (${mbps} Mbit/s)" \
  || { bad "camo stalled under load (${mbps} Mbit/s)"; echo "--- a ---"; tail -4 a.log; echo "--- b ---"; tail -4 b.log; }

echo; echo "$PASS passed, $FAIL failed"; [ "$FAIL" -eq 0 ]
