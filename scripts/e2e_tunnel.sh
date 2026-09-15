#!/bin/bash
# Two Norr nodes in separate network namespaces, carrying real traffic.
#
# Namespaces are mandatory rather than cosmetic: with both endpoints in one
# namespace the kernel routes between the two TUN devices directly and the
# tunnel is never exercised, so the test would pass without the datapath
# working at all.
#
# Exits non-zero on any failure, so this is usable in CI.
set -u

NORR="${NORR:-/tmp/b/norr}"
PASS=0
FAIL=0

# 77 is ctest's "skipped" code. Missing privilege or missing tooling is not a
# failure of the code under test, and reporting it as one would train people to
# ignore a red suite.
[ "$(uname -s)" = "Linux" ] || { echo "skip - not Linux"; exit 77; }
[ "$(id -u)" -eq 0 ] || { echo "skip - needs root for netns and TUN"; exit 77; }
command -v ip >/dev/null 2>&1 || { echo "skip - iproute2 not installed"; exit 77; }
command -v ping >/dev/null 2>&1 || { echo "skip - ping not installed"; exit 77; }
[ -e /dev/net/tun ] || { echo "skip - /dev/net/tun absent"; exit 77; }
ip netns list >/dev/null 2>&1 || { echo "skip - namespaces unavailable"; exit 77; }
[ -x "$NORR" ] || { echo "skip - binary not found at $NORR"; exit 77; }

ok()   { echo "ok   - $1"; PASS=$((PASS + 1)); }
bad()  { echo "FAIL - $1"; FAIL=$((FAIL + 1)); }

cleanup() {
  ip netns pids norr-a 2>/dev/null | xargs -r kill 2>/dev/null
  ip netns pids norr-b 2>/dev/null | xargs -r kill 2>/dev/null
  sleep 0.2
  ip netns del norr-a 2>/dev/null
  ip netns del norr-b 2>/dev/null
}
trap cleanup EXIT

cleanup
ip netns add norr-a || exit 1
ip netns add norr-b || exit 1

# The carrier: a veth pair joining the two namespaces. Norr's UDP travels here.
ip link add veth-a netns norr-a type veth peer name veth-b netns norr-b || exit 1
ip netns exec norr-a ip addr add 10.90.0.1/24 dev veth-a
ip netns exec norr-b ip addr add 10.90.0.2/24 dev veth-b
ip netns exec norr-a ip link set veth-a up
ip netns exec norr-b ip link set veth-b up
ip netns exec norr-a ip link set lo up
ip netns exec norr-b ip link set lo up

ip netns exec norr-a ping -c1 -W2 10.90.0.2 >/dev/null 2>&1 \
  && ok "carrier reachable" || { bad "carrier unreachable"; exit 1; }

mkdir -p /tmp/e2e
cd /tmp/e2e || exit 1

# Keys. keygen prints the private key on stdout and the public on stderr.
"$NORR" keygen >a.key 2>a.pub || { bad "keygen a"; exit 1; }
"$NORR" keygen >b.key 2>b.pub || { bad "keygen b"; exit 1; }
chmod 600 a.key b.key
A_PUB=$(awk '{print $2}' a.pub)
B_PUB=$(awk '{print $2}' b.pub)

[ ${#A_PUB} -eq 64 ] && ok "keygen produced a 64-char public key" \
  || { bad "keygen output malformed: '$A_PUB'"; exit 1; }

# A shared pre-shared key, as IKpsk2 requires.
PSK=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')

cat >a.toml <<EOF
[node]
role = "server"
listen_port = 51820
tun = "norrA"
[identity]
key_file = "/tmp/e2e/a.key"
[network]
address = "10.99.0.1/32"
[qos]
enabled = true
rate_bytes = 12500000
[observability]
metrics = true
listen = "127.0.0.1:19200"
[[peer]]
name = "b"
public_key = "$B_PUB"
preshared_key = "$PSK"
allowed_ips = "10.99.0.2/32"
EOF

cat >b.toml <<EOF
[node]
role = "client"
listen_port = 51821
tun = "norrB"
[identity]
key_file = "/tmp/e2e/b.key"
[network]
address = "10.99.0.2/32"
[qos]
enabled = true
rate_bytes = 12500000
[[peer]]
name = "a"
public_key = "$A_PUB"
preshared_key = "$PSK"
endpoint = "10.90.0.1:51820"
allowed_ips = "10.99.0.1/32"
EOF

"$NORR" check a.toml >/dev/null 2>&1 && ok "config a validates" || bad "config a rejected"
"$NORR" check b.toml >/dev/null 2>&1 && ok "config b validates" || bad "config b rejected"

# Start both nodes. B dials A, because only B has an endpoint configured.
ip netns exec norr-a "$NORR" run /tmp/e2e/a.toml >a.log 2>&1 &
ip netns exec norr-b "$NORR" run /tmp/e2e/b.toml >b.log 2>&1 &
sleep 1.5

ip netns exec norr-a ip link show norrA >/dev/null 2>&1 \
  && ok "node a created its TUN device" || { bad "node a has no TUN"; cat a.log; }
ip netns exec norr-b ip link show norrB >/dev/null 2>&1 \
  && ok "node b created its TUN device" || { bad "node b has no TUN"; cat b.log; }

# Inner addressing. Norr deliberately does not configure these itself, because
# doing so needs privileges the process drops at startup.
ip netns exec norr-a ip addr add 10.99.0.1/32 dev norrA 2>/dev/null
ip netns exec norr-a ip link set norrA up
ip netns exec norr-a ip route add 10.99.0.2/32 dev norrA 2>/dev/null

ip netns exec norr-b ip addr add 10.99.0.2/32 dev norrB 2>/dev/null
ip netns exec norr-b ip link set norrB up
ip netns exec norr-b ip route add 10.99.0.1/32 dev norrB 2>/dev/null

sleep 1

# The real test: an ICMP echo across the tunnel. This only succeeds if the
# handshake completed, a session was installed on both sides, and the datapath
# encrypted, carried, decrypted and wrote the packet.
if ip netns exec norr-b ping -c3 -W3 -I 10.99.0.2 10.99.0.1 >ping.log 2>&1; then
  ok "ICMP echo traversed the tunnel"

  # Cross the rekey timer. A tunnel that only works until its first rekey is
  # not a tunnel, and nothing short of waiting out the timer catches it: the
  # responder's replacement keys are held provisionally and expire unless the
  # initiator confirms them, which it only does by sending something.
  if [ "${NORR_SOAK:-0}" = "1" ]; then
    echo "soak: waiting ${NORR_SOAK_SECONDS:-150}s across the rekey timer"
    sleep "${NORR_SOAK_SECONDS:-150}"
    if ip netns exec norr-b ping -c5 -W3 -I 10.99.0.2 10.99.0.1 >ping2.log 2>&1; then
      ok "tunnel still carries traffic after rekey"
    else
      bad "tunnel died across rekey"
      tail -3 ping2.log
    fi
  fi
else
  bad "no ICMP echo across the tunnel"
  echo "--- ping ---"; cat ping.log
fi

echo "=== metrics scrape ==="
if ! command -v curl >/dev/null 2>&1; then
  echo "skip - curl absent, metrics endpoint not probed"
elif ip netns exec norr-a curl -s -m 3 http://127.0.0.1:19200/metrics 2>/dev/null \
     | grep -q "norr_packets_encrypted_total"; then
  ok "metrics endpoint served a scrape"
else
  bad "metrics endpoint did not answer"
fi

# Stop both nodes so they print their counters, which say how far the
# handshake got.
ip netns pids norr-a 2>/dev/null | xargs -r kill -TERM 2>/dev/null
ip netns pids norr-b 2>/dev/null | xargs -r kill -TERM 2>/dev/null
sleep 0.5
echo "--- a ---"; cat a.log
echo "--- b ---"; cat b.log

echo
echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
