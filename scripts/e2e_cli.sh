#!/bin/bash
set -u

NORR="${NORR:-/tmp/b/norrd}"
CLI="${CLI:-$(cd "$(dirname "$0")" && pwd)/norr}"
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
  for ns in cli-a cli-b; do ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null; done
  sleep 0.2
  ip netns del cli-a 2>/dev/null
  ip netns del cli-b 2>/dev/null
}
trap cleanup EXIT
cleanup

ip netns add cli-a && ip netns add cli-b || exit 1
ip link add cva netns cli-a type veth peer name cvb netns cli-b || exit 1
ip netns exec cli-a ip addr add 10.29.0.1/24 dev cva
ip netns exec cli-b ip addr add 10.29.0.2/24 dev cvb
for ns in cli-a cli-b; do ip netns exec $ns ip link set lo up; done
ip netns exec cli-a ip link set cva up
ip netns exec cli-a sysctl -qw net.ipv4.icmp_echo_ignore_all=1
ip netns exec cli-b ip link set cvb up

WORK=/tmp/e2e-cli
mkdir -p "$WORK/a" "$WORK/b"
export NORRD="$NORR" NO_COLOR=1

bring_up() {
  local ns=$1 conf=$2 tun address
  tun=$(awk -F'"' '/^tun *=/ {print $2; exit}' "$conf")
  address=$(awk -F'"' '/^address *=/ {print $2; exit}' "$conf")
  ip netns exec "$ns" ip addr add "$address" dev "$tun" 2>/dev/null
  ip netns exec "$ns" ip link set "$tun" up
}

for kind in udp tcp camo icmp; do
  NORR_CONFIG_DIR="$WORK/a" "$CLI" server --transport "$kind" --public-ip 10.29.0.1 --name "s$kind" --no-start \
    >"$WORK/server-$kind.out" 2>&1 || { bad "$kind: norr server failed"; cat "$WORK/server-$kind.out"; continue; }
  CODE=$(grep -oE 'norr:[A-Za-z0-9_-]+' "$WORK/server-$kind.out" | head -1)
  [ -n "$CODE" ] || { bad "$kind: no join code printed"; continue; }
  NORR_CONFIG_DIR="$WORK/b" "$CLI" client --name "c$kind" --no-start "$CODE" \
    >"$WORK/client-$kind.out" 2>&1 || { bad "$kind: norr client failed"; cat "$WORK/client-$kind.out"; continue; }

  grep -q "mode = \"$( [ "$kind" = udp ] && echo udp || { [ "$kind" = icmp ] && echo icmp || echo tcp-tls; })\"" \
    "$WORK/b/c$kind.toml" && ok "$kind: the join code carried the transport to the client" \
    || bad "$kind: client config has the wrong transport"

  ip netns exec cli-a "$NORR" run "$WORK/a/s$kind.toml" >"$WORK/a-$kind.log" 2>&1 &
  ip netns exec cli-b "$NORR" run "$WORK/b/c$kind.toml" >"$WORK/b-$kind.log" 2>&1 &
  sleep 2
  bring_up cli-a "$WORK/a/s$kind.toml"
  bring_up cli-b "$WORK/b/c$kind.toml"

  PEER=$(awk -F'"' '/^address *=/ {print $2; exit}' "$WORK/a/s$kind.toml"); PEER=${PEER%/*}
  ip netns exec cli-a nc -lk -s "$PEER" -p 7777 >/dev/null 2>&1 &
  UP=0
  for _ in $(seq 1 15); do
    if ip netns exec cli-b timeout 2 bash -c "echo > /dev/tcp/$PEER/7777" 2>/dev/null; then UP=1; break; fi
    sleep 1
  done
  [ "$UP" -eq 1 ] && ok "$kind: a tunnel made by norr server/client carries traffic" \
    || { bad "$kind: no traffic through the generated tunnel"; tail -3 "$WORK/a-$kind.log" "$WORK/b-$kind.log"; }

  for ns in cli-a cli-b; do ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null; done
  sleep 0.5
done

NAMES=$(NORR_CONFIG_DIR="$WORK/b" "$CLI" tunnels --machine | awk '{print $3}' | sort | tr '\n' ' ')
[ "$NAMES" = "camo icmp tcp udp " ] && ok "tunnels --machine reports every transport" \
  || bad "tunnels --machine reported: $NAMES"

echo
echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
