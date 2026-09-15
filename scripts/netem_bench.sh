#!/bin/bash
# Gates E and F on a path impaired by the kernel.
#
# The two endpoints MUST live in different network namespaces. With both
# addresses in one namespace the kernel routes locally through loopback and
# never touches the veth, so any qdisc on it is silently ignored. An earlier
# version of this script did exactly that and reported 0% loss at every
# configured rate; the figures were meaningless.
#
# Run with: docker run --rm --privileged --device=/dev/net/tun \
#   -v "$PWD":/src -w /src silkeh/clang:19 bash scripts/netem_bench.sh
set -e

apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq cmake ninja-build pkg-config libsodium-dev iproute2 iputils-ping >/dev/null 2>&1

BUILD=/tmp/netem-build
cmake -S . -B "$BUILD" -G Ninja -DCMAKE_BUILD_TYPE=Release >/dev/null 2>&1
cmake --build "$BUILD" >/dev/null 2>&1

setup_link() {
  ip netns del nsB 2>/dev/null || true
  ip link del vnorr0 2>/dev/null || true

  mkdir -p /var/run/netns
  mount --bind /var/run/netns /var/run/netns 2>/dev/null || true

  ip netns add nsB
  ip link add vnorr0 type veth peer name vnorr1
  ip link set vnorr1 netns nsB
  ip addr add 10.90.0.1/24 dev vnorr0
  ip link set vnorr0 up
  ip netns exec nsB ip addr add 10.90.0.2/24 dev vnorr1
  ip netns exec nsB ip link set vnorr1 up
  ip netns exec nsB ip link set lo up
}

impair() {
  tc qdisc del dev vnorr0 root 2>/dev/null || true
  ip netns exec nsB tc qdisc del dev vnorr1 root 2>/dev/null || true
  if [ -n "$1" ]; then
    # Applied in both directions so a round trip sees the impairment twice,
    # which is what a real path does.
    #
    # The queue limit must be raised well above the default 1000 packets. On a
    # delayed path the bandwidth-delay product exceeds that instantly, and the
    # qdisc then drops the overflow: an earlier run reported 60% "loss" on a
    # 20ms path that was configured to drop nothing at all. Those were real
    # kernel drops, but caused by this qdisc rather than by the tunnel.
    tc qdisc add dev vnorr0 root netem limit 100000 $1
    ip netns exec nsB tc qdisc add dev vnorr1 root netem limit 100000 $1
  fi
}

setup_link

echo "=== link verification ==="
ping -c 5 -i 0.01 -W 1 10.90.0.2 2>&1 | tail -2

echo ""
echo "=== netem verification: 50% loss must actually drop ==="
impair "loss 50%"
ping -c 100 -i 0.01 -W 1 10.90.0.2 2>&1 | tail -2
impair ""

run_case() {
  local label="$1"
  local settings="$2"
  impair "$settings"

  ip netns exec nsB "$BUILD/norr_bench_netem" responder 10.90.0.2 51999 >/dev/null 2>&1 &
  local responder_pid=$!
  sleep 1

  "$BUILD/norr_bench_netem" initiator 10.90.0.1 10.90.0.2 51999 "$label" 2>&1 | \
    grep -E "gate E|gate F"

  kill "$responder_pid" 2>/dev/null || true
  wait "$responder_pid" 2>/dev/null || true
}

echo ""
echo "############ BASELINE: clean path ############"
run_case "clean" ""

for loss in 0.5 1 2 5; do
  echo ""
  echo "############ GATE F: ${loss}% loss each way ############"
  run_case "loss ${loss}%" "loss ${loss}%"
done

echo ""
echo "############ GATE E: 20ms RTT with jitter ############"
run_case "delay 10ms 2ms" "delay 10ms 2ms"

impair ""
echo ""
echo "done"
