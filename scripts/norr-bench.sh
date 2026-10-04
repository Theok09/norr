#!/bin/bash
# Measures each Norr transport's real throughput and latency over the live
# tunnel pair, plus the raw inter-server path as a ceiling. Run from the
# client (ir) side; it drives an iperf3 server started on the peer (ex2).
# Read-only: it adds no config and restarts nothing.
set -u

PEER_SSH="${PEER_SSH:-}"           # ssh target for the server side (ex2)
PEER_PUBLIC="${PEER_PUBLIC:-}"     # ex2 public IP for the raw baseline
DUR="${DUR:-10}"
IPERF_PORT=5399

command -v iperf3 >/dev/null || { echo "iperf3 missing on client"; exit 1; }
[ -n "$PEER_SSH" ] || { echo "set PEER_SSH to the server's ssh target"; exit 1; }

# transport -> inner server IP, learned from the live configs
declare -A PEERIP
while read -r name role kind peer port tun; do
  [ "$role" = client ] || continue
  PEERIP[$kind]=$peer
done < <(norr tunnels --machine 2>/dev/null)

start_server() {
  ssh $PEER_SSH "pkill -f 'iperf3 -s -p $IPERF_PORT' 2>/dev/null; nohup iperf3 -s -p $IPERF_PORT >/tmp/ipf.log 2>&1 </dev/null & sleep 1" 2>/dev/null
}
stop_server() { ssh $PEER_SSH "pkill -f 'iperf3 -s -p $IPERF_PORT'" 2>/dev/null; }

rate() {  # $1 = target ip, $2 = extra iperf flags; echoes "Mbit/s"
  iperf3 -c "$1" -p $IPERF_PORT -t "$DUR" -f m $2 2>/dev/null \
    | awk '/receiver/ {print $7" "$8}' | tail -1
}
jitter() {  # iperf UDP jitter/loss as a latency-health proxy
  iperf3 -c "$1" -p $IPERF_PORT -u -b 50M -t 4 -f m 2>/dev/null     | awk '/receiver/ {print $9" "$10}' | tail -1
}

printf '\n%-10s %-16s %-14s %-14s %s\n' TRANSPORT PEER UP DOWN UDP-JITTER/LOSS
printf '%.0s-' {1..70}; printf '\n'

start_server
trap stop_server EXIT

# raw path ceiling (no tunnel), if we have the public IP reachable for iperf
if [ -n "$PEER_PUBLIC" ]; then
  ssh $PEER_SSH "iptables -I INPUT -p tcp --dport $IPERF_PORT -j ACCEPT 2>/dev/null" 2>/dev/null
  up=$(rate "$PEER_PUBLIC"); down=$(rate "$PEER_PUBLIC" -R)
  printf '%-10s %-16s %-14s %-14s %s\n' "raw" "$PEER_PUBLIC" "${up:-n/a}" "${down:-n/a}" "$(jitter "$PEER_PUBLIC")"
fi

for t in udp tcp camo icmp; do
  ip=${PEERIP[$t]:-}
  [ -z "$ip" ] && continue
  up=$(rate "$ip")
  down=$(rate "$ip" -R)
  printf '%-10s %-16s %-14s %-14s %s\n' "$t" "$ip" "${up:-FAIL/reset}" "${down:-FAIL/reset}" "$(jitter "$ip")"
done
echo
