# Benchmark Methodology

Compare:
- direct Linux forwarding/routing baseline
- WireGuard
- Backhaul
- Norr

Variables:
- 1 / 10 / 100 / 1k / 10k flows
- 0 / 0.1 / 0.5 / 1 / 2 / 5% loss
- 20 / 50 / 100 / 200 ms RTT
- small / mixed / large packets

Metrics:
- Gbps
- packets/s
- CPU%
- CPU/Gbps
- memory
- p50/p95/p99 latency
- jitter
- loss
