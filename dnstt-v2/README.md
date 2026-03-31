# dnstt v2 (WIP)

This directory contains a new experimental on-the-wire protocol ("v2") that is
designed for high-loss, rate-limited UDP DNS paths.

Design goals:
- Maintain **server-side dual-stack**: v1 clients continue to work unmodified.
- Improve v2 goodput at small DNS payload sizes (e.g. server `-mtu 512`) via:
  batching, selective ACKs, pacing, and optional lightweight FEC.

NOTE: This is intentionally separate from the upstream dnstt protocol.

