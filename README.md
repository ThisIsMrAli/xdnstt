# DNSTT (SlipNet Fork)

A hardened fork of [dnstt](https://www.bamsoftware.com/software/dnstt/) — a userspace DNS tunnel with DoH, DoT, and UDP support.

This fork is maintained by [SlipNet](https://github.com/anonvector/SlipNet) and includes significant modifications for production use in censorship-resistant networking.

## Changes from upstream

Based on [tladesignz/dnstt](https://github.com/tladesignz/dnstt) (itself a fork of [David Fifield's original](https://www.bamsoftware.com/software/dnstt/)).

Key modifications in this fork:

- **Server hardening** — session/stream limits, client eviction, removed PT dependency
- **Extracted server core into a reusable library** with pluggable hooks
- **TXT-only mode** — removed A-record/AAAA anti-filter mode for simplicity
- **Configurable query rate and retry settings** for mobile optimization
- **Battery optimization** — reduced DoH senders from 32 to 12
- **Graceful shutdown** — suppressed closed-connection errors during teardown
- **Fixed sendLoop** retrying forever on closed transport

## License

This fork is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

The original dnstt code by David Fifield is public domain (CC0). The upstream fork by tladesignz is also CC0. This fork relicenses the combined work under AGPL-3.0 to ensure that modifications to this code — including use over a network — remain open source.

See [COPYING](COPYING) for the full license text.

## Overview

dnstt is a DNS tunnel with these features:
 * Works over DNS over HTTPS (DoH) and DNS over TLS (DoT) as well as
   plaintext UDP DNS.
 * Embeds a sequencing and session protocol (KCP/smux), which means that
   the client does not have to wait for a response before sending more
   data, and any lost packets are automatically retransmitted.
 * Encrypts the contents of the tunnel and authenticates the server by
   public key.

dnstt is an application-layer tunnel that runs in userspace. It doesn't
provide a TUN/TAP interface; it only hooks up a local TCP port with a
remote TCP port (like netcat or `ssh -L`) by way of a DNS resolver.

```
.------.  |            .---------.             .------.
|tunnel|  |            | public  |             |tunnel|
|client|<---DoH/DoT--->|recursive|<--UDP DNS-->|server|
'------'  |c           |resolver |             '------'
   |      |e           '---------'                |
.------.  |n                                   .------.
|local |  |s                                   |remote|
| app  |  |o                                   | app  |
'------'  |r                                   '------'
```

## Usage

Refer to the original [dnstt documentation](https://www.bamsoftware.com/software/dnstt/) for general setup instructions (DNS zone, server/client configuration, proxy setup).

### UDP mode notes (censorship-heavy networks)

This fork contains a suite of hardening improvements specifically for plain UDP DNS, the transport that survives in the most hostile filtering environments.

#### Anti-blocking features

| Feature | What it does |
|---|---|
| **Per-query socket** | Each DNS query uses a fresh UDP socket (random source port), defeating 4-tuple-based blocking by DPI/firewalls |
| **Resolver health tracking** | Consecutive failures trigger exponential back-off per resolver; all others are tried first |
| **Domain rotation** | Use `domains=` to list multiple tunnel domains — one is picked randomly per connection so blocking one domain cannot kill the tunnel |
| **KCP fast mode** | UDP mode runs KCP in no-delay/20ms/fast-resend mode, halving effective RTT under packet loss |
| **Adaptive EDNS0 probing** | Client starts at 512 bytes (safe) and automatically promotes to 1232 or 4096 when the path proves it can carry larger DNS responses — no manual tuning needed |
| **Poll jitter + burst** | Idle polling is shaped into random bursts mimicking real browser DNS patterns to defeat timing-based DPI fingerprints |
| **TTL randomization** | Server varies each DNS answer TTL ±20% around 60 s to prevent caching/DPI fingerprinting on fixed TTL values |

#### Pluggable transport arguments for UDP mode

```
udp=1.1.1.1:53,8.8.8.8:53     resolver list (round-robin, health-tracked)
domains=t.example.com,t2.example.com   random domain per connection
edns0=512                       starting EDNS0 size (default 512; probed upward automatically)
probeedns0=true|false           enable adaptive EDNS0 probing (default true)
cover=true|false                mix A/AAAA cover queries into idle polls (default true)
udpsenders=6                    concurrent per-query sender goroutines (default 6)
udptimeoutms=3000               per-query read deadline in ms (default 3000)
jitter=true|false               poll timer jitter (default true)
burst=true|false                burst-mode idle polling (default true; requires jitter)
```

#### Metrics

When using UDP mode, the client logs a stats line every 60 seconds:
```
[metrics] queries Δ+42/+40 (Σ1200/1180) | bytes Δ+18.3KB/+91.2KB | edns0: 1232
```
This shows delta and cumulative query counts (sent/received), bytes (upload/download), and the current adaptive EDNS0 size.

## Encryption

The tunnel uses Noise_NK_25519_ChaChaPoly_BLAKE2s for end-to-end encryption between client and server, independent of the DoH/DoT transport layer.

```
application data
smux
Noise
KCP
DNS messages
DoH / DoT / UDP DNS
```
