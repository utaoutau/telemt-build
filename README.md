# Telemt - MTProxy on Rust + Tokio

**Telemt** is a fast, secure, and feature-rich server written in Rust: it fully implements the official Telegram proxy algo and adds many production-ready improvements such as connection pooling, replay protection, detailed statistics, masking from "prying" eyes

# GOTO
- [Features](#features)
- [Quick Start Guide](#quick-start-guide)
  - [Build](#build)
- [How to use?](#how-to-use)
  - [Systemd Method](#telemt-via-systemd)
- [Why Rust?](#why-rust)

## Features

- Full support for all official MTProto proxy modes:
  - Classic
  - Secure - with `dd` prefix
  - Fake TLS - with `ee` prefix + SNI fronting
- Replay attack protection
- Optional traffic masking: forward unrecognized connections to a real web server, e.g. GitHub 🤪
- Configurable keepalives + timeouts + IPv6 and "Fast Mode"
- Graceful shutdown on Ctrl+C
- Extensive logging via `trace` and `debug` with `RUST_LOG` method

## Quick Start Guide

### Build
```bash
# Cloning repo
git clone https://github.com/telemt/telemt 
# Changing Directory to telemt
cd telemt
# Starting Release Build
cargo build --release
# Move to /bin
mv ./target/release/telemt /bin
# Make executable
chmod +x /bin/telemt
# Lets go!
telemt config.toml
```

## How to use?
### Telemt via Systemd
1. Place your config to /etc/telemt.toml
2. Create service on /etc/systemd/system/telemt.service
```bash
[Unit]
Description=Telemt
After=network.target

[Service]
Type=simple
WorkingDirectory=/bin
ExecStart=/bin/telemt /etc/telemt.toml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
3. In Shell type `systemctl start telemt` - it must start with zero exit-code
4. In Shell type `systemctl status telemt` - there you can reach info about current MTProxy status
5. In Shell type `systemctl enable telemt` - then telemt will start with system startup, after the network is up

## Why Rust?
- Long-running reliability and idempotent behavior
- Rust’s deterministic resource management - RAII 
- No garbage collector
- Memory safety and reduced attack surface
- Tokio's asynchronous architecture

## Roadmap
- Public IP in links
- Config Reload-on-fly
- Bind to device or IP for outbound/inbound connections
- Adtag Support per SNI / Secret
- Fail-fast on start + Fail-soft on runtime (only WARN/ERROR)
- Zero-copy, minimal allocs on hotpath
- DC Healthchecks + global fallback
- No global mutable state
- Client isolation + Fair Bandwidth
- Backpressure-aware IO
- "Secret Policy" - SNI / Secret Routing :D
- Multi-upstream Balancer and Failover
- Strict FSM per handshake
- Session-based Antireplay with Sliding window, non-broking reconnects
- Web Control: statistic, state of health, latency, client experience...
