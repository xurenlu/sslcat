---
title: Dynamic Domain / Tunnel Integration Overview
description: Overview of supported tunneling providers and integration requirements
date: 2025-11-07
---

# Dynamic Domain / Tunnel Integration Overview

SSLcat can orchestrate several popular tunneling providers to expose private services securely on the public internet. This document summarises the feature scope and alignment between providers.

## Provider Comparison

| Provider | Positioning | Key Advantages | Common Constraints |
| --- | --- | --- | --- |
| Cloudflare Tunnel | Zero-trust reverse proxy | Global CDN, built-in TLS, DDoS protection | Requires Cloudflare account/domain; free tier has session limits |
| ngrok | SaaS reverse proxy | Quick setup, HTTP/TCP support, built-in inspection | Free tier rate limits, shared domains, long sessions require paid plan |
| frp | Self-hosted tunnel | Open source, flexible configuration, multiple protocols | Requires running `frps`, lifecycle and monitoring handled by operator |
| PeanutHull (花生壳) | Commercial DDNS/tunnel | Strong coverage in mainland China, bundled domain offering | CLI resources limited, free tier bandwidth and ports constrained |

## CLI Dependencies

| Provider | Required Binary | Installation Notes | Runtime Notes |
| --- | --- | --- | --- |
| Cloudflare Tunnel | `cloudflared` | Official packages / Homebrew / Docker | Generates `credentials.json`; requires account authorisation |
| ngrok | `ngrok` | Download official archive or `brew install ngrok/ngrok` | Configure token via `ngrok config add-authtoken`; local API on `127.0.0.1:4040` |
| frp | `frpc` | Download release tarball / build from source | Works with `frps`; optional admin API for status (`admin_port`) |
| PeanutHull | `phddns` / `phtunnel` | Vendor-provided installer | Requires Oray account; CLI can emit JSON status |

## Unified Model

- **Credentials** – stored as key/value pairs, masked in UI, persisted encrypted when possible.
- **Provider options** – additional flags such as region, entrypoint, or concurrency limits.
- **Tunnels** – each record contains protocol, local endpoint, public hostname/port, optional notes and edge region hint.
- **Status lifecycle** – statuses surface as `disconnected`, `connecting`, `connected`, `error`, `unknown` with last error message and timestamp.
- **Process orchestration** – current implementation keeps state in memory; adapters will evolve to spawn/monitor provider binaries.

## Integration Notes

### Cloudflare Tunnel
- Requires tunnel credentials file (`cloudflared tunnel create`).
- DNS mapping via `cloudflared tunnel route dns` or API.
- Status introspection through `cloudflared tunnel info --output json` or metrics endpoint.

### ngrok
- Auth token stored in `~/.config/ngrok/ngrok.yml`.
- Supports per-tunnel configuration file mode; local REST API at `http://127.0.0.1:4040/api`.
- CLI command `ngrok api tunnels list` returns live sessions.

### frp (frpc)
- Client communicates with `frps` server; authentication via token or OIDC.
- Configuration uses INI/TOML sections per tunnel.
- Optional admin API exposes `/api/status` for realtime metrics.

### PeanutHull
- CLI `phddns` manages auth code and LAN mapping.
- Status available via `phddns status --json` (varies by version).
- Enterprise accounts expose additional REST APIs for automation.

## Future Extensions

- Tailscale Funnel / Serve, ZeroTier Moon integration, Teleport Application Access.
- Automatic DNS record provisioning tying into SSLcat DNS providers.
- Telemetry export to Prometheus / existing monitoring channels.

