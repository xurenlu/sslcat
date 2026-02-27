# HTTP/3 (QUIC) Troubleshooting

## Symptom: Alt-Svc Is Present but QUIC Connection Fails

When using tools like [http3check.net](https://http3check.net/), you may see:

- **Response headers** include `Alt-Svc: h3=":443"; ma=86400` (SSLcat has HTTP/3 enabled and advertises it)
- **Check result**: `QUIC connection could not be established`

So the client can reach SSLcat over TCP 443 (HTTPS works), but the **UDP 443** QUIC handshake fails.

## Common Causes and Fixes

### 1. Reverse Proxy / Load Balancer Not Forwarding UDP 443 (Most Common)

**Cause**: If Nginx, HAProxy, a cloud LB, or CDN sits in front of SSLcat, they often forward only **TCP 443**. **UDP 443** is not forwarded to SSLcat. QUIC uses UDP 443; if UDP never reaches SSLcat, HTTP/3 cannot work.

**Fix**:

- **Option A (recommended)**: On the proxy/LB, enable **UDP 443** forwarding to the host and port where SSLcat listens (e.g. same host, port 443), and allow UDP 443 in firewalls.
- **Option B**: If the proxy supports HTTP/3 (e.g. Nginx 1.25+, Cloudflare), you can terminate HTTP/3 at the proxy and use HTTP/2 or HTTP/1.1 to the backend; then you can disable HTTP/3 in SSLcat to avoid advertising it without supporting it.
- **Option C**: Temporarily disable HTTP/3 in SSLcat (Settings → SSL → uncheck “Enable HTTP/3”) so `Alt-Svc` is not sent and clients do not try QUIC.

### 2. Firewall or Security Group Blocking UDP 443

**Cause**: Only TCP 443 is allowed; UDP 443 is not.

**Fix**: Add an inbound rule for **UDP 443** on the host and/or cloud security group where SSLcat runs.

### 3. Docker / Kubernetes Not Exposing UDP 443

**Cause**: Only TCP 443 is published; UDP 443 is not.

**Fix**:

- **Docker**: Ensure port 443 is published for both TCP and UDP (e.g. `-p 443:443` often does both; if you mapped only TCP, add UDP).
- **Kubernetes**: Service must include a port 443 with `protocol: UDP`, and the node/network must allow UDP 443 to the pod.

### 4. UDP 443 In Use or Permission Denied on Host

**Cause**: Another process is bound to UDP 443, or the process has no permission to bind to 443.

**Fix**: On the SSLcat host, check what is using UDP 443 (e.g. `ss -ulnp | grep 443` or `lsof -i UDP:443`). Stop that process or change the port (and update Alt-Svc or proxy config if needed). If it’s a permission issue, run SSLcat with sufficient privileges or use capabilities (e.g. `setcap`).

### 5. HTTP/3 Server Fails to Start While Config Says Enabled

**Cause**: HTTP/3 is enabled in config but the HTTP/3 server fails to start (e.g. port in use, TLS config). Alt-Svc may still be sent based on config, so clients try QUIC and fail.

**Fix**: Check SSLcat logs for `HTTP/3 server error` or `Failed to start HTTP/3 server`. Fix the underlying issue (port, TLS, etc.). If you cannot fix it soon, disable HTTP/3 so clients are not told to use QUIC.

### 6. Client-Side VPN / Proxy (Clash, V2Ray, etc.)

**Cause**: The check runs from **your machine**. If your PC or gateway uses a VPN/proxy (e.g. Clash, V2Ray, Shadowsocks), many of these tools have **incomplete UDP or QUIC support**: they forward only TCP, or do not forward UDP 443, or do not support HTTP/3. Result: HTTPS (TCP 443) reaches SSLcat through the proxy, so you see Alt-Svc; but QUIC (UDP 443) is dropped or not forwarded, so http3check reports “QUIC connection could not be established”. **The issue is on the client path, not the SSLcat server.**

**Fix**:

- **Verify server**: Test from an environment **without** the proxy (e.g. another device on the same LAN, or on the server itself: `curl -sI --http3 https://your-domain`). If QUIC works without the proxy, the client-side proxy is the cause.
- **Accept it**: Browsers will fall back to HTTP/2 or HTTP/1.1; normal access is unaffected. Only http3check will keep failing from that network.
- **Optional**: To get QUIC working from that network, use a proxy/mode that forwards UDP or supports HTTP/3, or test with the proxy disabled.

## Quick Checklist

| Check | Notes |
|-------|--------|
| Proxy/LB in front? | Is **UDP 443** forwarded to SSLcat? |
| Client using VPN/proxy? | If the check goes through VPN/Clash/V2Ray, it may not forward UDP 443 → QUIC fails |
| Firewall / security group | Is **UDP 443** allowed inbound? |
| Containers / orchestration | Is **UDP 443** exposed? |
| Host port | Is UDP 443 free? Can SSLcat bind to it? |
| Logs | Any HTTP/3 startup or runtime errors? |

## Tools to Test HTTP/3 (curl-like)

From an environment **without** a proxy, you can use these CLI tools to verify that the server’s QUIC endpoint is reachable:

| Tool | Usage | Notes |
|------|--------|--------|
| **curl** | `curl -sI --http3 https://your-domain` | Requires curl 7.66+ built with HTTP/3 (ngtcp2 or quiche). Use `--http3-only` to disable fallback to HTTP/2/1.1. |
| **xh** | `xh -h3 https://your-domain` or `xh --http-version=3 https://your-domain` | Modern HTTPie-like CLI with HTTP/3 (rustls). Install: `cargo install xh` or system package manager. |
| **h2load** (nghttp2) | `h2load -n1 -c1 --npn-list=h3 https://your-domain` | For load/bench; can force ALPN to h3. Requires nghttp2 built with HTTP/3. |

- **curl**: Many distro builds do not include HTTP/3; you may need to build from source or use official binaries. See [curl HTTP/3 docs](https://curl.se/docs/http3.html).
- **xh**: Written in Rust; often supports HTTP/3 out of the box via rustls, good for quick manual tests.
- If these work without a proxy, the server’s HTTP/3 is fine; if they only fail when using a proxy, the client-side proxy likely doesn’t support QUIC.

## References

- [HTTP/3 Feasibility Analysis](./http3-feasibility-analysis.md)
- [RFC 9114 HTTP/3](https://www.rfc-editor.org/rfc/rfc9114)
- [QUIC RFC 9000](https://www.rfc-editor.org/rfc/rfc9000)
