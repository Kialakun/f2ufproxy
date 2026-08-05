# **Forward Proxy to Upstrean Forward Proxy - Proxy**

A flexible Go-based HTTP proxy server that can forward both **HTTP** and **HTTPS** (CONNECT) requests to an upstream proxy server (e.g., Squid, HAProxy, or another forward proxy).  
It supports **basic authentication** for the upstream proxy and works as a transparent intermediary for any HTTP/HTTPS client.

---

## Features

- **HTTP & HTTPS support** – handles both plain HTTP requests and CONNECT tunnelling for HTTPS.
- **Upstream proxy chaining** – forwards all requests to an upstream proxy (e.g., corporate proxy, Squid, or a proxy in another network).
- **Basic authentication** – automatically adds `Proxy-Authorization: Basic ...` headers to the upstream proxy.
- **Transparent operation** – acts as a standard forward proxy; clients only need to set the proxy address.
- **Bidirectional TCP copy** – for CONNECT tunnels, data is streamed in both directions without buffering.
- **No external dependencies** – built with the Go standard library only.
