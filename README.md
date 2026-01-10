# TitanDNS

[中文](README.zh-CN.md) | English

TitanDNS is a high-performance DNS forwarder written in Rust, with optional eBPF acceleration on Linux.
This repository is published from the `online` branch and only includes the minimal public source set:
`src/`, `bpf/`, `www/`, and `Cargo.toml`.

## Highlights

- High-performance async core (Tokio)
- Pluggable pipeline: cache, policy, Geo rules, and upstream routing
- Hot reload for configuration
- Optional eBPF fast-path acceleration (Linux)
- Web UI assets included in `www/`
- Metrics-friendly design (Prometheus)

## Typical Use Cases

- Home / lab DNS gateway with smart split routing
- Edge / enterprise DNS forwarder with caching and policy control
- Multi-upstream resolver with DoH/DoT and SOCKS support

## Architecture (Simplified)

1. Receive DNS query (UDP/TCP/DoH)
2. Preprocess and normalize
3. Run sequence pipeline (cache / rules / geo / upstream)
4. Build response + optional caching
5. Emit response + metrics

## Build

Prerequisites:
- Rust stable toolchain
- Linux kernel headers if you want to build eBPF programs (optional)

Build release:

```
cargo build --release
```

## Run

You must provide your own config file (configs are intentionally not committed):

```
./target/release/titandns --config /path/to/config.yaml
```

Sample config (sanitized): `config.example.yaml`.

## One-click Install (Linux)

```
curl -fsSL https://raw.githubusercontent.com/jimmyzhou521-stack/TitanDns/online/install.sh | bash
```

The installer downloads the latest GitHub Release and runs the bundled `install.sh`.
After install, edit `/etc/titandns/config.yaml` to fit your environment.

Supported: Linux x86_64, x86_64-v3, and arm64 (auto-detected).

The installer verifies SHA256 checksums when `SHA256SUMS.txt` is present in the Release.

## Configuration (Overview)

Config format is YAML and typically contains:

- Global settings: `log`, `api`, `ebpf`
- `plugins`: named plugin blocks (cache / forward / geo / matcher / etc.)
- `sequences`: ordered execution chains
- `servers`: listener definitions (UDP / TCP / HTTP)

### Example 1: Minimal UDP + Cache + Upstream

```
log:
  level: "info"

plugins:
  cache_main:
    type: "cache"
    size: 100000
    prefetch_if_ttl_less_than: 240
    serve_stale_ttl: 120

  upstream_default:
    type: "forward"
    strategy: "smart"
    timeout_ms: 2000
    upstreams:
      - addr: "udp://1.1.1.1:53"

sequences:
  sequence_main:
    - exec: cache_main
    - exec: upstream_default

servers:
  - protocol: udp
    addr: "0.0.0.0:53"
    entry: sequence_main
```

### Example 2: Smart Split (Domestic vs Proxy)

```
plugins:
  cache_domestic:
    type: "cache"
    size: 100000

  cache_proxy:
    type: "cache"
    size: 100000

  upstream_local:
    type: "forward"
    strategy: "smart"
    upstreams:
      - addr: "udp://223.5.5.5:53"
      - addr: "udp://119.29.29.29:53"

  upstream_fakeip:
    type: "forward"
    strategy: "smart"
    upstreams:
      - addr: "https://1.1.1.1/dns-query"
        socks5: "127.0.0.1:7891"

  geosite_cn:
    type: "geosite"
    file: "/etc/titandns/geosite_cn.txt"
    tag: "cn"

  matcher_proxy:
    type: "matcher"
    file: "/etc/titandns/greylist.txt"
    tag: "proxy"

sequences:
  sequence_main:
    - exec: geosite_cn
    - exec: matcher_proxy
    - matches: [{ has_tag: "proxy" }]
      exec: sequence_proxy
    - matches: [{ has_tag: "cn" }]
      exec: sequence_local
    - exec: upstream_local  # fallback

  sequence_local:
    - exec: cache_domestic
    - exec: upstream_local

  sequence_proxy:
    - exec: cache_proxy
    - exec: upstream_fakeip

servers:
  - protocol: udp
    addr: "0.0.0.0:53"
    entry: sequence_main
```

### Example 3: DoH / DoT Upstreams

```
plugins:
  upstream_secure:
    type: "forward"
    strategy: "smart"
    timeout_ms: 5000
    upstreams:
      - addr: "https://1.1.1.1/dns-query"
        socks5: "127.0.0.1:7891"
      - addr: "tls://1.1.1.1:853"
        socks5: "127.0.0.1:7891"
```

### Example 4: eBPF (Linux)

```
ebpf:
  interface: "eth0"
  bpf_path: "/etc/titandns/titan_dns_filter.o"
  xdp_cache:
    enabled: true
    size: 1000000
```

## Web UI

Static assets are provided in `www/`. You can serve them via your own web server or integrate
with the TitanDNS HTTP endpoint (if enabled in your configuration).

## CI / Build Artifacts

On every push to `online`, GitHub Actions builds release binaries and uploads packaged artifacts
(containing `titandns` + `www/` + `bpf/`). Artifact naming:
`titandns-<version>-<date>-<os>.tar.gz` where `<version>` comes from `Cargo.toml`
and `<date>` is in `YYYYMMDD`.

## Release (Tags)

Create a git tag like `v1.0.0` and push it to trigger a GitHub Release:

```
git tag v1.0.0
git push origin v1.0.0
```

## Contributing

See `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md`.

## Security

Please report security issues via `SECURITY.md`.

## License

Apache-2.0. See `LICENSE`.
