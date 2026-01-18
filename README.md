<p align="center">
  <img src="www/logo.svg" alt="TitanDNS Logo" width="120" height="120">
</p>

<h1 align="center">TitanDNS</h1>

<p align="center">
  <b>A next-generation, high-performance DNS forwarder powered by Rust and eBPF</b>
</p>

<p align="center">
  <a href="https://github.com/jimmyzhou521-stack/TitanDns/actions"><img src="https://github.com/jimmyzhou521-stack/TitanDns/actions/workflows/build.yml/badge.svg" alt="Build Status"></a>
  <a href="https://github.com/jimmyzhou521-stack/TitanDns/releases"><img src="https://img.shields.io/github/v/release/jimmyzhou521-stack/TitanDns" alt="Release"></a>
  <a href="https://github.com/jimmyzhou521-stack/TitanDns/releases"><img src="https://img.shields.io/github/downloads/jimmyzhou521-stack/TitanDns/total" alt="Downloads"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License"></a>
</p>

<p align="center">
  <a href="README.zh-CN.md">中文</a> | English
</p>

---

## ✨ Features

### 🚀 Performance

- **High-performance async core** built on Tokio runtime
- **Optional eBPF/XDP acceleration** for kernel-level DNS caching (5M+ QPS)
- **Zero-copy parsing** with optimized memory allocation
- **Batch I/O** support for high-throughput scenarios

### 🔧 Flexibility

- **Pluggable pipeline architecture**: cache, policy, Geo rules, upstream routing
- **Hot configuration reload** without service restart
- **Multiple protocols**: UDP, TCP, DoH (DNS-over-HTTPS), DoT (DNS-over-TLS), DoQ (DNS-over-QUIC)
- **SOCKS5 proxy support** for upstream connections

### 🧠 Intelligence

- **Smart split routing**: Automatic domestic/foreign traffic classification
- **Machine learning-based upstream selection** with Thompson Sampling
- **Learning cache**: Domain classification learning and persistence
- **FakeIP integration** with sing-box for transparent proxy

### 🛡️ Security

- **DNSSEC validation** support
- **DGA detection** for malware domain identification
- **AdGuard-compatible AdBlock** rules
- **Rate limiting** and query logging

### 📊 Observability

- **Built-in Web Dashboard** for monitoring and management
- **Prometheus metrics** integration
- **Detailed query logging** with blocking history

---

## 📦 Quick Start

### One-click Install (Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/jimmyzhou521-stack/TitanDns/online/install.sh | bash
```

**Supported platforms:**

- Linux x86_64
- Linux x86_64-v3 (Intel Haswell+, AMD Zen+)
- Linux arm64 (Raspberry Pi 4, AWS Graviton)

After installation, edit `/etc/titandns/config.yaml` to fit your environment.

### Build from Source

**Prerequisites:**

- Rust stable toolchain (1.70+)
- Linux kernel headers (optional, for eBPF)

```bash
# Clone repository
git clone https://github.com/jimmyzhou521-stack/TitanDns.git
cd TitanDns

# Build release
cargo build --release

# Run
./target/release/titandns --config config.example.yaml
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        TitanDNS Core                            │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │
│  │   UDP    │  │   TCP    │  │   DoH    │  │  Web Dashboard   │ │
│  │ Listener │  │ Listener │  │ Listener │  │   (Port 8080)    │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────────┬─────────┘ │
│       │             │             │                  │          │
│       └─────────────┴─────────────┴──────────────────┘          │
│                              │                                   │
│  ┌───────────────────────────▼───────────────────────────────┐  │
│  │                    Plugin Pipeline                         │  │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────┐   │  │
│  │  │  Cache  │→ │ GeoSite │→ │ Matcher │→ │SmartForward │   │  │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────────┘   │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              │                                   │
│  ┌───────────────────────────▼───────────────────────────────┐  │
│  │                    Upstream Layer                          │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │  │
│  │  │UDP/TCP   │  │   DoH    │  │   DoT    │  │   DoQ    │   │  │
│  │  │(Direct)  │  │ (SOCKS5) │  │ (SOCKS5) │  │(SOCKS5)  │   │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              │                                   │
│  ┌───────────────────────────▼───────────────────────────────┐  │
│  │              eBPF/XDP Acceleration (Optional)              │  │
│  │         Kernel-level DNS cache for ultra-low latency       │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## ⚙️ Configuration

TitanDNS uses YAML configuration format. See `config.example.yaml` for a complete example.

### Configuration Structure

```yaml
log:           # Logging settings
api:           # Dashboard & API settings  
ebpf:          # eBPF/XDP acceleration (Linux only)
plugins:       # Plugin definitions
sequences:     # Execution pipelines
servers:       # Listener definitions
```

### Plugin Types

| Plugin | Description |
|--------|-------------|
| `cache` | High-performance DNS cache with prefetch and stale-serve |
| `forward` | Upstream DNS forwarder (UDP/TCP/DoH/DoT/DoQ) |
| `geosite` | Domain classification based on GeoSite rules |
| `geoip` | IP classification based on MaxMind MMDB |
| `matcher` | Domain pattern matching with tagging |
| `smart_forward` | Intelligent split routing with learning |
| `adblock` | AdGuard-compatible ad blocking |
| `dnssec` | DNSSEC validation |
| `ecs` | EDNS Client Subnet injection |
| `ratelimit` | Query rate limiting |

### Example: Smart Split Routing

```yaml
plugins:
  # Domestic cache
  cache_domestic:
    type: "cache"
    size: 100000

  # Proxy cache (FakeIP)
  cache_proxy:
    type: "cache"
    size: 100000
    fakeip_protection: true

  # Domestic upstream
  upstream_local:
    type: "forward"
    strategy: "race"
    upstreams:
      - addr: "udp://223.5.5.5:53"
      - addr: "udp://119.29.29.29:53"

  # FakeIP upstream (sing-box)
  upstream_fakeip:
    type: "forward"
    upstreams:
      - addr: "udp://127.0.0.1:6666"

  # GeoSite rules
  geosite_cn:
    type: "geosite"
    target: "cn"
    files:
      - "/etc/titandns/geosite.dat:cn"
    mark: "cn"

  geosite_proxy:
    type: "geosite"
    target: "proxy"
    files:
      - "/etc/titandns/geosite.dat:gfw"
    mark: "proxy"

sequences:
  sequence_main:
    - exec: geosite_cn
    - exec: geosite_proxy
    - matches: [{ has_tag: "cn" }]
      exec: sequence_local
    - matches: [{ has_tag: "proxy" }]
      exec: sequence_proxy
    - exec: smart_splitter  # fallback

  sequence_local:
    - exec: cache_domestic
    - exec: upstream_local

  sequence_proxy:
    - exec: cache_proxy
    - exec: upstream_fakeip
```

---

## 📊 Web Dashboard

TitanDNS includes a built-in web dashboard for monitoring and management.

**Access:** `http://your-server:8080`

Features:

- Real-time query statistics
- Upstream health monitoring
- Cache hit rate visualization
- Recent blocked queries
- Configuration management

---

## 🔧 Rule Updates

Use the included script to automatically update GeoSite, GeoIP, and AdBlock rules:

```bash
# Manual update
/etc/titandns/update_rules.sh

# Install daily auto-update (02:00 AM)
/etc/titandns/update_rules.sh --install
```

---

## 🏷️ Releases

Create and push a git tag to trigger a GitHub Release:

```bash
git tag v1.0.3
git push origin v1.0.3
```

Pre-built binaries will be available in the Releases page.

---

## 🤝 Contributing

We welcome contributions! Please read:

- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - Code of conduct

---

## 🔒 Security

For security issues, please refer to [SECURITY.md](SECURITY.md).

---

## 📄 License

Apache-2.0. See [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- [Tokio](https://tokio.rs/) - Async runtime
- [hickory-dns](https://github.com/hickory-dns/hickory-dns) - DNS protocol library
- [sing-box](https://github.com/SagerNet/sing-box) - FakeIP integration
- [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat) - GeoSite/GeoIP rules
