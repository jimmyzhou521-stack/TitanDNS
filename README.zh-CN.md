<p align="center">
  <img src="www/logo.svg" alt="TitanDNS Logo" width="120" height="120">
</p>

<h1 align="center">TitanDNS</h1>

<p align="center">
  <b>新一代高性能 DNS 转发器，基于 Rust 和 eBPF 构建</b>
</p>

<p align="center">
  <a href="https://github.com/jimmyzhou521-stack/TitanDns/actions"><img src="https://github.com/jimmyzhou521-stack/TitanDns/actions/workflows/build.yml/badge.svg" alt="构建状态"></a>
  <a href="https://github.com/jimmyzhou521-stack/TitanDns/releases"><img src="https://img.shields.io/github/v/release/jimmyzhou521-stack/TitanDns" alt="版本"></a>
  <a href="https://github.com/jimmyzhou521-stack/TitanDns/releases"><img src="https://img.shields.io/github/downloads/jimmyzhou521-stack/TitanDns/total" alt="下载量"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="许可证"></a>
</p>

<p align="center">
  中文 | <a href="README.md">English</a>
</p>

---

## ✨ 功能特性

### 🚀 极致性能

- **高性能异步核心**：基于 Tokio 运行时构建
- **可选 eBPF/XDP 加速**：内核级 DNS 缓存，500万+ QPS
- **零拷贝解析**：优化内存分配
- **批量 I/O**：支持高吞吐场景

### 🔧 灵活扩展

- **插件化架构**：缓存、策略、Geo 规则、上游路由
- **配置热更新**：无需重启服务
- **多协议支持**：UDP、TCP、DoH、DoT、DoQ
- **SOCKS5 代理支持**：上游连接可走代理

### 🧠 智能分流

- **智能分流路由**：自动识别国内/国外流量
- **机器学习选择**：基于 Thompson Sampling 的上游选择
- **学习缓存**：域名分类自动学习并持久化
- **FakeIP 集成**：与 sing-box 无缝配合透明代理

### 🛡️ 安全防护

- **DNSSEC 验证**：支持 DNS 安全扩展
- **DGA 检测**：识别恶意软件生成的随机域名
- **AdGuard 广告拦截**：兼容 AdGuard 规则语法
- **速率限制**：防止 DNS 放大攻击

### 📊 可观测性

- **内置 Web 仪表盘**：监控和管理
- **Prometheus 指标**：无缝对接监控系统
- **详细查询日志**：包含拦截历史

---

## 📦 快速开始

### 一键安装（Linux）

```bash
curl -fsSL https://raw.githubusercontent.com/jimmyzhou521-stack/TitanDns/online/install.sh | bash
```

**支持平台：**

- Linux x86_64
- Linux x86_64-v3（Intel Haswell+、AMD Zen+）
- Linux arm64（树莓派 4、AWS Graviton）

安装完成后，编辑 `/etc/titandns/config.yaml` 以适配你的环境。

### 从源码编译

**前置要求：**

- Rust stable 工具链（1.70+）
- Linux 内核头文件（可选，用于 eBPF）

```bash
# 克隆仓库
git clone https://github.com/jimmyzhou521-stack/TitanDns.git
cd TitanDns

# 编译 release
cargo build --release

# 运行
./target/release/titandns --config config.example.yaml
```

---

## 🏗️ 系统架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        TitanDNS 核心                            │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │
│  │   UDP    │  │   TCP    │  │   DoH    │  │   Web 仪表盘     │ │
│  │  监听器  │  │  监听器  │  │  监听器  │  │  (端口 8080)     │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────────┬─────────┘ │
│       │             │             │                  │          │
│       └─────────────┴─────────────┴──────────────────┘          │
│                              │                                   │
│  ┌───────────────────────────▼───────────────────────────────┐  │
│  │                      插件流水线                            │  │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────┐   │  │
│  │  │  缓存   │→ │ GeoSite │→ │ 匹配器  │→ │ 智能分流    │   │  │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────────┘   │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              │                                   │
│  ┌───────────────────────────▼───────────────────────────────┐  │
│  │                       上游层                               │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │  │
│  │  │ UDP/TCP  │  │   DoH    │  │   DoT    │  │   DoQ    │   │  │
│  │  │ (直连)   │  │ (SOCKS5) │  │ (SOCKS5) │  │(SOCKS5)  │   │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              │                                   │
│  ┌───────────────────────────▼───────────────────────────────┐  │
│  │              eBPF/XDP 加速层（可选）                       │  │
│  │             内核级 DNS 缓存，超低延迟                      │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## ⚙️ 配置说明

TitanDNS 使用 YAML 配置格式。完整示例请参考 `config.example.yaml`。

### 配置结构

```yaml
log:           # 日志设置
api:           # 仪表盘和 API 设置
ebpf:          # eBPF/XDP 加速（仅 Linux）
plugins:       # 插件定义
sequences:     # 执行流水线
servers:       # 监听器定义
```

### 插件类型

| 插件 | 说明 |
|------|------|
| `cache` | 高性能 DNS 缓存，支持预取和过期服务 |
| `forward` | 上游 DNS 转发器（UDP/TCP/DoH/DoT/DoQ）|
| `geosite` | 基于 GeoSite 规则的域名分类 |
| `geoip` | 基于 MaxMind MMDB 的 IP 分类 |
| `matcher` | 域名模式匹配与标签 |
| `smart_forward` | 智能分流路由，带自动学习 |
| `adblock` | AdGuard 兼容的广告拦截 |
| `dnssec` | DNSSEC 验证 |
| `ecs` | EDNS 客户端子网注入 |
| `ratelimit` | 查询速率限制 |

### 配置示例：智能分流

```yaml
plugins:
  # 国内缓存
  cache_domestic:
    type: "cache"
    size: 100000

  # 代理缓存（FakeIP）
  cache_proxy:
    type: "cache"
    size: 100000
    fakeip_protection: true

  # 国内上游
  upstream_local:
    type: "forward"
    strategy: "race"
    upstreams:
      - addr: "udp://223.5.5.5:53"     # 阿里 DNS
      - addr: "udp://119.29.29.29:53"  # DNSPod

  # FakeIP 上游（sing-box）
  upstream_fakeip:
    type: "forward"
    upstreams:
      - addr: "udp://127.0.0.1:6666"

  # GeoSite 规则
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
    - exec: smart_splitter  # 兜底智能分流

  sequence_local:
    - exec: cache_domestic
    - exec: upstream_local

  sequence_proxy:
    - exec: cache_proxy
    - exec: upstream_fakeip
```

---

## 📊 Web 仪表盘

TitanDNS 内置 Web 仪表盘，用于监控和管理。

**访问地址：** `http://你的服务器:8080`

功能：

- 实时查询统计
- 上游健康监控
- 缓存命中率可视化
- 最近拦截记录
- 配置管理

---

## 🔧 规则更新

使用内置脚本自动更新 GeoSite、GeoIP 和 AdBlock 规则：

```bash
# 手动更新
/etc/titandns/update_rules.sh

# 安装每日自动更新（凌晨 02:00）
/etc/titandns/update_rules.sh --install
```

---

## 🏷️ 版本发布

创建并推送 git 标签以触发 GitHub Release：

```bash
git tag v1.0.2
git push origin v1.0.2
```

预编译二进制文件将在 Releases 页面提供。

---

## 🤝 贡献指南

欢迎贡献！请阅读：

- [CONTRIBUTING.md](CONTRIBUTING.md) - 贡献指南
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - 行为准则

---

## 🔒 安全

安全问题请参考 [SECURITY.md](SECURITY.md)。

---

## 📄 许可证

Apache-2.0，详见 [LICENSE](LICENSE)。

---

## 🙏 致谢

- [Tokio](https://tokio.rs/) - 异步运行时
- [hickory-dns](https://github.com/hickory-dns/hickory-dns) - DNS 协议库
- [sing-box](https://github.com/SagerNet/sing-box) - FakeIP 集成
- [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat) - GeoSite/GeoIP 规则
