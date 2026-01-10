# TitanDNS

中文 | [English](README.md)

TitanDNS 是一个基于 Rust 的高性能 DNS 转发器，支持 Linux 下的可选 eBPF 加速。
本仓库发布自 `online` 分支，仅包含对外开源的最小源码集：
`src/`、`bpf/`、`www/`、`Cargo.toml`。

## 项目特点

- 高性能异步核心（Tokio）
- 插件化链路：缓存、策略、Geo 规则、上游路由
- 配置热更新
- 可选 eBPF 快路径加速（Linux）
- Web UI 资源（`www/`）
- 指标体系友好（Prometheus）

## 典型场景

- 家庭 / 自建网络的智能分流 DNS
- 企业边缘 DNS 转发与缓存
- 多上游 DoH/DoT 转发与策略控制

## 架构（简化流程）

1. 接收 DNS 请求（UDP/TCP/DoH）
2. 预处理与标准化
3. 执行插件序列（缓存 / 规则 / Geo / 上游）
4. 生成响应 + 可选缓存
5. 输出响应 + 指标采集

## 编译

依赖：
- Rust stable 工具链
- 如需编译 eBPF（可选），需要 Linux 内核头文件

编译 release：

```
cargo build --release
```

## 运行

你需要提供自己的配置文件（配置文件不在仓库中）：

```
./target/release/titandns --config /path/to/config.yaml
```

示例配置（脱敏）：`config.example.yaml`。

## 一键安装（Linux）

```
curl -fsSL https://raw.githubusercontent.com/jimmyzhou521-stack/TitanDns/online/install.sh | bash
```

脚本会下载最新 GitHub Release，并执行包内的 `install.sh`。
安装完成后，请编辑 `/etc/titandns/config.yaml` 以适配环境。

支持：Linux x86_64 / x86_64-v3 / arm64（自动识别）。

当 Release 中存在 `SHA256SUMS.txt` 时，安装脚本会自动校验。

## 配置（概览）

YAML 配置通常包含：

- 全局设置：`log`、`api`、`ebpf`
- `plugins`：插件定义（cache / forward / geo / matcher / 等）
- `sequences`：执行链路
- `servers`：监听器定义（UDP / TCP / HTTP）

### 示例 1：最小 UDP + 缓存 + 上游

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

### 示例 2：国内/代理分流

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

### 示例 3：DoH / DoT 上游

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

### 示例 4：eBPF（Linux）

```
ebpf:
  interface: "eth0"
  bpf_path: "/etc/titandns/titan_dns_filter.o"
  xdp_cache:
    enabled: true
    size: 1000000
```

## Web UI

`www/` 中包含静态资源，你可以使用自己的 Web 服务器托管，或在配置中开启
TitanDNS 的 HTTP 服务进行集成。

## CI / 构建产物

每次 push 到 `online`，GitHub Actions 会构建 release 并上传打包产物
（包含 `titandns` + `www/` + `bpf/`）。产物命名：
`titandns-<版本>-<日期>-<系统>.tar.gz`，其中 `<版本>` 来自 `Cargo.toml`，
`<日期>` 格式为 `YYYYMMDD`。

## 发布（Tag）

创建并推送标签（例如 `v1.0.0`）会触发 GitHub Release：

```
git tag v1.0.0
git push origin v1.0.0
```

## 贡献

请先阅读 `CONTRIBUTING.md`，并遵守 `CODE_OF_CONDUCT.md`。

## 安全

安全问题请参考 `SECURITY.md`。

## 许可

Apache-2.0，详见 `LICENSE`。
