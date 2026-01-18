# Changelog

All notable changes to this project will be documented in this file.

## [1.0.3] - 2026-01-18

### Changed

- ⚡ SmartForward 改用 `local_upstreams` + `race` 模式（解决首包卡顿）
- ⚡ 优化 UDP 超时：`udp_reply_timeout_ms: 100`
- ⚡ 禁用首包重试：`udp_retries: 0`
- ⚡ 增加本地并发数：`local_concurrent: 3`
- 📝 更新 `config.example.yaml` 生产级配置
- 🔒 脱敏处理：移除内网 IP 和敏感凭证

## [1.0.2] - 2026-01-18

### Added

- 🆕 新增 `task_manager.rs` 任务管理器模块
- 🆕 新增 cache 智能刷新功能 (`cache_smart_refresh.rs`)
- 🆕 新增 cache 预热功能 (`cache_warmup.rs`)
- 🆕 新增 `no_ipv4.txt` 规则文件支持
- 🆕 新增 PCDN 正则匹配规则 (`pcdnregv4.txt`, `pcdnregv6.txt`)

### Changed

- ⚡ 优化 SmartForward 插件：改进域名分类和路由逻辑
- ⚡ 优化 SmartResolve 插件：提升并发解析性能
- ⚡ 优化 Cache 插件：增强缓存预取和过期服务逻辑
- ⚡ 优化 Forward 插件：改进上游健康检查
- ⚡ 优化 API 模块：增强 Dashboard 功能
- ⚡ 优化 Metrics 模块：新增更多监控指标
- ⚡ 优化 Health 模块：改进健康检查逻辑
- ⚡ 优化 BPF 模块：增强 XDP 缓存同步
- 📝 更新 `config.example.yaml`：生产级配置示例

### Fixed

- 🔧 修复 RateLimit 插件计数器精度问题
- 🔧 修复 QueryLog 插件内存占用优化
- 🔧 修复 SOCKS5 UDP 代理连接稳定性

## [1.0.1] - 2026-01-17

### Fixed

- 🔧 Fixed GeoSite rules being stored to wrong category (twitter/facebook now correctly return FakeIP)
- 🔧 Fixed Forward plugin timeout configuration not being applied

### Changed

- ⚡ Reduced UDP single timeout from 2s to 500ms for faster race mode response
- ⚡ Reduced UDP retries from 2 to 1
- ⚡ Increased race mode concurrent upstreams from 3 to 5
- 📝 Updated README with architecture diagram, badges, and detailed examples
- 🎨 Added TitanDNS logo (SVG)

### Added

- 📝 Comprehensive bilingual documentation (English + Chinese)
- 📝 Detailed configuration examples in config.example.yaml
- 🔧 Troubleshooting workflow documentation

## [1.0.0] - 2026-01-10

- Initial public release of the minimal source set (online branch).
- Added CI build workflow for release artifacts with date-based naming.
- Added bilingual README and standard OSS docs.
- License set to Apache-2.0.
- Added tag-triggered GitHub Releases and one-click installer.
- Added Linux x86_64-v3 build target.
- Added release checksums and installer verification.
