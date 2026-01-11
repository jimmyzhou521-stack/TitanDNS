#!/bin/bash

# ==========================================
# TitanDNS Package Installer
# ==========================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

INTERACTIVE=1
if [ ! -t 0 ]; then
  INTERACTIVE=0
fi

ask_yes_no() {
  local prompt="$1"
  local default="$2"
  local ans=""
  if [ "$INTERACTIVE" -eq 0 ]; then
    echo "$default"
    return
  fi
  read -r -p "$prompt" ans
  if [ -z "$ans" ]; then
    ans="$default"
  fi
  echo "$ans"
}

SKIP_EBPF=0
if [[ "${1:-}" == "--no-ebpf" ]]; then
  SKIP_EBPF=1
fi

WORK_DIR=$(dirname $(readlink -f $0))
BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/titandns"
RULES_DIR="$CONF_DIR/rules"
LOG_DIR="/var/log/titandns"
CACHE_DIR="/dev/shm/titandns"

DNS_BACKUP="$CONF_DIR/resolv.conf.bak"
RESOLVED_DROPIN_DIR="/etc/systemd/resolved.conf.d"
RESOLVED_DROPIN_FILE="$RESOLVED_DROPIN_DIR/titandns.conf"

is_systemd_resolved() {
  command -v resolvectl >/dev/null 2>&1 && systemctl is-active --quiet systemd-resolved
}

set_dns_custom() {
  local dns_ip="$1"
  if is_systemd_resolved; then
    mkdir -p "$RESOLVED_DROPIN_DIR"
    cat > "$RESOLVED_DROPIN_FILE" <<EOF
[Resolve]
DNS=$dns_ip
EOF
    systemctl restart systemd-resolved || true
  else
    if [ -f /etc/resolv.conf ] && [ ! -f "$DNS_BACKUP" ]; then
      cp /etc/resolv.conf "$DNS_BACKUP"
    fi
    cat > /etc/resolv.conf <<EOF
nameserver $dns_ip
options timeout:2 attempts:2
EOF
  fi
}

restore_dns() {
  if [ -f "$DNS_BACKUP" ]; then
    cp "$DNS_BACKUP" /etc/resolv.conf
  fi
  if [ -f "$RESOLVED_DROPIN_FILE" ]; then
    rm -f "$RESOLVED_DROPIN_FILE"
    systemctl restart systemd-resolved || true
  fi
}

# 1. 权限检查
if [ "$EUID" -ne 0 ]; then
    log_error "请使用 root 用户运行此脚本: sudo bash install.sh"
    exit 1
fi

# 1.1 系统兼容性检查
log_info "检查系统兼容性..."
OS_TYPE=$(uname -s)
if [ "$OS_TYPE" != "Linux" ]; then
    log_error "此脚本仅支持 Linux 系统"
    exit 1
fi

# 检查 systemd
if ! command -v systemctl &> /dev/null; then
    log_error "未检测到 systemd，请使用支持 systemd 的发行版"
    exit 1
fi

# 检查 curl (用于下载)
if ! command -v curl &> /dev/null; then
    log_info "安装 curl..."
    apt-get update -qq && apt-get install -y curl -qq 2>/dev/null || \
    yum install -y curl 2>/dev/null || \
    { log_error "无法安装 curl，请手动安装"; exit 1; }
fi

# 检查内核版本 (XDP 需要 4.x+)
KERNEL_VERSION=$(uname -r | cut -d. -f1)
if [ "$KERNEL_VERSION" -lt 4 ]; then
    log_warn "内核版本较低 ($(uname -r))，XDP 加速可能不兼容"
fi

log_success "系统兼容性检查通过"

# 2. 停止旧服务
if [ -x "/usr/local/bin/titandns" ]; then
    if [ "$INTERACTIVE" -eq 1 ]; then
        ans=$(ask_yes_no "检测到已安装 TitanDNS，是否重新安装？[Y/n] " "Y")
        if [[ "$ans" =~ ^[Nn]$ ]]; then
            log_warn "已取消安装。"
            exit 0
        fi
    fi
fi

if systemctl is-active --quiet titandns; then
    log_info "停止现有服务..."
    systemctl stop titandns
fi

# 3. 创建必要目录
log_info "创建目录结构..."
mkdir -p "$CONF_DIR"
mkdir -p "$RULES_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$CACHE_DIR"
mkdir -p "$CONF_DIR/www"
mkdir -p "$CONF_DIR/certs"

# 4. 架构检测与二进制安装
ARCH=$(uname -m)
log_info "检测到系统架构: $ARCH"

BINARY_NAME=""
if [ -f "$WORK_DIR/bin/titandns" ]; then
    BINARY_NAME="titandns"
fi
if [[ -z "$BINARY_NAME" && "$ARCH" == "x86_64" ]]; then
    if [ -f "$WORK_DIR/bin/titandns-linux-amd64" ]; then
        BINARY_NAME="titandns-linux-amd64"
    fi
elif [[ -z "$BINARY_NAME" && "$ARCH" == "aarch64" ]]; then
    if [ -f "$WORK_DIR/bin/titandns-linux-arm64" ]; then
        BINARY_NAME="titandns-linux-arm64"
    fi
fi

if [ -z "$BINARY_NAME" ]; then
    log_error "未找到适合当前架构的二进制文件！"
    log_error "请将编译好的文件放入 bin/ 目录"
    exit 1
fi

log_info "安装二进制文件: $BINARY_NAME"
cp "$WORK_DIR/bin/$BINARY_NAME" "$BIN_DIR/titandns"
chmod +x "$BIN_DIR/titandns"
log_success "二进制文件已安装"

# 5. eBPF 安装 (优先使用预编译)
log_info "处理 eBPF 内核模块..."
BPF_OBJ="$CONF_DIR/titan_dns_filter.o"

if [ "$SKIP_EBPF" -eq 1 ]; then
    log_warn "已跳过 eBPF 安装 (--no-ebpf)"
elif [ -f "$WORK_DIR/bpf/titan_dns_filter.o" ]; then
    cp "$WORK_DIR/bpf/titan_dns_filter.o" "$BPF_OBJ"
    log_success "eBPF 模块已安装 (预编译版本)"
else
    if [ -f "$WORK_DIR/bpf/titan_filter.c" ]; then
        log_warn "未找到预编译 eBPF，尝试现场编译..."
        if ! command -v clang &> /dev/null; then
            log_info "安装编译依赖..."
            if command -v apt-get &> /dev/null; then
                apt-get update -qq
                apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) -qq 2>/dev/null || \
                apt-get install -y clang llvm linux-headers-generic -qq
            elif command -v yum &> /dev/null; then
                yum install -y clang llvm kernel-devel
            fi
        fi
        CLANG_FLAGS="-O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include -I/usr/include/x86_64-linux-gnu"
        if clang $CLANG_FLAGS -c "$WORK_DIR/bpf/titan_filter.c" -o "$BPF_OBJ" 2>/dev/null; then
            log_success "eBPF 现场编译成功"
        else
            log_warn "eBPF 编译失败 (XDP 加速将不可用，但不影响基本功能)"
        fi
    else
        log_warn "未找到 eBPF 文件 (XDP 加速将不可用)"
    fi
fi
if [ -f "$WORK_DIR/bpf/titan_filter.c" ]; then
    cp "$WORK_DIR/bpf/titan_filter.c" "$CONF_DIR/titan_filter.c"
fi

# 6. 配置文件
log_info "安装配置文件..."
if [ -f "$CONF_DIR/config.yaml" ]; then
    log_info "备份现有配置..."
    cp "$CONF_DIR/config.yaml" "$CONF_DIR/config.yaml.bak_$(date +%s)"
fi
cp "$WORK_DIR/config.yaml" "$CONF_DIR/"

# 6.1 自动检测网卡并修改配置
log_info "自动检测网络接口..."
PRIMARY_IF=$(ip route | grep default | head -1 | awk '{print $5}')
if [ -z "$PRIMARY_IF" ]; then
    PRIMARY_IF=$(ip -o link show | grep -v "lo:" | head -1 | awk -F': ' '{print $2}')
fi
if [ -z "$PRIMARY_IF" ]; then
    PRIMARY_IF=$(ifconfig | grep -E "^[a-z]" | grep -v "^lo" | head -1 | awk '{print $1}' | tr -d ':')
fi
if [ -n "$PRIMARY_IF" ]; then
    log_success "检测到主网卡: $PRIMARY_IF"
    if grep -q 'interface:' "$CONF_DIR/config.yaml"; then
        use_if=$(ask_yes_no "使用该网卡作为 eBPF 接口？[Y/n] " "Y")
        if [[ "$use_if" =~ ^[Nn]$ ]]; then
            if [ "$INTERACTIVE" -eq 1 ]; then
                read -r -p "请输入网卡名称: " NEW_IF
                if [ -n "$NEW_IF" ]; then
                    PRIMARY_IF="$NEW_IF"
                fi
            fi
        fi
        sed -i "s/interface: \".*\"/interface: \"$PRIMARY_IF\"/" "$CONF_DIR/config.yaml"
        log_success "配置文件已更新网卡为: $PRIMARY_IF"
    fi
else
    log_warn "无法自动检测网卡，请手动修改 $CONF_DIR/config.yaml 中的 interface 参数"
    if [ "$INTERACTIVE" -eq 1 ]; then
        read -r -p "请输入网卡名称(回车跳过): " NEW_IF
        if [ -n "$NEW_IF" ]; then
            if grep -q 'interface:' "$CONF_DIR/config.yaml"; then
                sed -i "s/interface: \".*\"/interface: \"$NEW_IF\"/" "$CONF_DIR/config.yaml"
                log_success "配置文件已更新网卡为: $NEW_IF"
            fi
        fi
    fi
fi
log_success "配置文件已安装"

# 6.2 科学上游地址确认
if [ "$INTERACTIVE" -eq 1 ]; then
    DEFAULT_FAKEIP="udp://127.0.0.1:6666"
    read -r -p "科学上游(FakeIP)当前为 $DEFAULT_FAKEIP 。若为远端或需修改请输入新地址(回车保持): " NEW_FAKEIP
    if [ -n "$NEW_FAKEIP" ]; then
        sed -i "s|$DEFAULT_FAKEIP|$NEW_FAKEIP|g" "$CONF_DIR/config.yaml"
        log_success "已更新 FakeIP 上游为: $NEW_FAKEIP"
    fi
fi

# 7. 规则文件
log_info "安装规则文件..."
if [ -d "$WORK_DIR/rules" ]; then
    cp -r "$WORK_DIR/rules/"* "$RULES_DIR/" 2>/dev/null || true
fi
for f in adguard.txt blocklist.txt whitelist.txt hosts.txt greylist.txt ddnslist.txt pcdnlist.txt; do
    touch "$RULES_DIR/$f"
done
log_success "规则文件已安装"
log_info "规则已内置并可直接使用（无需再次运行 update_rules.sh）"
log_info "如需定时更新规则：tdns rules-install"

# 8. Dashboard
log_info "安装 Dashboard..."
if [ -d "$WORK_DIR/www" ]; then
    cp -r "$WORK_DIR/www/"* "$CONF_DIR/www/" 2>/dev/null || true
    log_success "Dashboard 已安装"
fi

# 9. TLS 证书
if [ ! -f "$CONF_DIR/certs/key.pem" ]; then
    log_info "生成自签名证书..."
    if ! command -v openssl &> /dev/null; then
        apt-get install -y openssl -qq 2>/dev/null || yum install -y openssl 2>/dev/null
    fi
    openssl req -x509 -newkey rsa:4096 \
        -keyout "$CONF_DIR/certs/key.pem" \
        -out "$CONF_DIR/certs/cert.pem" \
        -days 3650 -nodes -subj "/CN=TitanDNS" 2>/dev/null
    chmod 600 "$CONF_DIR/certs/key.pem"
    log_success "证书已生成"
fi

# 10. 下载 GeoIP/GeoSite
log_info "检查 GeoIP/GeoSite 数据..."

download_file() {
    local url1=$1
    local url2=$2
    local dest=$3
    if [ ! -f "$dest" ]; then
        log_info "下载 $(basename $dest)..."
        curl -sSL -o "$dest" "$url1" 2>/dev/null || \
        curl -sSL -o "$dest" "$url2" 2>/dev/null || \
        log_warn "下载失败: $(basename $dest)"
    fi
}

if [ -f "$WORK_DIR/db/geosite.dat" ]; then
    cp "$WORK_DIR/db/geosite.dat" "$CONF_DIR/"
else
    download_file \
        "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat" \
        "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" \
        "$CONF_DIR/geosite.dat"
fi

if [ -f "$WORK_DIR/db/geoip.mmdb" ]; then
    cp "$WORK_DIR/db/geoip.mmdb" "$CONF_DIR/"
else
    download_file \
        "https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb" \
        "https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb" \
        "$CONF_DIR/geoip.mmdb"
fi

log_success "GeoIP/GeoSite 数据已就绪"

# 11. 下载高精度 IP 列表
log_info "下载高精度 IP 列表..."
if [ ! -s "$RULES_DIR/cn_ipv4.txt" ]; then
    curl -sSL -o "$RULES_DIR/cn_ipv4.txt" "https://ispip.clang.cn/all_cn.txt" 2>/dev/null || true
fi
if [ ! -s "$RULES_DIR/cn_ipv6.txt" ]; then
    curl -sSL -o "$RULES_DIR/cn_ipv6.txt" "https://ispip.clang.cn/all_cn_ipv6.txt" 2>/dev/null || true
fi
if [ ! -s "$RULES_DIR/cn_ipv4_apnic.txt" ]; then
    curl -sSL "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest" 2>/dev/null | \
        grep "|CN|ipv4|" | awk -F'|' '{print $4"/"32-log($5)/log(2)}' > "$RULES_DIR/cn_ipv4_apnic.txt" || true
fi
if [ ! -s "$RULES_DIR/cn_ipv6_apnic.txt" ]; then
    curl -sSL "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest" 2>/dev/null | \
        grep "|CN|ipv6|" | awk -F'|' '{print $4"/"$5}' > "$RULES_DIR/cn_ipv6_apnic.txt" || true
fi
if [ ! -s "$RULES_DIR/adguard.txt" ]; then
    curl -sSL -o "$RULES_DIR/adguard.txt" \
        "https://cdn.jsdelivr.net/gh/privacy-protection-tools/anti-AD@master/anti-ad-domains.txt" 2>/dev/null || true
fi
log_success "IP 列表已就绪"

# 12. 复制辅助脚本
if [ -f "$WORK_DIR/update_rules.sh" ]; then
    cp "$WORK_DIR/update_rules.sh" "$CONF_DIR/"
    chmod +x "$CONF_DIR/update_rules.sh"
fi
if [ -f "$WORK_DIR/health_check.sh" ]; then
    cp "$WORK_DIR/health_check.sh" "$CONF_DIR/"
    chmod +x "$CONF_DIR/health_check.sh"
fi

# 12.1 安装 tdns 快捷指令
cat > "$BIN_DIR/tdns" <<'TDNS_EOF'
#!/usr/bin/env bash
set -euo pipefail

CONF_DIR="/etc/titandns"
BIN="/usr/local/bin/titandns"
REPO="jimmyzhou521-stack/TitanDNS"
DNS_BACKUP="/etc/titandns/resolv.conf.bak"
RESOLVED_DROPIN_DIR="/etc/systemd/resolved.conf.d"
RESOLVED_DROPIN_FILE="$RESOLVED_DROPIN_DIR/titandns.conf"

is_systemd_resolved() {
  command -v resolvectl >/dev/null 2>&1 && systemctl is-active --quiet systemd-resolved
}

set_dns_custom() {
  local dns_ip="$1"
  if is_systemd_resolved; then
    mkdir -p "$RESOLVED_DROPIN_DIR"
    cat > "$RESOLVED_DROPIN_FILE" <<EOF
[Resolve]
DNS=$dns_ip
EOF
    systemctl restart systemd-resolved || true
  else
    if [ -f /etc/resolv.conf ] && [ ! -f "$DNS_BACKUP" ]; then
      cp /etc/resolv.conf "$DNS_BACKUP"
    fi
    cat > /etc/resolv.conf <<EOF
nameserver $dns_ip
options timeout:2 attempts:2
EOF
  fi
}

restore_dns() {
  if [ -f "$DNS_BACKUP" ]; then
    cp "$DNS_BACKUP" /etc/resolv.conf
  fi
  if [ -f "$RESOLVED_DROPIN_FILE" ]; then
    rm -f "$RESOLVED_DROPIN_FILE"
    systemctl restart systemd-resolved || true
  fi
}

help() {
  cat <<EOF
tdns commands:
  status|start|stop|restart   Service control
  logs                        Follow logs
  config                      Edit config.yaml
  update|reinstall            Reinstall latest release
  uninstall                   Uninstall (asks confirmation)
  rules                       Update rules now
  rules-install               Install rules update timer
  bpf-rebuild                 Rebuild eBPF (if titan_filter.c exists)
  kernel-check                Show current kernel version
  kernel-update               Update kernel packages (interactive)
EOF
}

CMD="${1:-help}"

case "$CMD" in
  status|start|stop|restart)
    systemctl "$CMD" titandns
    ;;
  logs)
    journalctl -u titandns -f
    ;;
  config)
    ${EDITOR:-nano} "$CONF_DIR/config.yaml"
    ;;
  update|reinstall)
    curl -fsSL "https://raw.githubusercontent.com/${REPO}/online/install.sh" | bash
    ;;
  uninstall)
    read -r -p "确认卸载 TitanDNS？将移除服务与二进制文件 (Y/N): " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
      systemctl stop titandns || true
      systemctl disable titandns || true
      rm -f /etc/systemd/system/titandns.service
      systemctl daemon-reload || true
      rm -f "$BIN" /usr/local/bin/tdns
      read -r -p "是否删除配置目录 /etc/titandns？(y/N): " ans2
      if [[ "$ans2" =~ ^[Yy]$ ]]; then
        rm -rf "$CONF_DIR"
        restore_dns
      else
        read -r -p "是否恢复系统 DNS 到 223.5.5.5？(Y/n): " ans3
        if [[ -z "$ans3" || "$ans3" =~ ^[Yy]$ ]]; then
          set_dns_custom "223.5.5.5"
        fi
      fi
      echo "卸载完成"
    fi
    ;;
  rules)
    bash "$CONF_DIR/update_rules.sh"
    ;;
  rules-install)
    bash "$CONF_DIR/update_rules.sh" --install
    ;;
  bpf-rebuild)
    if [ -f "$CONF_DIR/titan_filter.c" ]; then
      if ! command -v clang >/dev/null 2>&1; then
        echo "clang 未安装，请先安装 clang/llvm"
        exit 1
      fi
      clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include -I/usr/include/x86_64-linux-gnu \
        -c "$CONF_DIR/titan_filter.c" -o "$CONF_DIR/titan_dns_filter.o"
      echo "eBPF 已重新编译：$CONF_DIR/titan_dns_filter.o"
    else
      echo "未找到 $CONF_DIR/titan_filter.c"
    fi
    ;;
  kernel-check)
    uname -a
    ;;
  kernel-update)
    echo "⚠️ 该操作会更新内核并可能需要重启。"
    read -r -p "确认继续？(Y/N): " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
      if command -v apt-get >/dev/null 2>&1; then
        apt-get update && apt-get install -y linux-image-generic
      elif command -v yum >/dev/null 2>&1; then
        yum update -y kernel
      else
        echo "未识别的包管理器，请手动更新内核。"
      fi
    fi
    ;;
  help|*)
    help
    ;;
esac
TDNS_EOF
chmod +x "$BIN_DIR/tdns"
log_success "已安装 tdns 快捷指令"

# 13. Systemd 服务
log_info "配置 Systemd 服务..."
cat > /etc/systemd/system/titandns.service <<EOF
[Unit]
Description=TitanDNS High-Performance DNS Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/titandns
ExecStartPre=/bin/mkdir -p /dev/shm/titandns
ExecStartPre=/bin/mkdir -p /var/log/titandns
ExecStart=/usr/local/bin/titandns -c config.yaml
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable titandns
log_success "Systemd 服务已配置"

# 14. 启动服务
log_info "启动 TitanDNS..."
systemctl restart titandns
sleep 3

if systemctl is-active --quiet titandns; then
    log_success "TitanDNS 服务已启动!"
    log_info "验证 DNS 功能..."
    if ! command -v dig &> /dev/null; then
        apt-get install -y dnsutils -qq 2>/dev/null || \
        yum install -y bind-utils 2>/dev/null || true
    fi
    if command -v dig &> /dev/null; then
        TEST_RESULT=$(dig @127.0.0.1 www.baidu.com +short +time=3 2>/dev/null | head -1)
        if [ -n "$TEST_RESULT" ]; then
            log_success "DNS 验证通过! www.baidu.com -> $TEST_RESULT"
        else
            log_warn "DNS 验证失败，请检查配置。可能需要等待 GeoIP 数据加载。"
        fi
    else
        log_warn "dig 未安装，跳过 DNS 验证"
    fi
else
    log_error "服务启动失败，尝试恢复..."
    if [ -f "$CONF_DIR/config.yaml.bak_"* ]; then
        LATEST_BAK=$(ls -t "$CONF_DIR/config.yaml.bak_"* 2>/dev/null | head -1)
        if [ -n "$LATEST_BAK" ]; then
            log_warn "恢复旧配置: $LATEST_BAK"
            cp "$LATEST_BAK" "$CONF_DIR/config.yaml"
            systemctl restart titandns
            sleep 2
            if systemctl is-active --quiet titandns; then
                log_warn "服务已使用旧配置恢复，请检查新配置文件"
            fi
        fi
    fi
    log_error "请检查日志: journalctl -u titandns -n 50"
    exit 1
fi

# 15. 系统 DNS 指向
if [ "$INTERACTIVE" -eq 1 ]; then
    ans=$(ask_yes_no "是否将系统 DNS 指向 127.0.0.1（TitanDNS）？[Y/n] " "Y")
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        set_dns_custom "127.0.0.1"
        log_success "系统 DNS 已指向 127.0.0.1"
    else
        log_warn "未修改系统 DNS，可手动设置或使用 tdns 命令"
    fi
fi

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}       🎉 TitanDNS 安装完成!                    ${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo "  配置文件: $CONF_DIR/config.yaml"
echo "  规则目录: $RULES_DIR/"
echo "  日志目录: $LOG_DIR/"
echo ""
echo "  Dashboard: http://<服务器IP>:8080"
echo ""
echo "  常用命令:"
echo "    systemctl status titandns    # 查看状态"
echo "    systemctl restart titandns   # 重启服务"
echo "    journalctl -u titandns -f    # 查看日志"
echo "    bash $CONF_DIR/health_check.sh  # 健康检测"
echo ""
echo "  测试 DNS:"
echo "    dig @127.0.0.1 www.baidu.com +short"
echo "    dig @127.0.0.1 www.google.com +short"
echo ""
echo -e "${YELLOW}  ⚠️ 注意: 请编辑 $CONF_DIR/config.yaml${NC}"
echo -e "${YELLOW}     将 interface: \"eth0\" 改为您的网卡名称${NC}"
echo ""
echo -e "${GREEN}================================================${NC}"
