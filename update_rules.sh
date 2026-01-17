#!/bin/bash

# =================================================================
# TitanDNS Global Rule Updater & Auto-Scheduler
# =================================================================
# 功能：自动更新 GeoIP, GeoSite, AdGuard 及国内 IP 列表
# 特色：自动路径识别 (dat/mmdb 在根目录, txt 在 rules 目录)
#       支持一键安装 Systemd 定时任务 (每日凌晨2点)
#       [新增] 自动拉取并转换 AI 项目代理规则 (OpenAI, Gemini, etc.)
# =================================================================
# 使用方法：
#   ./update_rules.sh           # 立即更新规则
#   ./update_rules.sh --install # 安装定时任务（每日 02:00 自动更新）
# =================================================================

# ==================== 配置区域 ====================
# 代理设置（如需通过代理下载 GitHub 资源，取消注释并修改）
# PROXY="socks5h://127.0.0.1:7891"
PROXY=""

CONF_DIR="/etc/titandns"
RULES_DIR="$CONF_DIR/rules"
LOG_FILE="/var/log/titandns/rules_update.log"
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# ==================== 资源定义 ====================
declare -A RESOURCES

# GeoSite: MetaCubeX (V2Ray Protobuf 格式 - TitanDNS 完美兼容)
# ✅ 规则覆盖最全面，包含 cn/gfw/google/youtube/telegram/openai 等分类
# ✅ 每日更新，来源可靠
RESOURCES["geosite.dat"]="https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat"

# GeoIP MMDB: Loyalsoldier (MaxMind MMDB 格式 - TitanDNS 原生支持)
# ✅ 基于 MaxMind GeoLite2 + 国内 IP 优化
# ✅ 文件小 (~6MB)，加载快
# 注意: geoip.dat 不需要，TitanDNS 只使用 MMDB 格式
RESOURCES["geoip.mmdb"]="https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb"

# AdBlock 规则 (使用 AdGuard DNS Filter)
RESOURCES["adguard.txt"]="https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"

# 中国 IP 列表 (来源: ispip.clang.cn)
RESOURCES["cn_ipv4.txt"]="https://ispip.clang.cn/all_cn.txt"
RESOURCES["cn_ipv6.txt"]="https://ispip.clang.cn/all_cn_ipv6.txt"
RESOURCES["cn_ipv4_apnic.txt"]="https://ispip.clang.cn/all_cn_apnic.txt"
RESOURCES["cn_ipv6_apnic.txt"]="https://ispip.clang.cn/all_cn_ipv6_apnic.txt"

# AI 规则集 (可选，需要代理才能下载)
# 包含 OpenAI, Gemini, Claude, Copilot 等 AI 服务域名
AI_RULES=(
    # 如需使用，取消注释并确保设置了 PROXY
    # "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/OpenAI/OpenAI.list"
    # "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Gemini/Gemini.list"
)

# ==================== 核心函数 ====================

log() { 
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

# 一键安装 Systemd 定时任务
install_cron() {
    log "Configuring Systemd Timer (Daily at 02:00)..."
    
    # 确保脚本被复制到了标准位置
    mkdir -p $CONF_DIR
    cp "$0" "$CONF_DIR/update_rules.sh"
    chmod +x "$CONF_DIR/update_rules.sh"
    
    # 创建 Service
    cat <<EOF > /etc/systemd/system/titandns-update.service
[Unit]
Description=TitanDNS Rules Auto-Update Service
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash $CONF_DIR/update_rules.sh
User=root
EOF

    # 创建 Timer (精确设定为 02:00)
    cat <<EOF > /etc/systemd/system/titandns-update.timer
[Unit]
Description=Daily TitanDNS Rules Update Timer

[Timer]
OnCalendar=*-*-* 02:00:00
RandomizedDelaySec=60
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now titandns-update.timer
    log "Timer enabled! Check status: systemctl status titandns-update.timer"
    exit 0
}

# ==================== 执行区域 ====================

if [[ "$1" == "--install" ]]; then
    install_cron
fi

log "=== TitanDNS Rule Update Cycle Started ==="
mkdir -p $RULES_DIR
mkdir -p $(dirname $LOG_FILE)

# 确保所有必要的规则文件都存在
touch "$RULES_DIR/ai_proxy.txt"
touch "$RULES_DIR/blocklist.txt"
touch "$RULES_DIR/whitelist.txt"
touch "$RULES_DIR/greylist.txt"
touch "$RULES_DIR/hosts.txt"
touch "$RULES_DIR/pcdnlist.txt"
touch "$RULES_DIR/ddnslist.txt"

UPDATED_COUNT=0

# Loop 1: 下载标准资源
for FILE_NAME in "${!RESOURCES[@]}"; do
    URL=${RESOURCES[$FILE_NAME]}
    
    # 自动识别目标路径
    if [[ $FILE_NAME == *.dat ]] || [[ $FILE_NAME == *.mmdb ]]; then
        TARGET_PATH="$CONF_DIR/$FILE_NAME"
    else
        TARGET_PATH="$RULES_DIR/$FILE_NAME"
    fi
    
    log "Checking for updates: $FILE_NAME..."
    TMP_FILE="/tmp/$FILE_NAME.tmp"
    
    # 国内资源不使用代理 (ispip.clang.cn, adguardteam.github.io 可直连)
    if [[ $URL == *"clang.cn"* ]] || [[ $URL == *"adguardteam.github.io"* ]]; then
        OPTS=("-sSL" "-A" "$USER_AGENT" "--connect-timeout" "15" "--retry" "3")
        log "  (Direct connection - no proxy)"
    elif [[ -n "$PROXY" ]]; then
        OPTS=("-sSL" "-A" "$USER_AGENT" "-x" "$PROXY" "--connect-timeout" "15" "--retry" "3")
    else
        OPTS=("-sSL" "-A" "$USER_AGENT" "--connect-timeout" "15" "--retry" "3")
    fi
    
    # 增量下载（仅当文件有更新时才下载）
    if [ -f "$TARGET_PATH" ]; then
        FILE_SIZE=$(stat -c%s "$TARGET_PATH" 2>/dev/null || stat -f%z "$TARGET_PATH" 2>/dev/null || echo 0)
        if [ "$FILE_SIZE" -lt 1024 ]; then
            log "⚠️ File $FILE_NAME is too small ($FILE_SIZE bytes), forcing update..."
            rm -f "$TARGET_PATH"
        else
            OPTS+=("-z" "$TARGET_PATH")
        fi
    fi

    if curl "${OPTS[@]}" -o "$TMP_FILE" "$URL"; then
        if [ -s "$TMP_FILE" ]; then
            mv "$TMP_FILE" "$TARGET_PATH"
            log "✅ Updated: $FILE_NAME"
            ((UPDATED_COUNT++))
        else
            log "No changes: $FILE_NAME is up to date."
            rm -f "$TMP_FILE"
        fi
    else
        log "❌ Error: Failed to fetch $FILE_NAME"
        rm -f "$TMP_FILE"
    fi
done

# Loop 2: AI 规则集（合并转换）
if [ ${#AI_RULES[@]} -gt 0 ] && [ -n "$PROXY" ]; then
    log "Processing AI Proxy Rules..."
    AI_TMP="/tmp/ai_proxy_merged.txt"
    > "$AI_TMP" # 清空临时文件

    for URL in "${AI_RULES[@]}"; do
        FILENAME=$(basename "$URL")
        log " -> Fetching $FILENAME"
        # 下载并转换格式：移除注释、前缀，只保留域名
        curl -sSL -A "$USER_AGENT" -x "$PROXY" "$URL" | \
            grep -v "^#" | \
            grep -v "IP-CIDR" | \
            sed 's/DOMAIN-SUFFIX,//g' | \
            sed 's/DOMAIN,//g' | \
            sed 's/DOMAIN-KEYWORD,//g' | \
            sed 's/,.*//g' | \
            grep -v "^$" >> "$AI_TMP"
    done

    # 对比是否有变化
    AI_TARGET="$RULES_DIR/ai_proxy.txt"
    if [ ! -f "$AI_TARGET" ] || ! cmp -s "$AI_TMP" "$AI_TARGET"; then
        mv "$AI_TMP" "$AI_TARGET"
        log "✅ AI Rules Updated: Merged into $AI_TARGET"
        ((UPDATED_COUNT++))
    else
        log "No changes in AI Rules."
        rm -f "$AI_TMP"
    fi
else
    log "AI Rules skipped (no proxy configured or no rules defined)"
fi

# 重启服务使规则生效
if [ $UPDATED_COUNT -gt 0 ]; then
    log "Reloading TitanDNS (Restarting)..."
    systemctl restart titandns
    log "🎉 Update cycle complete. $UPDATED_COUNT files updated."
else
    log "No updates performed."
fi

echo "------------------------------------" >> $LOG_FILE
