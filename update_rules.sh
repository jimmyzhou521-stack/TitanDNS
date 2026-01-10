#!/bin/bash

# =================================================================
# TitanDNS Global Rule Updater & Auto-Scheduler
# =================================================================

PROXY=""   # optional: socks5h://127.0.0.1:7891
CONF_DIR="/etc/titandns"
RULES_DIR="$CONF_DIR/rules"
LOG_FILE="/var/log/titandns/rules_update.log"
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# 1. 资源定义
declare -A RESOURCES
RESOURCES["geosite.dat"]="https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat"
RESOURCES["geoip.dat"]="https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat"
RESOURCES["geoip.mmdb"]="https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb"
RESOURCES["adguard.txt"]="https://adguardteam.github.io/HostlistsRegistry/assets/filter_24.txt"
RESOURCES["cn_ipv4.txt"]="https://ispip.clang.cn/all_cn.txt"
RESOURCES["cn_ipv6.txt"]="https://ispip.clang.cn/all_cn_ipv6.txt"
RESOURCES["cn_ipv4_apnic.txt"]="https://ispip.clang.cn/all_cn_apnic.txt"
RESOURCES["cn_ipv6_apnic.txt"]="https://ispip.clang.cn/all_cn_ipv6_apnic.txt"

log() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE; }

install_cron() {
    log "Configuring Systemd Timer (Daily at 02:00)..."
    mkdir -p $CONF_DIR
    cp "$0" "$CONF_DIR/update_rules.sh"
    chmod +x "$CONF_DIR/update_rules.sh"

    cat <<EOF > /etc/systemd/system/titandns-update.service
[Unit]
Description=TitanDNS Rules Auto-Update Service
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash $CONF_DIR/update_rules.sh
User=root
EOF

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

if [[ "$1" == "--install" ]]; then
    install_cron
fi

log "=== TitanDNS Rule Update Cycle Started ==="
mkdir -p $RULES_DIR
mkdir -p $(dirname $LOG_FILE)

UPDATED_COUNT=0

for FILE_NAME in "${!RESOURCES[@]}"; do
    URL=${RESOURCES[$FILE_NAME]}

    if [[ $FILE_NAME == *.dat ]] || [[ $FILE_NAME == *.mmdb ]]; then
        TARGET_PATH="$CONF_DIR/$FILE_NAME"
    else
        TARGET_PATH="$RULES_DIR/$FILE_NAME"
    fi

    log "Checking for updates: $FILE_NAME..."
    TMP_FILE="/tmp/$FILE_NAME.tmp"

    OPTS=("-sSL" "-A" "$USER_AGENT" "--connect-timeout" "15" "--retry" "3")
    if [[ -n "$PROXY" ]]; then
        OPTS+=("-x" "$PROXY")
    fi
    if [ -f "$TARGET_PATH" ]; then
        OPTS+=("-z" "$TARGET_PATH")
    fi

    if curl "${OPTS[@]}" -o "$TMP_FILE" "$URL"; then
        if [ -s "$TMP_FILE" ]; then
            mv "$TMP_FILE" "$TARGET_PATH"
            log "Update Found: $FILE_NAME has been updated."
            ((UPDATED_COUNT++))
        else
            log "No changes: $FILE_NAME is up to date (skipped)."
            rm -f "$TMP_FILE"
        fi
    else
        log "Error: Failed to fetch $FILE_NAME."
        rm -f "$TMP_FILE"
    fi
done

if [ $UPDATED_COUNT -gt 0 ]; then
    log "Reloading TitanDNS (Restarting)..."
    systemctl restart titandns
    log "Update cycle complete. $UPDATED_COUNT files updated."
else
    log "No updates performed."
fi
