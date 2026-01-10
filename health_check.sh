#!/bin/bash

# TitanDNS Advanced Health & Feature Diagnostics v2.1
# Fixes: dig cookie warnings and improved parsing

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SERVER_IP="127.0.0.1"
DNS_PORT="53"
API_PORT="8080"

echo -e "${CYAN}=================================================${NC}"
echo -e "${CYAN}   TitanDNS Deep Feature Diagnostic v2.1   ${NC}"
echo -e "${CYAN}=================================================${NC}"
echo ""

# Helper for dig: filters out warnings and comments
safe_dig() {
    dig @$SERVER_IP -p $DNS_PORT "$1" +short +nocookie +timeout=2 +tries=1 | grep -v ";" | head -n 1
}

# --- 1. Infrastructure Checks ---
echo -e "1. [Infrastructure] System Status"
if pgrep titandns > /dev/null; then
    echo -e "   - Process : ${GREEN}RUNNING${NC}"
else
    echo -e "   - Process : ${RED}STOPPED${NC}"
    exit 1
fi

if ss -tuln | grep -q ":$DNS_PORT "; then
    echo -e "   - DNS Port: ${GREEN}Open ($DNS_PORT)${NC}"
else
    echo -e "   - DNS Port: ${RED}Closed${NC}"
fi

API_ALIVE=0
if curl -s -m 2 http://$SERVER_IP:$API_PORT/api/stats > /dev/null; then
    echo -e "   - API Port: ${GREEN}Online ($API_PORT)${NC}"
    API_ALIVE=1
else
    echo -e "   - API Port: ${RED}Offline${NC}"
fi
echo ""

# --- 2. Feature: Caching Architecture ---
echo -e "2. [Feature: Caching] Performance Test"
TARGET="www.taobao.com"

# First Query (Cold)
START_1=$(date +%s%N)
dig @$SERVER_IP -p $DNS_PORT $TARGET +short +nocookie > /dev/null
END_1=$(date +%s%N)
DUR_1=$(( ($END_1 - $START_1) / 1000000 ))

# Second Query (Hot)
START_2=$(date +%s%N)
dig @$SERVER_IP -p $DNS_PORT $TARGET +short +nocookie > /dev/null
END_2=$(date +%s%N)
DUR_2=$(( ($END_2 - $START_2) / 1000000 ))

echo -e "   - Cold Query: ${YELLOW}${DUR_1} ms${NC}"
echo -e "   - Hot  Query: ${GREEN}${DUR_2} ms${NC}"

if [ "$DUR_2" -lt 5 ]; then
    echo -e "   -> Conclusion: ${GREEN}Cache is WORKING (Instant Response)${NC}"
elif [ "$DUR_2" -lt "$DUR_1" ] || [ "$DUR_2" -le 10 ]; then
    echo -e "   -> Conclusion: ${GREEN}Cache is WORKING${NC}"
else
    echo -e "   -> Conclusion: ${RED}Cache might be DISABLED or SLOW${NC}"
fi
echo ""

# --- 3. Feature: Intelligent Routing (Split-DNS) ---
echo -e "3. [Feature: Routing] Split-DNS Verification"
CN_RES=$(safe_dig "www.baidu.com")
if [[ -n "$CN_RES" ]]; then
   if [[ "$CN_RES" == 198.18.* || "$CN_RES" == 7.0.0.* ]]; then
       echo -e "   - Domestic (Baidu) : ${YELLOW}$CN_RES (FakeIP?)${NC}"
   else
       echo -e "   - Domestic (Baidu) : ${GREEN}$CN_RES (Real IP)${NC}"
   fi
else
    echo -e "   - Domestic (Baidu) : ${RED}Failed${NC}"
fi

EN_RES=$(safe_dig "www.google.com")
if [[ -n "$EN_RES" ]]; then
    echo -e "   - Foreign (Google) : ${GREEN}$EN_RES${NC}"
else
    echo -e "   - Foreign (Google) : ${RED}Failed / Blocked${NC}"
fi
echo ""

# --- 4. Feature: AdBlocking ---
echo -e "4. [Feature: AdBlock] Filtering Test"
AD_RES=$(safe_dig "ad.doubleclick.net")
if [[ "$AD_RES" == "0.0.0.0" || "$AD_RES" == "127.0.0.1" || -z "$AD_RES" ]]; then
    echo -e "   - Ad Domain        : ${GREEN}BLOCKED ($AD_RES)${NC}"
else
    echo -e "   - Ad Domain        : ${RED}ALLOWED ($AD_RES)${NC}"
fi
echo ""

# --- 5. Feature: eBPF/XDP High Performance ---
echo -e "5. [Feature: eBPF/XDP] Kernel State"
if [ "$API_ALIVE" -eq 1 ]; then
    STATS=$(curl -s http://$SERVER_IP:$API_PORT/api/stats)
    XDP_HITS=$(echo "$STATS" | grep -o '"xdp_hits":[0-9]*' | cut -d: -f2)
    if [ -n "$XDP_HITS" ] && [ "$XDP_HITS" -gt 0 ]; then
        echo -e "   - XDP Cache Hits   : ${GREEN}$XDP_HITS (Kernel processing active)${NC}"
    else
        echo -e "   - XDP Cache Hits   : ${YELLOW}0 (Idle/Cold/Inactive)${NC}"
    fi
fi

echo ""
echo -e "${CYAN}== Diagnostics Complete ==${NC}"
