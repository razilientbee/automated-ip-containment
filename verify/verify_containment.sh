#!/bin/bash
# =============================================================================
#  verify_containment.sh  —  Run on Ubuntu Defender VM (Chiron)
#  Usage: bash verify/verify_containment.sh [action]
# =============================================================================

ACTION="${1:-help}"

case "$ACTION" in

check)
    echo ""
    echo "=============================================="
    echo "  IPTABLES — INPUT CHAIN"
    echo "=============================================="
    sudo iptables -L INPUT -n -v --line-numbers
    ;;

flush)
    echo ""
    echo "[FLUSH] Removing DROP rule for 192.168.100.10 ..."
    sudo iptables -D INPUT -s 192.168.100.10 -j DROP 2>/dev/null \
        && echo "  Rule removed." \
        || echo "  No rule found."
    echo ""
    sudo iptables -L INPUT -n --line-numbers
    ;;

flushall)
    echo ""
    echo "[WARNING] Flushing ALL INPUT chain rules..."
    sudo iptables -F INPUT
    echo "  Done."
    ;;

watch)
    echo ""
    echo "[WATCH] Live iptables packet counter (Ctrl+C to stop)..."
    watch -n 1 'sudo iptables -L INPUT -n -v --line-numbers'
    ;;

sniff)
    echo ""
    echo "[SNIFF] Capturing SYN packets from 192.168.100.10 on enp0s8 ..."
    sudo tcpdump -i enp0s8 -n \
        'tcp[tcpflags] & tcp-syn != 0 and src 192.168.100.10' -l
    ;;

sniff-all)
    echo ""
    echo "[SNIFF-ALL] All traffic from 192.168.100.10 ..."
    sudo tcpdump -i enp0s8 -n 'src 192.168.100.10' -l
    ;;

log)
    echo ""
    echo "[LOG] Tailing /var/log/ip_containment.log (Ctrl+C to stop)..."
    tail -f /var/log/ip_containment.log
    ;;

metrics)
    MFILE="/tmp/containment_metrics.json"
    if [ ! -f "$MFILE" ]; then
        echo "[ERROR] $MFILE not found. Run ip_containment.py first."
        exit 1
    fi
    echo ""
    echo "=============================================="
    echo "  CONTAINMENT METRICS"
    echo "=============================================="
    python3 -c "
import json, sys
with open('$MFILE') as f:
    data = json.load(f)
if not data:
    print('  No events recorded yet.')
    sys.exit(0)
for i, e in enumerate(data, 1):
    print(f'  Event #{i}')
    print(f'    IP              : {e[\"ip\"]}')
    print(f'    SYN count       : {e[\"syn_count\"]}')
    print(f'    Detection time  : {e[\"detection_time\"]}')
    print(f'    Block latency   : {e[\"detection_to_block_ms\"]} ms')
    print(f'    Full-stop       : {e[\"detection_to_fullstop_ms\"]} ms  [{e.get(\"rating\",\"\")}]')
    print(f'    Post-block pkts : {e[\"post_block_pkts\"]}')
    print()
n = len(data)
avg = sum(e['detection_to_fullstop_ms'] for e in data) / n
print(f'  Total events : {n}')
print(f'  Avg full-stop: {avg:.1f} ms')
print(f'  3s target    : {\"PASS\" if avg < 3000 else \"FAIL\"}')
"
    ;;

reset)
    echo ""
    echo "[RESET] Clearing rules and metrics for next run..."
    sudo iptables -D INPUT -s 192.168.100.10 -j DROP 2>/dev/null || true
    sudo bash -c 'echo "[]" > /tmp/containment_metrics.json'
    sudo truncate -s 0 /var/log/ip_containment.log
    echo "  Done. Ready for next run."
    ;;

ping-test)
    echo ""
    echo "[PING] Testing connectivity to attacker VM..."
    ping -c 4 192.168.100.10
    ;;

*)
    echo ""
    echo "Usage: bash verify/verify_containment.sh [action]"
    echo ""
    echo "  check      — show iptables INPUT chain"
    echo "  flush      — remove attacker IP DROP rule"
    echo "  flushall   — clear entire INPUT chain"
    echo "  watch      — live watch iptables counters"
    echo "  sniff      — tcpdump SYN packets from attacker"
    echo "  sniff-all  — tcpdump all traffic from attacker"
    echo "  log        — tail containment log file"
    echo "  metrics    — print metrics JSON summary"
    echo "  reset      — clear rules and metrics for next run"
    echo "  ping-test  — ping attacker VM"
    echo ""
    ;;
esac
