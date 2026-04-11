#!/bin/bash
# =============================================================================
#  setup_attacker_vm.sh  —  One-time setup for Kali Attacker VM
#  Run: sudo bash setup/setup_attacker_vm.sh
# =============================================================================

set -e

echo "=============================================="
echo "  SOC LAB — ATTACKER VM SETUP"
echo "  Kali Linux  |  IP: 192.168.100.10"
echo "  Interface: eth1"
echo "=============================================="

echo ""
echo "[1] Installing packages..."
apt-get update -qq
apt-get install -y hping3 nmap python3-pip 2>&1 | tail -5

echo ""
echo "[2] Installing Python packages..."
pip3 install scapy --break-system-packages --quiet

echo ""
echo "=============================================="
echo "  SETUP COMPLETE"
echo "=============================================="
echo "  hping3 : $(hping3 --version 2>&1 | head -1)"
echo "  nmap   : $(nmap --version | head -1)"
echo "  scapy  : $(python3 -c 'import scapy; print(scapy.__version__)' 2>/dev/null)"
echo ""
echo "  Next: sudo python3 attacker/malicious_flood.py"
echo "=============================================="
