#!/bin/bash
# =============================================================================
#  setup_defender_vm.sh  —  One-time setup for Ubuntu Defender VM
#  Run: sudo bash setup/setup_defender_vm.sh
# =============================================================================

set -e

echo "=============================================="
echo "  SOC LAB — DEFENDER VM SETUP"
echo "  Ubuntu 22.04/24.04  |  IP: 192.168.100.20"
echo "  Interface: enp0s8"
echo "=============================================="

echo ""
echo "[1] Installing packages..."
apt-get update -qq
apt-get install -y python3-pip iptables tcpdump net-tools 2>&1 | tail -5

echo ""
echo "[2] Installing Python packages..."
apt-get install -y python3-matplotlib python3-numpy python3-scapy 2>&1 | tail -5

echo ""
echo "[3] Creating log file..."
touch /var/log/ip_containment.log
chmod 666 /var/log/ip_containment.log

echo ""
echo "=============================================="
echo "  SETUP COMPLETE"
echo "=============================================="
echo "  Python : $(python3 --version)"
echo "  Scapy  : $(python3 -c 'import scapy; print(scapy.__version__)' 2>/dev/null)"
echo ""
echo "  Next: sudo python3 defender/ip_containment.py"
echo "=============================================="
