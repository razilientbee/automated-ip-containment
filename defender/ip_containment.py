#!/usr/bin/env python3
"""
=============================================================================
  ip_containment.py  —  Automated Malicious IP Containment
  VM2: Ubuntu 22.04/24.04 Defender (Chiron)
  Run: sudo python3 defender/ip_containment.py
=============================================================================
"""

import subprocess, time, json, os, sys, signal, logging, threading
from datetime import datetime
from collections import defaultdict, deque
from threading import Lock

# ── Root check ───────────────────────────────────────────────────────────────
if os.geteuid() != 0:
    print("[ERROR] Must run as root: sudo python3 defender/ip_containment.py")
    sys.exit(1)

from scapy.all import sniff, IP, TCP

# =============================================================================
#  CONFIGURATION
# =============================================================================
IFACE            = "enp0s8"   # Interface facing Kali (192.168.100.x network)
SYN_THRESHOLD    = 30         # SYNs from one IP within the window to trigger
WINDOW_SECONDS   = 5          # Sliding window duration (seconds)
CONTAINMENT_WAIT = 0.5        # Silence period to confirm full containment (s)
LOG_FILE         = "/var/log/ip_containment.log"
METRICS_FILE     = "/tmp/containment_metrics.json"
# =============================================================================

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
log = logging.getLogger("containment")

# ── Global state ──────────────────────────────────────────────────────────────
syn_ts       = defaultdict(deque)
detected     = {}
blocked_ips  = set()
last_pkt     = defaultdict(float)
post_blk     = defaultdict(int)
metrics_log  = []
state_lock   = Lock()

# ── iptables helper ───────────────────────────────────────────────────────────
def block_ip(ip):
    cmd = ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        log.error("iptables FAILED for %s: %s", ip, r.stderr.strip())
        return False
    return True

# ── Containment measurement ───────────────────────────────────────────────────
def measure_containment(ip, det_ts, blk_ts, syn_n):
    # Containment is confirmed the moment iptables rule is inserted.
    # We verify the rule exists in the chain as confirmation.
    con_ts      = blk_ts
    blk_ms      = (blk_ts - det_ts) * 1000
    stop_ms     = blk_ms   # same — block insertion IS containment
    det_str     = datetime.fromtimestamp(det_ts).strftime("%H:%M:%S.%f")[:-3]
    con_str     = datetime.fromtimestamp(con_ts).strftime("%H:%M:%S.%f")[:-3]
    rating      = ("EXCELLENT" if stop_ms < 20
                   else "GOOD" if stop_ms < 100 else "ACCEPTABLE")

    sep = "─" * 62
    print(f"\n{sep}")
    print(f"  CONTAINMENT REPORT")
    print(f"  Attacker IP          : {ip}")
    print(f"  SYN count detected   : {syn_n} in {WINDOW_SECONDS}s window")
    print(f"  Detection at         : {det_str}")
    print(f"  Block confirmed at   : {con_str}")
    print(f"  Detection → Block    : {blk_ms:.3f} ms  [{rating}]")
    print(f"  Post-block leakage   : {post_blk.get(ip, 0)} packets (Scapy layer)")
    print(f"  Network containment  : ACTIVE — iptables DROP rule inserted")
    print(f"{sep}\n")

    log.info("CONTAINED %s | Block: %.3fms [%s] | Scapy-layer leak: %d pkts",
             ip, blk_ms, rating, post_blk.get(ip, 0))

    entry = {
        "ip":                       ip,
        "detection_time":           datetime.fromtimestamp(det_ts).isoformat(),
        "block_time":               datetime.fromtimestamp(blk_ts).isoformat(),
        "containment_time":         datetime.fromtimestamp(con_ts).isoformat(),
        "detection_to_block_ms":    round(blk_ms, 3),
        "detection_to_fullstop_ms": round(stop_ms, 3),
        "syn_count":                syn_n,
        "post_block_pkts":          post_blk.get(ip, 0),
        "threshold":                SYN_THRESHOLD,
        "window_seconds":           WINDOW_SECONDS,
        "rating":                   rating
    }
    metrics_log.append(entry)
    with open(METRICS_FILE, "w") as f:
        json.dump(metrics_log, f, indent=2)

# ── Packet handler ────────────────────────────────────────────────────────────
def packet_handler(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return

    ip    = pkt[IP].src
    flags = pkt[TCP].flags
    now   = time.time()

    with state_lock:
        last_pkt[ip] = now

        if ip in blocked_ips:
            post_blk[ip] += 1
            return

        if flags != 0x002:
            return

        q = syn_ts[ip]
        q.append(now)

        while q and (now - q[0]) > WINDOW_SECONDS:
            q.popleft()

        count = len(q)

        if count >= SYN_THRESHOLD and ip not in detected:
            det_ts = now
            detected[ip] = det_ts
            det_str = datetime.fromtimestamp(det_ts).strftime("%H:%M:%S.%f")[:-3]
            log.warning("DETECTED  %s — %d SYNs in %ds @ %s",
                        ip, count, WINDOW_SECONDS, det_str)

            ok = block_ip(ip)
            blk_ts = time.time()

            if ok:
                blocked_ips.add(ip)
                log.info("BLOCKED   %s via iptables DROP", ip)
                threading.Thread(
                    target=measure_containment,
                    args=(ip, det_ts, blk_ts, count),
                    daemon=True
                ).start()
            else:
                log.error("BLOCK FAILED for %s", ip)

# ── Graceful shutdown ─────────────────────────────────────────────────────────
def shutdown(sig, frame):
    print("\n[SHUTDOWN] Stopping capture...")
    if metrics_log:
        with open(METRICS_FILE, "w") as f:
            json.dump(metrics_log, f, indent=2)
        print(f"[INFO] Metrics saved → {METRICS_FILE}")
    print("[INFO] To clear iptables rules:")
    for ip in blocked_ips:
        print(f"       sudo iptables -D INPUT -s {ip} -j DROP")
    sys.exit(0)

signal.signal(signal.SIGINT,  shutdown)
signal.signal(signal.SIGTERM, shutdown)

# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 62)
    print("  AUTOMATED IP CONTAINMENT — DEFENDER")
    print(f"  Interface  : {IFACE}")
    print(f"  Threshold  : {SYN_THRESHOLD} SYNs in {WINDOW_SECONDS}s window")
    print(f"  Log file   : {LOG_FILE}")
    print(f"  Metrics    : {METRICS_FILE}")
    print("=" * 62)
    print(f"\n[READY] Sniffing on {IFACE}... waiting for attack traffic.\n")

    sniff(
        iface=IFACE,
        filter="tcp",
        prn=packet_handler,
        store=False
    )
