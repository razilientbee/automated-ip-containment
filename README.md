# Automated Malicious IP Containment

Real-time SYN flood detection and automatic iptables blocking — 2-node SOC lab.

## Lab Setup
| VM   | OS                  | IP               | Role     |
|------|---------------------|------------------|----------|
| VM1  | Kali Linux (latest) | 192.168.100.10   | Attacker |
| VM2  | Ubuntu 22.04/24.04  | 192.168.100.20   | Defender |

## Detection Logic
- Sniffs TCP traffic in real time using Scapy
- Sliding 5-second window counts SYN packets per source IP
- Threshold: 30 SYNs triggers an iptables DROP rule
- Measures Detection to Block and Detection to FullStop latency in ms
- Writes metrics to JSON, visualized as 8-chart PNG report

## Project Structure
automated-ip-containment/
├── defender/
│   ├── ip_containment.py       # Main detection + blocking script
│   └── visualize_metrics.py    # 8-chart metrics visualizer
├── attacker/
│   └── malicious_flood.py      # SYN flood attack script
├── setup/
│   ├── setup_defender_vm.sh    # One-time Ubuntu VM setup
│   └── setup_attacker_vm.sh    # One-time Kali VM setup
├── verify/
│   └── verify_containment.sh  # All verification commands
├── COMMANDS.txt                # Complete command reference
└── README.md

## Network Interfaces
- Kali interface   : eth1
- Ubuntu interface : enp0s8

## Quick Start
```bash
# VM2 — Ubuntu (Chiron)
sudo python3 defender/ip_containment.py

# VM1 — Kali
sudo hping3 -S -p 80 --flood 192.168.100.20
```

## Target Performance
| Metric                  | Target     |
|-------------------------|------------|
| Detection to Block      | < 100 ms   |
| Detection to Full Stop  | < 3000 ms  |
| Post-block leakage      | < 10 pkts  |

## Results

### First Successful Containment
| Metric                  | Result       |
|-------------------------|--------------|
| Detection → Block       | 586.261 ms   |
| Detection → Full Stop   | 2751.683 ms  |
| Rating                  | GOOD         |
| Post-block leakage      | 68 packets   |
| 3s target               | PASS ✅      |

## Final Results — 5 Use Case Trials

| Event | Use Case                  | Block Latency | Rating    |
|-------|---------------------------|---------------|-----------|
| 1     | High-Rate SYN Flood       | 14.781 ms     | EXCELLENT |
| 2     | Slow-Rate SYN Flood       | 12.211 ms     | EXCELLENT |
| 3     | Multi-Port Flood          | 20.824 ms     | GOOD      |
| 4     | Reconnaissance + Flood    | 22.881 ms     | GOOD      |
| 5     | Re-attack After Containment | 27.103 ms   | GOOD      |

**Average containment: 19.6 ms — all trials PASS**
