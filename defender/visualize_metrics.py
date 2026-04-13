#!/usr/bin/env python3
"""
=============================================================================
  visualize_metrics.py  —  SOC Lab Containment Metrics Visualizer
  VM2: Ubuntu Defender (Chiron)
  Run: python3 defender/visualize_metrics.py
=============================================================================
"""

import json, sys, os, argparse
from datetime import datetime

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.patches as mpatches
import numpy as np

# ── CLI arguments ─────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser()
parser.add_argument("--metrics", default="/tmp/containment_metrics.json")
parser.add_argument("--out",     default="/tmp/containment_report.png")
args = parser.parse_args()

# ── Load data ─────────────────────────────────────────────────────────────────
if not os.path.exists(args.metrics):
    print(f"[ERROR] Metrics file not found: {args.metrics}")
    print("        Run ip_containment.py first and trigger at least one attack.")
    sys.exit(1)

with open(args.metrics) as f:
    data = json.load(f)

if not data:
    print("[ERROR] No events recorded yet.")
    sys.exit(1)

print(f"[INFO] Loaded {len(data)} event(s) from {args.metrics}")

# ── Extract series ─────────────────────────────────────────────────────────────
n          = len(data)
event_nums = list(range(1, n + 1))
blk_ms     = [d["detection_to_block_ms"]    for d in data]
stop_ms    = [d["detection_to_fullstop_ms"] for d in data]
syn_counts = [d["syn_count"]                for d in data]
post_pkts  = [d["post_block_pkts"]          for d in data]
tail_ms    = [s - b for s, b in zip(stop_ms, blk_ms)]
det_times  = [datetime.fromisoformat(d["detection_time"])   for d in data]
con_times  = [datetime.fromisoformat(d["containment_time"]) for d in data]

avg_blk  = np.mean(blk_ms)
avg_stop = np.mean(stop_ms)
min_stop = min(stop_ms)
max_stop = max(stop_ms)
std_stop = np.std(stop_ms)

# ── Theme ──────────────────────────────────────────────────────────────────────
DARK   = "#ffffff"
PANEL  = "#f8f9fa"
BORDER = "#dee2e6"
ACCENT = "#00e5ff"
GREEN  = "#2ed573"
RED    = "#ff4757"
YELLOW = "#ffa502"
GRAY   = "#495057"
WHITE  = "#000000"

plt.rcParams.update({
    "figure.facecolor": DARK,
    "axes.facecolor":   PANEL,
    "axes.edgecolor":   BORDER,
    "axes.labelcolor":  WHITE,
    "xtick.color":      GRAY,
    "ytick.color":      GRAY,
    "text.color":       WHITE,
    "grid.color":       BORDER,
    "grid.linewidth":   0.8,
    "font.family":      "monospace",
    "font.size":        9,
})

def bar_color(val, good, warn):
    if val <= good: return GREEN
    if val <= warn: return YELLOW
    return RED

BAR_KW = dict(edgecolor=DARK, linewidth=0.6, width=0.55)

def style_ax(ax, title, xlabel="", ylabel=""):
    ax.set_title(title, color=WHITE, fontsize=10, pad=7, fontweight="bold")
    if xlabel: ax.set_xlabel(xlabel, color=GRAY, fontsize=8)
    if ylabel: ax.set_ylabel(ylabel, color=GRAY, fontsize=8)
    ax.grid(True, axis="y", alpha=0.45)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

def bar_labels(ax, bars, vals, fmt="{:.0f}"):
    for bar, val in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + max(vals) * 0.01,
                fmt.format(val), ha="center", va="bottom",
                fontsize=7, color=WHITE)

x     = np.array(event_nums)
x_lbl = [str(i) for i in event_nums]

# ── Figure ─────────────────────────────────────────────────────────────────────
fig = plt.figure(figsize=(22, 15), dpi=110, facecolor="white")
fig.suptitle("SOC LAB — IP CONTAINMENT METRICS REPORT",
             fontsize=15, color=ACCENT, fontweight="bold", y=0.975)
fig.text(0.5, 0.955,
         f"Events: {n}  |  Avg Block: {avg_blk:.1f}ms  |  "
         f"Avg Full-Stop: {avg_stop:.1f}ms  |  "
         f"Min: {min_stop:.1f}ms  |  Max: {max_stop:.1f}ms",
         ha="center", fontsize=9, color=GRAY)

gs = fig.add_gridspec(3, 3, hspace=0.52, wspace=0.38,
                      left=0.06, right=0.97, top=0.935, bottom=0.055)

# [1] Detection → Block
ax1 = fig.add_subplot(gs[0, 0])
c1  = [bar_color(v, 10, 50) for v in blk_ms]
b1  = ax1.bar(x, blk_ms, color=c1, **BAR_KW)
ax1.axhline(avg_blk, color=ACCENT, linewidth=1.2, linestyle="--",
            label=f"avg {avg_blk:.1f}ms")
bar_labels(ax1, b1, blk_ms, "{:.1f}")
style_ax(ax1, "[1] Detection → Block (ms)", "Event", "ms")
ax1.set_xticks(x); ax1.set_xticklabels(x_lbl)
ax1.legend(fontsize=7.5)

# [2] Detection → Full Stop
ax2 = fig.add_subplot(gs[0, 1])
c2  = [bar_color(v, 1000, 2500) for v in stop_ms]
b2  = ax2.bar(x, stop_ms, color=c2, **BAR_KW)
ax2.axhline(avg_stop, color=ACCENT, linewidth=1.2, linestyle="--",
            label=f"avg {avg_stop:.1f}ms")
ax2.axhline(3000, color=RED, linewidth=1.0, linestyle=":",
            alpha=0.7, label="3000ms target")
bar_labels(ax2, b2, stop_ms, "{:.0f}")
style_ax(ax2, "[2] Detection → Full Stop (ms)", "Event", "ms")
ax2.set_xticks(x); ax2.set_xticklabels(x_lbl)
ax2.legend(fontsize=7.5)

# [3] SYN count
ax3 = fig.add_subplot(gs[0, 2])
b3  = ax3.bar(x, syn_counts, color=RED + "bb", **BAR_KW)
ax3.axhline(30, color=YELLOW, linewidth=1.2, linestyle="--", label="threshold=30")
bar_labels(ax3, b3, syn_counts, "{:.0f}")
style_ax(ax3, "[3] SYN Count at Detection", "Event", "Packets")
ax3.set_xticks(x); ax3.set_xticklabels(x_lbl)
ax3.legend(fontsize=7.5)

# [4] Post-block leakage
ax4 = fig.add_subplot(gs[1, 0])
c4  = [bar_color(v, 0.5, 5) for v in post_pkts]
b4  = ax4.bar(x, post_pkts, color=c4, **BAR_KW)
bar_labels(ax4, b4, post_pkts, "{:.0f}")
style_ax(ax4, "[4] Post-Block Packet Leak", "Event", "Packets")
ax4.set_xticks(x); ax4.set_xticklabels(x_lbl)
pg = mpatches.Patch(color=GREEN,  label="0 = clean")
py = mpatches.Patch(color=YELLOW, label="1-4 = minor")
pr = mpatches.Patch(color=RED,    label="5+ = concern")
ax4.legend(handles=[pg, py, pr], fontsize=7)

# [5] Stacked breakdown
ax5 = fig.add_subplot(gs[1, 1])
ax5.bar(x, blk_ms,  color=ACCENT + "cc", label="Det → Block",     **BAR_KW)
ax5.bar(x, tail_ms, color=YELLOW + "cc", label="Block → FullStop",
        bottom=blk_ms, **BAR_KW)
style_ax(ax5, "[5] Latency Breakdown (Stacked)", "Event", "ms")
ax5.set_xticks(x); ax5.set_xticklabels(x_lbl)
ax5.legend(fontsize=7.5)

# [6] Scatter
ax6 = fig.add_subplot(gs[1, 2])
c6  = [bar_color(v, 1000, 2500) for v in stop_ms]
ax6.scatter(syn_counts, stop_ms, c=c6, s=75, zorder=4, alpha=0.9)
for i, (sx, sy) in enumerate(zip(syn_counts, stop_ms)):
    ax6.annotate(f"#{i+1}", (sx, sy), textcoords="offset points",
                 xytext=(5, 3), fontsize=7, color=GRAY)
style_ax(ax6, "[6] SYN Count vs Containment Speed",
         "SYN Count", "Full-Stop (ms)")
ax6.grid(True, alpha=0.35)

# [7] Timeline
ax7 = fig.add_subplot(gs[2, :2])
ax7.scatter(det_times, [1.0]*n, color=RED,   s=70, zorder=5,
            marker="^", label="Detection")
ax7.scatter(con_times, [1.8]*n, color=GREEN, s=70, zorder=5,
            marker="v", label="Contained")
for dt, ct, ms in zip(det_times, con_times, stop_ms):
    ax7.annotate("", xy=(ct, 1.8), xytext=(dt, 1.0),
                 arrowprops=dict(arrowstyle="->", color=ACCENT, lw=0.9))
    mid = dt + (ct - dt) / 2
    ax7.text(mid, 1.41, f"{ms:.0f}ms", ha="center", fontsize=7.5, color=ACCENT)
ax7.set_yticks([1.0, 1.8])
ax7.set_yticklabels(["  Detected", "  Contained"], fontsize=9)
ax7.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
ax7.set_ylim(0.5, 2.3)
ax7.set_title("[7] Event Timeline", color=WHITE, fontsize=10, pad=7, fontweight="bold")
ax7.set_xlabel("Time", color=GRAY, fontsize=8)
ax7.grid(True, axis="x", alpha=0.35)
ax7.spines["top"].set_visible(False)
ax7.spines["right"].set_visible(False)
ax7.legend(fontsize=8)

# [8] KPI panel
ax8 = fig.add_subplot(gs[2, 2])
ax8.set_xlim(0, 1); ax8.set_ylim(0, 1); ax8.axis("off")
ax8.text(0.5, 0.96, "[8] SUMMARY", ha="center", va="top",
         fontsize=11, color=ACCENT, fontweight="bold")
overall_pass = avg_stop < 3000
kpis = [
    ("Total events",      str(n),               WHITE),
    ("Avg block",         f"{avg_blk:.1f} ms",  GREEN if avg_blk < 50 else YELLOW),
    ("Avg full-stop",     f"{avg_stop:.1f} ms",  GREEN if avg_stop < 3000 else RED),
    ("Best",              f"{min_stop:.1f} ms",  GREEN),
    ("Worst",             f"{max_stop:.1f} ms",  YELLOW if max_stop < 3000 else RED),
    ("Std deviation",     f"{std_stop:.1f} ms",  WHITE),
    ("3s target",         "PASS" if overall_pass else "FAIL",
                           GREEN if overall_pass else RED),
]
for i, (label, val, color) in enumerate(kpis):
    yp = 0.83 - i * 0.115
    ax8.text(0.04, yp, label + ":", ha="left",  va="center", fontsize=8.5, color=GRAY)
    ax8.text(0.96, yp, val,         ha="right", va="center", fontsize=8.5,
             color=color, fontweight="bold")
    if i < len(kpis) - 1:
        ax8.plot([0.03, 0.97], [yp - 0.052, yp - 0.052],
                 color=BORDER, linewidth=0.6)

fig.text(0.5, 0.015,
         f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  "
         f"Threshold: {data[0].get('threshold',30)} SYNs / "
         f"{data[0].get('window_seconds',5)}s window",
         ha="center", fontsize=7.5, color=GRAY)

plt.savefig(args.out, dpi=110, bbox_inches="tight", facecolor="white")

print(f"\n{'='*50}")
print(f"  REPORT SAVED → {args.out}")
print(f"  Events      : {n}")
print(f"  Avg block   : {avg_blk:.1f} ms")
print(f"  Avg stop    : {avg_stop:.1f} ms")
print(f"  3s target   : {'PASS' if overall_pass else 'FAIL'}")
print(f"{'='*50}\n")
