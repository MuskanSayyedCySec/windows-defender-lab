"""Turns the events CSV from Defender-HealthReport.ps1 into a bar chart.

Usage:  python3 chart_events.py events_2026-11-16_1625.csv
Needs:  pip install matplotlib
"""
import csv
import sys
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt

csv_path = Path(sys.argv[1])

# Count how many events there are of each type
with open(csv_path, newline="", encoding="utf-8-sig") as f:
    counts = Counter(f"{row['EventID']}  {row['EventType']}" for row in csv.DictReader(f))

# Largest at the top
labels, values = zip(*sorted(counts.items(), key=lambda item: item[1]))

fig, ax = plt.subplots(figsize=(8, 3.2))
bars = ax.barh(labels, values, color="#2a78d6", height=0.55)
ax.bar_label(bars, padding=4, color="#0b0b0b")

ax.set_title("Microsoft Defender events by type", loc="left", fontweight="bold")
ax.set_xlabel("Number of events")
ax.set_xlim(0, max(values) + 1)
ax.xaxis.get_major_locator().set_params(integer=True)
ax.spines[["top", "right", "left"]].set_visible(False)
ax.tick_params(axis="y", length=0)
ax.grid(axis="x", color="#e4e3df", linewidth=0.8)
ax.set_axisbelow(True)

out_path = csv_path.with_name("events_by_type.png")
fig.savefig(out_path, dpi=200, bbox_inches="tight", facecolor="white")
print(f"Chart saved to {out_path}")
