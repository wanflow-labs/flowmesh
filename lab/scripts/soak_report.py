#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Judge a soak run (lab/scripts/soak.sh output): memory trend, fds, reconnects vs injected faults,
state, and traffic. Usage: soak_report.py OUT_DIR [--window-hours 48]"""
import csv
import datetime as dt
import sys

out = sys.argv[1]
window_h = float(sys.argv[sys.argv.index("--window-hours") + 1]) if "--window-hours" in sys.argv else 48.0
rows = list(csv.DictReader(open(f"{out}/samples.csv")))
rows = [r for r in rows if r["rss_kb"]]
ts = lambda s: dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
t0 = ts(rows[0]["time"])
hours = [(ts(r["time"]) - t0).total_seconds() / 3600 for r in rows]
rss = [int(r["rss_kb"]) for r in rows]
fds = [int(r["fds"]) for r in rows]
threads = [int(r["threads"]) for r in rows]
fails = []

# Memory: least-squares slope over the last window (skip warm-up); projected growth over the window.
span = hours[-1]
w = [(h, m) for h, m in zip(hours, rss) if h >= max(0.0, span - window_h)]
n = len(w)
mh = sum(h for h, _ in w) / n
mm = sum(m for _, m in w) / n
den = sum((h - mh) ** 2 for h, _ in w) or 1.0
slope = sum((h - mh) * (m - mm) for h, m in w) / den  # kB per hour
growth = slope * min(window_h, span)
median = sorted(rss)[len(rss) // 2]
print(f"samples {len(rows)} over {span:.1f} h; RSS median {median/1024:.1f} MB, min {min(rss)/1024:.1f}, max {max(rss)/1024:.1f}")
print(f"RSS trend over the last {min(window_h, span):.1f} h: {slope:+.1f} kB/h -> {growth/1024:+.2f} MB")
if growth > 5 * 1024 or growth > 0.10 * median:
    fails.append(f"sustained memory growth: {growth/1024:+.2f} MB over the window")
print(f"fds {min(fds)}..{max(fds)}; threads {min(threads)}..{max(threads)}")
if max(fds) - min(fds) > 10:
    fails.append(f"fd count varies by {max(fds) - min(fds)}")

# Reconnects must each follow an injected fault within 5 minutes.
events = [l.split(" ", 2) for l in open(f"{out}/events.log").read().splitlines()]
faults = [(ts(e[0]), e[2] if len(e) > 2 else e[1]) for e in events if e[1] == "fault"]
def unexplained(col, kinds):
    bad = []
    for prev, cur in zip(rows, rows[1:]):
        if int(cur[col]) > int(prev[col]):
            t = ts(cur["time"])
            if not any(k in kind and dt.timedelta(0) <= t - ft <= dt.timedelta(minutes=5) for ft, kind in faults for k in kinds):
                bad.append(cur["time"])
    return bad
ctl_bad = unexplained("control_reconnects", ["control"])
derp_bad = unexplained("derp_connects", ["derp", "control"])
print(f"faults injected: {len(faults)}; control reconnects {rows[-1]['control_reconnects']}, relay connects {rows[-1]['derp_connects']}")
if ctl_bad:
    fails.append(f"control reconnects without a fault: {ctl_bad}")
if derp_bad:
    fails.append(f"relay reconnects without a fault: {derp_bad}")

# The other direction: a fault that should force a reconnect must be followed by one within 5
# minutes (a short control outage need not: TCP rides it out under the 120 s idle limit).
def missing(kind, col):
    bad = []
    for ft, k in faults:
        if kind not in k:
            continue
        before = [r for r in rows if ts(r["time"]) <= ft]
        after = [r for r in rows if ft < ts(r["time"]) <= ft + dt.timedelta(minutes=5)]
        if before and after and int(after[-1][col]) <= int(before[-1][col]):
            bad.append(ft.isoformat())
    return bad
for kind, col in (("control-restart", "control_reconnects"), ("derp-restart", "derp_connects")):
    m = missing(kind, col)
    if m:
        fails.append(f"{kind} not followed by a reconnect within 5 min: {m}")

states = {}
for r in rows:
    states[r["state"]] = states.get(r["state"], 0) + 1
print(f"BackendState samples: {states}")
if any(s != "Running" for s in states):
    fails.append(f"not Running in {sum(v for k, v in states.items() if k != 'Running')} samples")

# Traffic: ping's own final statistics (ping-summary.txt, fmsd then wm1) when the run finished. The
# per-sample columns are only an estimate (sent = seconds elapsed, replies still in flight not yet
# counted) and read low after slow replies: use them only for a run that did not finish.
import os
import re
final = []
if os.path.exists(f"{out}/ping-summary.txt"):
    final = re.findall(r"(\d+) packets transmitted, (\d+) (?:packets )?received", open(f"{out}/ping-summary.txt").read())
last = rows[-1]
for i, peer in enumerate(("fmsd", "wm1")):
    if len(final) == 2:
        sent, got = map(int, final[i])
        src = "final"
    else:
        sent, got = int(last[f"ping_{peer}_tx"]), int(last[f"ping_{peer}_rx"])
        src = "estimate, run did not finish"
    ratio = got / sent if sent else 0
    print(f"ping {peer}: {got}/{sent} answered ({ratio:.2%}, {src})")
    if ratio < 0.99:
        fails.append(f"ping {peer} answered {ratio:.2%}")

print("FAIL:\n  " + "\n  ".join(fails) if fails else "ok: soak passed")
sys.exit(1 if fails else 0)
