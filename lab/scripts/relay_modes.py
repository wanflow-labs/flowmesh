# SPDX-License-Identifier: Apache-2.0
"""Relay-mode differential: apply the same relay tags to wanflow-mesh (wm1, reference) and flowmesh (fm1) in turn, and observe
whether traffic from the official client ts1 to each goes direct or via relay, and whether any direct UDP appears between them.
Usage (from the repository root): python3 lab/scripts/relay_modes.py
"""
import datetime
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "acl-diff"))
import run as base  # noqa: E402

# Same tag combinations as production (prefer = relay-force; strict = relay-force + relay-strict).
MODES = [
    ("auto", ["tag:relay-enabled"]),
    ("prefer", ["tag:relay-enabled", "tag:relay-force"]),
    ("strict", ["tag:relay-enabled", "tag:relay-force", "tag:relay-strict"]),
    ("auto-again", ["tag:relay-enabled"]),
]
TARGETS = {"wm1": "172.29.0.41", "fm1": "172.29.0.31"}


def node_ids():
    nodes = json.loads(base.compose("headscale", "headscale", "nodes", "list", "-o", "json"))
    return {n["given_name"]: (n["id"], n["ip_addresses"][0]) for n in nodes if n.get("online")}


def path_from_ts1(tailnet_ip):
    import re
    for line in base.compose("ts1", "tailscale", "status").splitlines():
        if line.startswith(tailnet_ip + " "):
            m = re.search(r"(direct [^,]+|relay \"[^\"]+\")", line)
            return m.group(1) if m else line.strip()
    return "?"


def restart(target):
    """Restart the tagged node so the measurement reflects a fresh session (in production, tags are fixed at registration)."""
    if target == "wm1":
        base.sh(["docker", "restart", "flowmesh-lab-wm1-1"])
        time.sleep(6)
    else:
        base.sh([os.path.join(base.LAB, "scripts", "fm1.sh"), "start"])
        time.sleep(3)


def main():
    base.apply_policy([{"action": "accept", "src": ["*"], "dst": ["*:*"]}])
    ids = node_ids()
    date = datetime.date.today().strftime("%Y%m%d")
    out_dir = os.path.join(base.ROOT, "fixtures", "observed", f"{date}-relay-modes")
    os.makedirs(out_dir, exist_ok=True)
    results = []
    for target, eth in TARGETS.items():
        name = next(n for n in ids if n == target or n.startswith(target + "-"))
        node_id, tailnet_ip = ids[name]
        for (mode, tags), fresh in [(m, f) for m in MODES for f in (False, True)]:
            base.compose("headscale", "headscale", "nodes", "tag", "-i", str(node_id), "-t", ",".join(tags))
            time.sleep(8)
            if fresh:
                restart(target)
                mode = mode + "/fresh"
            cap = f"relay-cap-{os.getpid()}"
            pcap = f"{target}-{mode.replace('/', '-')}.pcap"
            base.sh(["docker", "run", "-d", "--rm", "--name", cap, "--net", f"container:{base.TS1_C}", "-v", f"{out_dir}:/out",
                     base.NETSHOOT, "tcpdump", "-i", "eth0", "-n", "-U", "-w", f"/out/{pcap}", "udp", "and", "host", eth,
                     "and", "not", "port", "3478"])
            time.sleep(2)
            base.compose("ts1", "sh", "-c", f"ping -c 16 -i 0.5 -W 2 {tailnet_ip} >/dev/null || true")
            time.sleep(1)
            base.sh(["docker", "stop", cap])
            counts = base.sh(["docker", "run", "--rm", "-v", f"{out_dir}:/out", base.NETSHOOT, "tshark", "-r", f"/out/{pcap}",
                              "-T", "fields", "-e", "ip.src"])
            to_t = sum(1 for l in counts.split() if l == "172.29.0.21")
            from_t = sum(1 for l in counts.split() if l == eth)
            row = {"target": target, "mode": mode, "tags": tags, "path_seen_by_ts1": path_from_ts1(tailnet_ip),
                   "udp_ts1_to_target": to_t, "udp_target_to_ts1": from_t}
            results.append(row)
            print(f"{target:4s} {mode:17s} path={row['path_seen_by_ts1'][:34]:34s} udp ts1->t={to_t:3d} t->ts1={from_t:3d}")
    with open(os.path.join(out_dir, "results.json"), "w") as f:
        json.dump(results, f, indent=2)
    with open(os.path.join(out_dir, "manifest.json"), "w") as f:
        json.dump({"label": "relay-modes", "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                   "method": "lab/scripts/relay_modes.py", "reference": "wm1 = wanflow-mesh (WanFlow fork)",
                   "files": ["results.json", "*.pcap"]}, f, indent=2)


if __name__ == "__main__":
    main()
