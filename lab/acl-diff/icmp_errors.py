# SPDX-License-Identifier: Apache-2.0
"""Receiver-side semantics of ICMPv4 errors (attribution experiment): fm1 (flowmesh, no outbound filtering) sends to the official client ts1,
varying the embedded original packet. Observed on ts1's tailscale0.
Usage (from the repository root): python3 lab/acl-diff/icmp_errors.py
"""
import datetime
import json
import os
import time

import run as base

SEND = r'''
import socket, sys, json
from scapy.all import IP, ICMP, UDP, Raw
spec = json.loads(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
for n, e in enumerate(spec["errors"], start=1):
    if e["embed"] == "garbage":
        inner = Raw(load=b"icmp-unreachable")
    elif e["embed"] == "x8":
        inner = Raw(load=b"x" * 8)
    else:
        inner = IP(src=e["isrc"], dst=e["idst"]) / UDP(sport=e["isport"], dport=e["idport"])
    # The outer IP ID tags each error, so detection does not depend on how tshark parses the embedded packet.
    pkt = IP(src=spec["src"], dst=spec["dst"], id=n) / ICMP(type=e["type"], code=e["code"]) / inner
    s.sendto(bytes(pkt), (spec["dst"], 0))
    __import__("time").sleep(0.3)
'''


def main():
    fm1, ts1 = base.ts_ip("fm1"), base.ts_ip("ts1")
    errors = [
        {"id": "garbage", "type": 3, "code": 3, "embed": "garbage"},
        {"id": "x8", "type": 3, "code": 3, "embed": "x8"},
        {"id": "related", "type": 3, "code": 3, "embed": "ip", "isrc": ts1, "idst": fm1, "isport": 47000, "idport": 5353},
        {"id": "unrelated", "type": 3, "code": 3, "embed": "ip", "isrc": ts1, "idst": fm1, "isport": 47099, "idport": 5399},
        {"id": "time-exceeded-related", "type": 11, "code": 0, "embed": "ip", "isrc": ts1, "idst": fm1, "isport": 47000, "idport": 5353},
    ]
    date = datetime.date.today().strftime("%Y%m%d")
    out_dir = os.path.join(base.ROOT, "fixtures", "observed", f"{date}-icmp-errors-receiver")
    os.makedirs(out_dir, exist_ok=True)
    results = {}
    for pol_name, acls in [("allow-all", [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]), ("deny-all", [])]:
        base.apply_policy(acls)
        time.sleep(5)
        # ts1 first initiates a UDP flow 47000 -> fm1:5353, so "related" refers to a flow ts1 really started.
        base.sh(["docker", "run", "--rm", "--net", f"container:{base.TS1_C}", "--cap-add", "NET_RAW", base.NETSHOOT,
                 "python3", "-c", f"import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('{ts1}',47000)); s.sendto(b'hi', ('{fm1}',5353))"])
        cap = f"icmp-cap-{os.getpid()}"
        pcap = f"{pol_name}.pcap"
        base.sh(["docker", "run", "-d", "--rm", "--name", cap, "--net", f"container:{base.TS1_C}", "-v", f"{out_dir}:/out",
                 base.NETSHOOT, "tcpdump", "-i", "tailscale0", "-n", "-U", "-w", f"/out/{pcap}", "icmp", "and", "src", "host", fm1])
        time.sleep(2)
        base.compose("fm1", "python3", "-c", SEND, json.dumps({"src": fm1, "dst": ts1, "errors": errors}))
        time.sleep(2)
        base.sh(["docker", "stop", cap])
        fields = base.sh(["docker", "run", "--rm", "-v", f"{out_dir}:/out", base.NETSHOOT, "tshark", "-r", f"/out/{pcap}",
                          "-T", "fields", "-e", "ip.id"])
        ids = {int(line.split(",")[0], 16) for line in fields.split() if line}
        results[pol_name] = {e["id"]: (n in ids) for n, e in enumerate(errors, start=1)}
        print(pol_name, results[pol_name])
    base.apply_policy([{"action": "accept", "src": ["*"], "dst": ["*:*"]}])
    with open(os.path.join(out_dir, "cases.json"), "w") as f:
        json.dump({"sender": "fm1 (flowmesh, no outbound filter)", "receiver": "ts1 (official 1.94.2)", "fm1": fm1, "ts1": ts1,
                   "errors": errors, "observed": results}, f, indent=2, sort_keys=True)
    with open(os.path.join(out_dir, "manifest.json"), "w") as f:
        json.dump({"label": "icmp-errors-receiver", "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                   "method": "lab/acl-diff/icmp_errors.py", "files": ["cases.json", "allow-all.pcap", "deny-all.pcap"]}, f, indent=2)


if __name__ == "__main__":
    main()
