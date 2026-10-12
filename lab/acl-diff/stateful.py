# SPDX-License-Identifier: Apache-2.0
"""Black-box collection of the official client's stateful filtering.

Policy: only ts2 → ts1 is allowed; ts1 may not initiate to ts2. Observes whether ts1's replies to connections ts2 initiated reach ts2,
each with a control: the same kind of packet that belongs to no connection.
Usage (from the repository root): python3 lab/acl-diff/stateful.py
"""
import datetime
import json
import os
import time

import run as base

SEND = """
import socket, sys, json
from scapy.all import IP, TCP, UDP, Raw
spec = json.loads(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
ip = IP(src=spec["src"], dst=spec["dst"])
if spec["proto"] == "udp":
    pkt = ip / UDP(sport=spec["sport"], dport=spec["dport"]) / Raw(load=spec["id"].encode())
else:
    pkt = ip / TCP(sport=spec["sport"], dport=spec["dport"], flags=spec["flags"], seq=5000, ack=1)
s.sendto(bytes(pkt), (spec["dst"], 0))
"""


def netshoot(container, *cmd, detach=False, name=None):
    args = ["docker", "run", "--rm", "--net", f"container:{container}", "--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN"]
    if detach:
        args += ["-d"]
    if name:
        args += ["--name", name]
    return base.sh(args + [base.NETSHOOT, *cmd])


def send(container, **spec):
    netshoot(container, "python3", "-c", SEND, json.dumps(spec))


def main():
    ts1, ts2 = base.ts_ip("ts1"), base.ts_ip("ts2")
    policy = base.apply_policy([{"action": "accept", "src": [ts2], "dst": [f"{ts1}:*"]}])
    rules, changed = base.wait_rules_change(base.ts2_rules())
    date = datetime.date.today().strftime("%Y%m%d")
    out_dir = os.path.join(base.ROOT, "fixtures", "observed", f"{date}-acl-stateful")
    os.makedirs(out_dir, exist_ok=True)

    listener = f"acl-listen-{os.getpid()}"
    netshoot(base.TS1_C, "nc", "-lk", "-p", "5555", detach=True, name=listener)
    cap = f"acl-cap-{os.getpid()}"
    base.sh(["docker", "run", "-d", "--rm", "--name", cap, "--net", f"container:{base.TS2_C}",
             "-v", f"{out_dir}:/out", base.NETSHOOT, "tcpdump", "-i", "tailscale0", "-n", "-U",
             "-w", "/out/stateful.pcap", "src", "host", ts1])
    cap1 = f"acl-cap1-{os.getpid()}"
    base.sh(["docker", "run", "-d", "--rm", "--name", cap1, "--net", f"container:{base.TS1_C}",
             "-v", f"{out_dir}:/out", base.NETSHOOT, "tcpdump", "-i", "tailscale0", "-n", "-U",
             "-w", "/out/stateful-ts1-egress.pcap", "icmp", "and", "dst", "host", ts2])
    time.sleep(2)
    try:
        # S1: ts2 initiates a TCP connection to ts1:5555 (listening) → does ts1's SYN-ACK reach ts2?
        netshoot(base.TS2_C, "sh", "-c", f"nc -z -w 2 {ts1} 5555 || true")
        # S1-control: ts1 sends a SYN-ACK to ts2 that belongs to no connection.
        send(base.TS1_C, id="s1c", proto="tcp", src=ts1, dst=ts2, sport=7777, dport=46666, flags="SA")
        # S2: ts2 sends UDP 47000 → ts1:5353 first, then ts1 replies 5353 → ts2:47000.
        send(base.TS2_C, id="s2-out", proto="udp", src=ts2, dst=ts1, sport=47000, dport=5353)
        time.sleep(0.5)
        send(base.TS1_C, id="s2-reply", proto="udp", src=ts1, dst=ts2, sport=5353, dport=47000)
        # S2-control: ts1 sends to the same ts2 port from a different source port (not that flow).
        send(base.TS1_C, id="s2-control", proto="udp", src=ts1, dst=ts2, sport=5354, dport=47000)
        # S3: ts2 sends UDP to a closed port on ts1 → ICMP port-unreachable produced by ts1's kernel (with embedded original packet).
        send(base.TS2_C, id="s3-out", proto="udp", src=ts2, dst=ts1, sport=48000, dport=9)
        time.sleep(2)
    finally:
        base.sh(["docker", "stop", cap])
        base.sh(["docker", "stop", cap1])
        base.sh(["docker", "stop", listener])

    fields = base.sh(["docker", "run", "--rm", "-v", f"{out_dir}:/out", base.NETSHOOT, "tshark", "-r", "/out/stateful.pcap",
                      "-T", "fields", "-e", "ip.proto", "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "tcp.flags",
                      "-e", "udp.srcport", "-e", "udp.dstport", "-e", "icmp.type", "-e", "icmp.code"])
    seen = []
    for line in fields.splitlines():
        # A packet with an embedded IP header (an ICMP error) gets multi-valued fields such as "1,17"; take only the outer header's value.
        f = [x.split(",")[0] for x in (line.split("\t") + [""] * 8)[:8]]
        seen.append({"proto": f[0], "tcp": f[1:4], "udp": f[4:6], "icmp": f[6:8]})

    def any_seen(pred):
        return any(pred(s) for s in seen)

    egress = base.sh(["docker", "run", "--rm", "-v", f"{out_dir}:/out", base.NETSHOOT, "tshark", "-r",
                      "/out/stateful-ts1-egress.pcap", "-T", "fields", "-e", "icmp.type", "-e", "icmp.code"])
    ts1_sent_unreachable = any(l.split("\t")[:2] == ["3", "3"] for l in egress.splitlines())
    results = {
        "control-ts1-actually-sent-icmp-port-unreachable": ts1_sent_unreachable,
        "s1-synack-after-outbound": any_seen(lambda s: s["proto"] == "6" and s["tcp"][0] == "5555" and s["tcp"][2] and int(s["tcp"][2], 16) & 0x12 == 0x12),
        "s1-control-unsolicited-synack": any_seen(lambda s: s["proto"] == "6" and s["tcp"][0] == "7777"),
        "s2-udp-reply-after-outbound": any_seen(lambda s: s["proto"] == "17" and s["udp"] == ["5353", "47000"]),
        "s2-control-other-sport": any_seen(lambda s: s["proto"] == "17" and s["udp"] == ["5354", "47000"]),
        "s3-icmp-port-unreachable-for-outbound": any_seen(lambda s: s["proto"] == "1" and s["icmp"] == ["3", "3"]),
    }
    with open(os.path.join(out_dir, "cases.json"), "w") as f:
        json.dump({"policy": policy, "rules_changed": changed, "rules": rules, "ts1": ts1, "ts2": ts2,
                   "observed": results, "raw_packets_seen_at_ts2": seen}, f, indent=2, sort_keys=True)
    with open(os.path.join(out_dir, "manifest.json"), "w") as f:
        json.dump({"label": "acl-stateful", "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                   "method": "lab/acl-diff/stateful.py", "files": ["cases.json", "stateful.pcap", "stateful-ts1-egress.pcap"]}, f, indent=2)
    for k, v in results.items():
        print(f"{k:42s} delivered={v}")
    base.apply_policy([{"action": "accept", "src": ["*"], "dst": ["*:*"]}])


if __name__ == "__main__":
    main()
