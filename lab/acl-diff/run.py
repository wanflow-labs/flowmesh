# SPDX-License-Identifier: Apache-2.0
"""Black-box collection of the official client's filtering behavior (M3 Task 1).

For each policy: apply it on headscale → wait for ts2's rules to change → capture on ts2's tailscale0 →
send the probe packets from ts1 → record which probes reached ts2.
Output goes to fixtures/observed/<date>-acl-diff/cases.json.
Usage (from the repository root): python3 lab/acl-diff/run.py
"""
import datetime
import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LAB = os.path.join(ROOT, "lab")
HERE = os.path.join(LAB, "acl-diff")
NETSHOOT = "nicolaka/netshoot:v0.13"
OTHER = "100.64.0.99"
TS1_C, TS2_C = "flowmesh-lab-ts1-1", "flowmesh-lab-ts2-1"


def sh(args, **kw):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kw).stdout


def compose(*args, stdin=None):
    return sh(["docker", "compose", "-f", os.path.join(LAB, "compose.yaml"), "exec", "-T", *args], input=stdin)


def ts_ip(svc):
    return compose(svc, "tailscale", "ip", "-4").strip()


def ts2_rules():
    netmap = json.loads(compose("ts2", "tailscale", "debug", "netmap"))
    return netmap.get("PacketFilterRules") or []


def probes(ts1, ts2, ts1_6, ts2_6):
    out = []
    for port in [22, 80, 443, 8000, 8100, 8101, 65535]:
        out.append({"id": f"tcp-syn-{port}", "proto": "tcp", "dport": port, "tcp_flags": "S"})
    for port in [80, 9999]:
        out.append({"id": f"tcp-ack-{port}", "proto": "tcp", "dport": port, "tcp_flags": "A"})
    for port in [53, 8050, 40000]:
        out.append({"id": f"udp-{port}", "proto": "udp", "dport": port, "tcp_flags": ""})
    out.append({"id": "icmp-echo", "proto": "icmp", "dport": 0, "tcp_flags": "", "icmp_type": 8})
    out.append({"id": "icmp-echo-reply", "proto": "icmp", "dport": 0, "tcp_flags": "", "icmp_type": 0})
    out.append({"id": "icmp-timestamp", "proto": "icmp", "dport": 0, "tcp_flags": "", "icmp_type": 13})
    out.append({"id": "icmp-timestamp-reply", "proto": "icmp", "dport": 0, "tcp_flags": "", "icmp_type": 14})
    out.append({"id": "icmp-unreachable", "proto": "icmp", "dport": 0, "tcp_flags": "", "icmp_type": 3})
    out.append({"id": "icmp-time-exceeded", "proto": "icmp", "dport": 0, "tcp_flags": "", "icmp_type": 11})
    out.append({"id": "gre", "proto": "gre", "dport": 0, "tcp_flags": ""})
    for p in out:
        p.update({"src": ts1, "dst": ts2})
    v6 = [
        {"id": "v6-tcp-syn-80", "proto": "tcp", "dport": 80, "tcp_flags": "S"},
        {"id": "v6-tcp-syn-8101", "proto": "tcp", "dport": 8101, "tcp_flags": "S"},
        {"id": "v6-tcp-ack-9999", "proto": "tcp", "dport": 9999, "tcp_flags": "A"},
        {"id": "v6-udp-53", "proto": "udp", "dport": 53, "tcp_flags": ""},
        {"id": "v6-icmp6-echo", "proto": "icmp6", "dport": 0, "tcp_flags": "", "icmp_type": 128},
        {"id": "v6-icmp6-echo-reply", "proto": "icmp6", "dport": 0, "tcp_flags": "", "icmp_type": 129},
    ]
    for p in v6:
        p.update({"src": ts1_6, "dst": ts2_6})
    return out + v6


def substitute(obj, mapping):
    text = json.dumps(obj)
    for k, v in mapping.items():
        text = text.replace("{" + k + "}", v)
    return json.loads(text)


def apply_policy(acls):
    policy = {"tagOwners": {"tag:relay-enabled": ["lab@"]}, "acls": acls}
    compose("headscale", "sh", "-c", "cat > /tmp/acl-diff-policy.json", stdin=json.dumps(policy))
    compose("headscale", "headscale", "policy", "set", "-f", "/tmp/acl-diff-policy.json")
    return policy


def wait_rules_change(before, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        now = ts2_rules()
        if json.dumps(now, sort_keys=True) != json.dumps(before, sort_keys=True):
            time.sleep(2)
            return ts2_rules(), True
        time.sleep(1)
    return ts2_rules(), False


def classify(fields):
    proto, tdport, tflags, udport, icmptype, nxt, icmp6type = (fields + [""] * 7)[:7]
    if nxt:
        prefix = "v6-"
        if nxt == "6":
            flags = int(tflags, 16) if tflags else 0
            return f"{prefix}tcp-{'syn' if flags & 0x02 else 'ack'}-{tdport}"
        if nxt == "17":
            return f"{prefix}udp-{udport}"
        if nxt == "58":
            return {"128": "v6-icmp6-echo", "129": "v6-icmp6-echo-reply"}.get(icmp6type)
        return None
    if proto == "6":
        flags = int(tflags, 16) if tflags else 0
        kind = "syn" if flags & 0x02 else "ack"
        return f"tcp-{kind}-{tdport}"
    if proto == "17":
        return f"udp-{udport}"
    if proto == "1":
        return {"8": "icmp-echo", "0": "icmp-echo-reply", "13": "icmp-timestamp", "14": "icmp-timestamp-reply",
                "3": "icmp-unreachable", "11": "icmp-time-exceeded"}.get(icmptype)
    if proto == "47":
        return "gre"
    return None


def capture_and_send(name, plist, workdir, ts1, ts1_6):
    pcap = f"{name}.pcap"
    cap = f"acl-cap-{os.getpid()}"
    sh(["docker", "run", "-d", "--rm", "--name", cap, "--net", f"container:{TS2_C}",
        "-v", f"{workdir}:/out", NETSHOOT, "tcpdump", "-i", "tailscale0", "-n", "-U",
        "-w", f"/out/{pcap}", "src", "host", ts1, "or", "src", "host", ts1_6])
    time.sleep(2)
    with open(os.path.join(workdir, "probes.json"), "w") as f:
        json.dump(plist, f)
    sh(["docker", "run", "--rm", "--net", f"container:{TS1_C}", "--cap-add", "NET_RAW",
        "-v", f"{HERE}:/w:ro", "-v", f"{workdir}:/out", NETSHOOT,
        "python3", "/w/send_probes.py", "/out/probes.json", "0.3"])
    time.sleep(2)
    sh(["docker", "stop", cap])
    fields = sh(["docker", "run", "--rm", "-v", f"{workdir}:/out", NETSHOOT, "tshark", "-r", f"/out/{pcap}",
                 "-T", "fields", "-e", "ip.proto", "-e", "tcp.dstport", "-e", "tcp.flags",
                 "-e", "udp.dstport", "-e", "icmp.type", "-e", "ipv6.nxt", "-e", "icmpv6.type"])
    seen = set()
    for line in fields.splitlines():
        k = classify(line.split("\t"))
        if k:
            seen.add(k)
    return seen


def main():
    ts1, ts2 = ts_ip("ts1"), ts_ip("ts2")
    ts1_6 = compose("ts1", "tailscale", "ip", "-6").strip()
    ts2_6 = compose("ts2", "tailscale", "ip", "-6").strip()
    ts2_all = compose("ts2", "tailscale", "ip").split()
    date = datetime.date.today().strftime("%Y%m%d")
    out_dir = os.path.join(ROOT, "fixtures", "observed", f"{date}-acl-diff")
    work = os.path.join(out_dir, "pcap")
    os.makedirs(work, exist_ok=True)
    mapping = {"ts1": ts1, "ts2": ts2, "other": OTHER}
    plist = probes(ts1, ts2, ts1_6, ts2_6)
    cases = []
    rules = ts2_rules()
    for pol in json.load(open(os.path.join(HERE, "policies.json"))):
        acls = substitute(pol["acls"], mapping)
        policy = apply_policy(acls)
        rules, changed = wait_rules_change(rules)
        seen = capture_and_send(pol["name"], plist, work, ts1, ts1_6)
        result = [{**p, "delivered": p["id"] in seen} for p in plist]
        cases.append({"name": pol["name"], "policy": policy, "rules_changed": changed,
                      "rules": rules, "local_ips": ts2_all, "probes": result})
        print(f"{pol['name']:22s} changed={changed!s:5s} delivered={sorted(p['id'] for p in result if p['delivered'])}")
    with open(os.path.join(out_dir, "cases.json"), "w") as f:
        json.dump(cases, f, indent=2, sort_keys=True)
    with open(os.path.join(out_dir, "manifest.json"), "w") as f:
        json.dump({"label": "acl-diff", "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                   "official_client": compose("ts2", "tailscale", "version").splitlines()[0],
                   "method": "lab/acl-diff/run.py: per policy, scapy probes from ts1 (raw socket) to ts2; tcpdump on ts2 tailscale0",
                   "files": ["cases.json", "pcap/"]}, f, indent=2)
    print("wrote", os.path.relpath(out_dir, ROOT))


if __name__ == "__main__":
    sys.exit(main())
