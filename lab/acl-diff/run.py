# SPDX-License-Identifier: Apache-2.0
"""Black-box collection of the official client's filtering behavior.

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
# Roles can be overridden by environment variables. Default: ts1 sends, ts2 receives (sender outbound + receiver inbound).
# FLOWMESH_ACL_SENDER=fm1 FLOWMESH_ACL_RECEIVER=ts1: flowmesh does no outbound filtering, so this observes only the receiver's inbound filter.
SENDER = os.environ.get("FLOWMESH_ACL_SENDER", "ts1")
RECEIVER = os.environ.get("FLOWMESH_ACL_RECEIVER", "ts2")
LABEL = os.environ.get("FLOWMESH_ACL_LABEL", "acl-diff")


def sh(args, **kw):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kw).stdout


def compose(*args, stdin=None):
    return sh(["docker", "compose", "-f", os.path.join(LAB, "compose.yaml"), "exec", "-T", *args], input=stdin)


def ts_ip(svc, family="-4"):
    if svc.startswith("fm"):
        fam = "inet" if family == "-4" else "inet6"
        out = compose(svc, "sh", "-c", f"ip -o addr show flowmesh0 | awk '$3==\"{fam}\" && $4 !~ /^fe80/ {{print $4}}'")
        return out.strip().split("/")[0]
    return compose(svc, "tailscale", "ip", family).strip()


def ts2_rules():
    netmap = json.loads(compose(RECEIVER, "tailscale", "debug", "netmap"))
    return netmap.get("PacketFilterRules") or []


def probes(ts1, ts2, ts1_6, ts2_6):
    out = []
    for port in [22, 80, 443, 8000, 8100, 8101, 65535]:
        out.append({"id": f"tcp-syn-{port}", "proto": "tcp", "dport": port, "tcp_flags": "S"})
    for port in [80, 9999]:
        out.append({"id": f"tcp-ack-{port}", "proto": "tcp", "dport": port, "tcp_flags": "A"})
    for flags, name in [("F", "fin"), ("R", "rst"), ("", "null"), ("SA", "synack"), ("SF", "synfin")]:
        out.append({"id": f"tcp-{name}-9001", "proto": "tcp", "dport": 9001, "tcp_flags": flags})
    for port in [53, 8050, 40000]:
        out.append({"id": f"udp-{port}", "proto": "udp", "dport": port, "tcp_flags": ""})
    out.append({"id": "icmp-echo", "proto": "icmp", "dport": 0, "tcp_flags": "", "icmp_type": 8})
    out.append({"id": "icmp-echo-reply", "proto": "icmp", "dport": 0, "tcp_flags": "", "icmp_type": 0})
    out.append({"id": "icmp-timestamp", "proto": "icmp", "dport": 0, "tcp_flags": "", "icmp_type": 13})
    out.append({"id": "icmp-timestamp-reply", "proto": "icmp", "dport": 0, "tcp_flags": "", "icmp_type": 14})
    out.append({"id": "icmp-unreachable", "proto": "icmp", "dport": 0, "tcp_flags": "", "icmp_type": 3})
    out.append({"id": "icmp-time-exceeded", "proto": "icmp", "dport": 0, "tcp_flags": "", "icmp_type": 11})
    for t, name in [(4, "source-quench"), (5, "redirect"), (12, "param-problem")]:
        out.append({"id": f"icmp-{name}", "proto": "icmp", "dport": 0, "tcp_flags": "", "icmp_type": t})
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
        {"id": "v6-icmp6-unreachable", "proto": "icmp6", "dport": 0, "tcp_flags": "", "icmp_type": 1},
        {"id": "v6-icmp6-too-big", "proto": "icmp6", "dport": 0, "tcp_flags": "", "icmp_type": 2},
        {"id": "v6-icmp6-time-exceeded", "proto": "icmp6", "dport": 0, "tcp_flags": "", "icmp_type": 3},
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
    owners = {t: ["lab@"] for t in ("tag:relay-enabled", "tag:relay-force", "tag:relay-strict")}
    policy = {"tagOwners": owners, "acls": acls}
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
    # A packet that carries an embedded IP header (e.g. an ICMP error) gets multiple comma-separated values for a field such as "1,17";
    # take only the first value, i.e. the outer header. Ignoring this once made every ICMPv4 error count as "not delivered" (see filter.md §5).
    fields = [f.split(",")[0] for f in fields]
    proto, tdport, tflags, udport, icmptype, nxt, icmp6type = (fields + [""] * 7)[:7]
    # Classify by the outer IP version: when ip.proto is present the packet is IPv4. tshark parses the payload of an ICMPv4 error
    # as an embedded packet and may fill ipv6.nxt with a garbage value; checking nxt first once made every ICMPv4 error count as "not delivered".
    if nxt and not proto:
        prefix = "v6-"
        if nxt == "6":
            flags = int(tflags, 16) if tflags else 0
            return f"{prefix}tcp-{'syn' if flags & 0x02 else 'ack'}-{tdport}"
        if nxt == "17":
            return f"{prefix}udp-{udport}"
        if nxt == "58":
            return {"128": "v6-icmp6-echo", "129": "v6-icmp6-echo-reply", "1": "v6-icmp6-unreachable",
                    "2": "v6-icmp6-too-big", "3": "v6-icmp6-time-exceeded"}.get(icmp6type)
        return None
    if proto == "6":
        flags = int(tflags, 16) if tflags else 0
        if tdport == "9001":
            kind = {0x01: "fin", 0x04: "rst", 0x00: "null", 0x12: "synack", 0x03: "synfin"}.get(flags & 0x17, f"flags{flags:x}")
        else:
            kind = "syn" if flags & 0x02 else "ack"
        return f"tcp-{kind}-{tdport}"
    if proto == "17":
        return f"udp-{udport}"
    if proto == "1":
        return {"8": "icmp-echo", "0": "icmp-echo-reply", "13": "icmp-timestamp", "14": "icmp-timestamp-reply",
                "3": "icmp-unreachable", "11": "icmp-time-exceeded", "4": "icmp-source-quench",
                "5": "icmp-redirect", "12": "icmp-param-problem"}.get(icmptype)
    if proto == "47":
        return "gre"
    return None


def capture_and_send(name, plist, workdir, ts1, ts1_6):
    pcap = f"{name}.pcap"
    cap = f"acl-cap-{os.getpid()}"
    sh(["docker", "run", "-d", "--rm", "--name", cap, "--net", f"container:flowmesh-lab-{RECEIVER}-1",
        "-v", f"{workdir}:/out", NETSHOOT, "tcpdump", "-i", "tailscale0", "-n", "-U",
        "-w", f"/out/{pcap}", "src", "host", ts1, "or", "src", "host", ts1_6])
    time.sleep(2)
    with open(os.path.join(workdir, "probes.json"), "w") as f:
        json.dump(plist, f)
    if SENDER.startswith("fm"):
        rel = os.path.relpath(workdir, ROOT)
        compose(SENDER, "python3", "/src/lab/acl-diff/send_probes.py", f"/src/{rel}/probes.json", "0.3")
    else:
        sh(["docker", "run", "--rm", "--net", f"container:flowmesh-lab-{SENDER}-1", "--cap-add", "NET_RAW",
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


def reparse(out_dir):
    """Recompute delivered from the saved pcaps (the lab is not needed)."""
    path = os.path.join(out_dir, "cases.json")
    cases = json.load(open(path))
    changed = 0
    for case in cases:
        fields = sh(["docker", "run", "--rm", "-v", f"{os.path.join(out_dir, 'pcap')}:/out", NETSHOOT, "tshark", "-r",
                     f"/out/{case['name']}.pcap", "-T", "fields", "-e", "ip.proto", "-e", "tcp.dstport", "-e", "tcp.flags",
                     "-e", "udp.dstport", "-e", "icmp.type", "-e", "ipv6.nxt", "-e", "icmpv6.type"])
        seen = {k for k in (classify(l.split("\t")) for l in fields.splitlines()) if k}
        for p in case["probes"]:
            new = p["id"] in seen
            if new != p["delivered"]:
                print(f"{case['name']}/{p['id']}: {p['delivered']} -> {new}")
                changed += 1
            p["delivered"] = new
    with open(path, "w") as f:
        json.dump(cases, f, indent=2, sort_keys=True)
    print(f"reparsed {path}: {changed} probes changed")


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--reparse":
        return reparse(sys.argv[2])
    ts1, ts2 = ts_ip(SENDER), ts_ip(RECEIVER)
    ts1_6, ts2_6 = ts_ip(SENDER, "-6"), ts_ip(RECEIVER, "-6")
    ts2_all = compose(RECEIVER, "tailscale", "ip").split()
    date = datetime.date.today().strftime("%Y%m%d")
    out_dir = os.path.join(ROOT, "fixtures", "observed", f"{date}-{LABEL}")
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
        json.dump({"label": LABEL, "sender": SENDER, "receiver": RECEIVER, "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                   "official_client": compose(RECEIVER, "tailscale", "version").splitlines()[0],
                   "method": "lab/acl-diff/run.py: per policy, scapy probes from ts1 (raw socket) to ts2; tcpdump on ts2 tailscale0",
                   "files": ["cases.json", "pcap/"]}, f, indent=2)
    print("wrote", os.path.relpath(out_dir, ROOT))


if __name__ == "__main__":
    sys.exit(main())
