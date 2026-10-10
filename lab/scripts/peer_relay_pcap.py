#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""List the UDP packets of a peer relay pcap: who sent what to the relay port, where disco envelopes
sit inside, and who sealed them. Usage: peer_relay_pcap.py PCAP NETMAP_JSON [PORT]"""
import json
import struct
import sys

MAGIC = bytes.fromhex("5453f09f92ac")  # disco envelope magic (docs/protocol/disco.md §1)


def packets(path):
    """Yield (time, src_ip, src_port, dst_ip, dst_port, payload) for IPv4/UDP in a classic pcap
    (Ethernet or Linux cooked v1 link types)."""
    with open(path, "rb") as f:
        head = f.read(24)
        endian = "<" if head[:4] == b"\xd4\xc3\xb2\xa1" else ">"
        link = struct.unpack(endian + "I", head[20:24])[0]
        skip = {1: 14, 113: 16}[link]
        while rec := f.read(16):
            sec, usec, caplen, _ = struct.unpack(endian + "IIII", rec)
            frame = f.read(caplen)
            ip = frame[skip:]
            if len(ip) < 28 or ip[0] >> 4 != 4 or ip[9] != 17:
                continue
            ihl = (ip[0] & 15) * 4
            sport, dport = struct.unpack(">HH", ip[ihl:ihl + 4])
            src = ".".join(map(str, ip[12:16]))
            dst = ".".join(map(str, ip[16:20]))
            yield sec + usec / 1e6, src, sport, dst, dport, ip[ihl + 8:]


def names(netmap):
    """Map disco public key bytes and IPv4 endpoints to node names."""
    by_key, by_ip = {}, {}
    # The official client's `tailscale debug netmap` calls its own node SelfNode; a MapResponse calls it Node.
    me = netmap.get("SelfNode") or netmap.get("Node") or {}
    for n in [me] + (netmap.get("Peers") or []):
        name = n.get("Name", "?").split(".")[0]
        if n.get("DiscoKey", "").startswith("discokey:"):
            by_key[bytes.fromhex(n["DiscoKey"][9:])] = name
        for ep in n.get("Endpoints") or []:
            by_ip[ep.rsplit(":", 1)[0]] = name
    return by_key, by_ip


def describe(payload, by_key):
    at = payload.find(MAGIC)
    if at < 0:
        return "head=" + payload[:16].hex()
    sender = payload[at + 6:at + 38]
    return f"disco@{at} from={by_key.get(sender, sender[:4].hex())}"


def main():
    pcap, netmap_path = sys.argv[1], sys.argv[2]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 40000
    by_key, by_ip = names(json.load(open(netmap_path)))
    t0 = None
    for t, src, sp, dst, dp, payload in packets(pcap):
        if port not in (sp, dp):
            continue
        t0 = t0 or t
        who = lambda ip, p: "relay" if p == port else by_ip.get(ip, ip)
        print(f"{t - t0:8.3f}  {who(src, sp)}->{who(dst, dp)}  len={len(payload):4d}  {describe(payload, by_key)}")


if __name__ == "__main__":
    main()
