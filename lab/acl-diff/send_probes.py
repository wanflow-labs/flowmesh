# SPDX-License-Identifier: Apache-2.0
"""Run inside the sender's network namespace (netshoot). Build probe packets with scapy and send them through a kernel raw socket so they follow the full policy routing.

Usage: python3 send_probes.py <probes.json> [gap seconds]
Every probe is a dict: {"id","proto","src","dst","dport","tcp_flags"}.
"""
import json
import socket
import sys
import time

from scapy.all import ICMP, IP, TCP, UDP, IPv6, ICMPv6DestUnreach, ICMPv6EchoReply, ICMPv6EchoRequest, ICMPv6PacketTooBig, ICMPv6TimeExceeded, Raw

GRE = 47


def build6(p):
    ip = IPv6(src=p["src"], dst=p["dst"], hlim=64)
    proto = p["proto"]
    if proto == "tcp":
        return ip / TCP(sport=40000 + (p["dport"] % 20000), dport=p["dport"], flags=p["tcp_flags"], seq=1000)
    if proto == "udp":
        return ip / UDP(sport=40000, dport=p["dport"]) / Raw(load=p["id"].encode())
    if proto == "icmp6":
        t = p.get("icmp_type", 128)
        if t in (128, 129):
            cls = ICMPv6EchoRequest if t == 128 else ICMPv6EchoReply
            return ip / cls(id=4242, seq=1, data=p["id"].encode())
        err = {1: ICMPv6DestUnreach, 2: ICMPv6PacketTooBig, 3: ICMPv6TimeExceeded}[t]
        return ip / err() / Raw(load=p["id"].encode())
    raise ValueError(proto)


def build(p):
    ip = IP(src=p["src"], dst=p["dst"], ttl=64)
    proto = p["proto"]
    if proto == "tcp":
        return ip / TCP(sport=40000 + (p["dport"] % 20000), dport=p["dport"], flags=p["tcp_flags"], seq=1000)
    if proto == "udp":
        return ip / UDP(sport=40000, dport=p["dport"]) / Raw(load=p["id"].encode())
    if proto == "icmp":
        return ip / ICMP(type=p.get("icmp_type", 8), id=4242, seq=1) / Raw(load=p["id"].encode())
    if proto == "gre":
        ip.proto = GRE
        return ip / Raw(load=b"\x00\x00\x08\x00" + p["id"].encode())
    raise ValueError(proto)


def main():
    probes = json.load(open(sys.argv[1]))
    gap = float(sys.argv[2]) if len(sys.argv) > 2 else 0.3
    s4 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s4.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # Linux: an IPPROTO_RAW socket on AF_INET6 means the caller supplies the full IPv6 header.
    s6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
    for p in probes:
        if ":" in p["dst"]:
            s6.sendto(bytes(build6(p)), (p["dst"], 0))
        else:
            s4.sendto(bytes(build(p)), (p["dst"], 0))
        time.sleep(gap)


if __name__ == "__main__":
    main()
