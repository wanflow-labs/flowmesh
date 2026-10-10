#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build the fuzz seed corpora from observed fixtures (real netmaps, filter rules, disco payloads)
and a few hand-built DNS queries. Run from the repository root: python3 fuzz/seed.py"""
import glob
import json
import os
import struct

root = "fuzz/corpus"


def put(target, name, data):
    d = os.path.join(root, target)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)


maps = sorted(glob.glob("fixtures/observed/*/map-*.json"))
for i, path in enumerate(maps):
    raw = open(path, "rb").read()
    put("map_json", f"seed-map-{i}", raw)
    m = json.loads(raw)
    for g, rules in (m.get("PacketFilters") or {}).items():
        if rules:
            put("filter_rules", f"seed-filter-{i}-{g}", json.dumps(rules).encode())

for path in glob.glob("fixtures/observed/20261010-disco/decrypted-*.tsv"):
    for n, line in enumerate(open(path)):
        for field in line.split("\t"):
            if field.startswith("payload="):
                put("disco", f"seed-{os.path.basename(path)}-{n}", bytes.fromhex(field[8:].strip()))


def dns_query(name, qtype):
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.rstrip(".").split(".")) + b"\0"
    return struct.pack(">HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", qtype, 1)


for name, t in [("ts1.mesh.lab.internal", 1), ("ts1.mesh.lab.internal", 28),
                ("1.0.64.100.in-addr.arpa", 12), ("example.com", 1), ("nosuch.mesh.lab.internal", 16)]:
    put("dns", f"seed-{name}-{t}", dns_query(name, t))

print({t: len(os.listdir(os.path.join(root, t))) for t in sorted(os.listdir(root))})
