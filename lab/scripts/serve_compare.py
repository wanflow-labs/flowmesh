#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare `serve_observe.sh` runs: the official server (OFFICIAL_DIR) and flowmesh (FLOWMESH_DIR),
case by case, after normalizing what differs by nature (node names, addresses, dates, ephemeral
ports, header name case, the random order of the official listing). Known, intended differences
(docs/protocol/serve.md) are listed separately and do not fail the comparison.

Usage: serve_compare.py OFFICIAL_DIR FLOWMESH_DIR
"""
import os
import re
import sys

# Cases flowmesh answers differently on purpose.
INTENDED = {
    "https-default.txt": "HTTPS needs certificates: refused",
    "tls-terminated.txt": "TLS termination needs certificates: refused",
    "service-flag.txt": "services need control server support: refused",
    "prefs.txt": "different preference formats",
    "server-log.txt": "different logs",
    "serve-config.json": "includes the refused TLS-terminated port on the official side",
    "nodes.txt": "names",
}
# Header lines the official server's Go HTTP stack adds and flowmesh does not.
DROP_LINES = re.compile(r"^(accept-encoding: gzip|tailscale-headers-info: .*)$", re.I)


def nodes(d):
    w = open(os.path.join(d, "nodes.txt")).read().split()
    return w[1], w[2]


def normalize(text, name, ip):
    short = name.split(".")[0]
    text = text.replace(name, "NODE").replace(short, "SHORT").replace(ip, "SERVERIP")
    text = text.replace("tailscale", "flowmesh")
    text = re.sub(r"fd7a:115c:a1e0::[0-9a-f]+", "V6", text)
    text = re.sub(r"100\.64\.0\.\d+", "IP", text)
    out = []
    for line in text.splitlines():
        if DROP_LINES.match(line):
            continue
        line = re.sub(r"^(date|last-modified|server): .*$", r"\1: X", line, flags=re.I)
        line = re.sub(r"\('127\.0\.0\.1', \d+\)", "('127.0.0.1', PORT)", line)
        line = re.sub(r"(PROXY TCP[46] \S+ \S+) \d+ ", r"\1 PORT ", line)
        m = re.match(r"^([A-Za-z0-9-]+): (.*)$", line)
        if m:  # header names are case-insensitive
            line = f"{m.group(1).lower()}: {m.group(2)}"
        out.append(line)
    return sort_headers(out)


def sort_headers(lines):
    """In an HTTP response: header lines in a fixed order (the order is not meaningful); a proxied
    response's length differs by the headers flowmesh does not add, so it is left out."""
    if len(lines) < 2 or not lines[1].startswith("HTTP/"):
        return lines
    try:
        end = lines.index("", 1)
    except ValueError:
        end = len(lines)
    headers = lines[2:end]
    proxied = any(h.startswith("x-backend:") for h in headers)
    headers = sorted(h for h in headers if not (proxied and h.startswith("content-length:")))
    body = lines[end:]
    if proxied:
        # The echoed request headers: their order is not meaningful either.
        k = next((i for i, l in enumerate(body) if l.startswith(("get ", "post ", "GET ", "POST "))), None)
        e = next((i for i, l in enumerate(body) if l.startswith("body=")), None)
        if k is not None and e is not None:
            body = body[: k + 1] + sorted(body[k + 1 : e]) + body[e:]
    return lines[:2] + headers + body


def sort_listing(lines):
    """Official status lists TCP forwarders and HTTP servers in Go's random map order."""
    cmd = [l for l in lines[:1] if l.startswith("$")]
    lines = lines[len(cmd):]
    tcp, rest = [], []
    for l in lines:
        (tcp if l.startswith("|-") and not rest else rest).append(l)
    blocks = sorted("\n".join(tcp[i : i + 4]) for i in range(0, len(tcp), 4))
    webs = sorted(b.strip() for b in "\n".join(rest).split("\n\n") if b.strip())
    return cmd + blocks + webs


def drop_tls_terminated(lines):
    """flowmesh refuses the TLS-terminated port (2224): leave it out of the official listing."""
    out, skip = [], 0
    for l in lines:
        if ":2224 (TLS terminated" in l:
            skip = 4
        if skip:
            skip -= 1
            continue
        out.append(l)
    return out


def drop_json_port(lines, port):
    """The refused TLS-terminated port out of the official JSON."""
    import json
    i = next(k for k, l in enumerate(lines) if l.startswith("{"))
    j = max(k for k, l in enumerate(lines) if l.startswith("}"))
    cfg = json.loads("\n".join(lines[i : j + 1]))
    cfg.get("TCP", {}).pop(port, None)
    return lines[:i] + json.dumps(cfg, indent=2, sort_keys=True).splitlines() + lines[j + 1 :]


def main():
    off_dir, fm_dir = sys.argv[1], sys.argv[2]
    (on, oip), (fn, fip) = nodes(off_dir), nodes(fm_dir)
    same, differ, intended = [], [], []
    for f in sorted(os.listdir(off_dir)):
        if f in INTENDED:
            intended.append(f"{f}: {INTENDED[f]}")
            continue
        fp = os.path.join(fm_dir, f)
        if not os.path.exists(fp):
            differ.append(f"{f}: missing from the flowmesh run")
            continue
        a = normalize(open(os.path.join(off_dir, f)).read(), on, oip)
        b = normalize(open(fp).read(), fn, fip)
        if f.startswith("status-all") or f == "status-after-off.txt":
            a = drop_tls_terminated(a)
        if f == "status-all-json.txt":
            a = drop_json_port(a, "2224")
        if f.startswith("status") and not f.endswith("json.txt"):
            a, b = sort_listing(a), sort_listing(b)
        if f == "status-all-json.txt":
            b = drop_json_port(b, "none")
        if a == b:
            same.append(f)
        else:
            diff = [f"    - {x}" for x in a if x not in b] + [f"    + {x}" for x in b if x not in a]
            differ.append(f"{f}:\n" + "\n".join(diff[:12]))
    print(f"same ({len(same)}): {' '.join(same)}")
    print(f"intended differences ({len(intended)}):")
    for i in intended:
        print(f"  {i}")
    if differ:
        print(f"DIFFERENT ({len(differ)}):")
        for d in differ:
            print(f"  {d}")
        sys.exit(1)


if __name__ == "__main__":
    main()
