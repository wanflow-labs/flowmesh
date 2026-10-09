# SPDX-License-Identifier: Apache-2.0
"""Redact secrets in observation samples in place: private keys, pre-auth keys, and any field whose name contains private/secret/password/token.

Usage: python3 lab/scripts/redact.py <dir> <authkey>
Afterwards it re-scans every file; if any secret is still present it exits with code 1.
"""
import json
import os
import re
import sys

SENSITIVE_NAME = re.compile(r"private|secret|password|token", re.IGNORECASE)
REDACTED = "<redacted>"


def redact(value, authkey, parent=""):
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if SENSITIVE_NAME.search(k) or (k == "key" and parent.lower() == "preauthkey"):
                out[k] = REDACTED if v not in (None, "", {}, []) else v
            else:
                out[k] = redact(v, authkey, k)
        return out
    if isinstance(value, list):
        return [redact(v, authkey, parent) for v in value]
    if isinstance(value, str) and (value == authkey or value.startswith("privkey:")):
        return REDACTED
    return value


def main():
    directory, authkey = sys.argv[1], sys.argv[2]
    for name in sorted(os.listdir(directory)):
        path = os.path.join(directory, name)
        if not name.endswith(".json"):
            continue
        with open(path) as f:
            data = json.load(f)
        with open(path, "w") as f:
            json.dump(redact(data, authkey), f, indent=2, sort_keys=True)
            f.write("\n")
    leaked = []
    for name in sorted(os.listdir(directory)):
        text = open(os.path.join(directory, name)).read()
        if authkey in text or "privkey:" in text:
            leaked.append(name)
    if leaked:
        print("secrets still present in: " + ", ".join(leaked))
        sys.exit(1)


if __name__ == "__main__":
    main()
