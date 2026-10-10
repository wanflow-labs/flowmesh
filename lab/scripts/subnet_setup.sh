#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Subnet route lab setup: ts2 advertises 10.99.0.0/24 (10.99.0.1 lives on its lo), and headscale approves (approve) or revokes (revoke) it.
# Usage: subnet_setup.sh approve|revoke
set -euo pipefail
cd "$(dirname "$0")/.."
hs() { docker compose exec -T headscale headscale "$@"; }
ts2_id=$(hs nodes list -o json | python3 -c 'import json,sys; print([n["id"] for n in json.load(sys.stdin) if n["given_name"]=="ts2"][0])')
docker compose exec -T ts2 sh -c 'ip addr add 10.99.0.1/32 dev lo 2>/dev/null || true'
docker compose exec -T ts2 tailscale set --advertise-routes=10.99.0.0/24
case "$1" in
  approve) hs nodes approve-routes -i "$ts2_id" -r 10.99.0.0/24 >/dev/null ;;
  revoke) hs nodes approve-routes -i "$ts2_id" -r "" >/dev/null ;;
esac
sleep 3
hs nodes list -o json | python3 -c 'import json,sys; [print("ts2 approved:", n.get("approved_routes"), "available:", n.get("available_routes")) for n in json.load(sys.stdin) if n["given_name"]=="ts2"]'
