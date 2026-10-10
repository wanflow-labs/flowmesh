#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Bring the official client ts2 back to a fresh, joined state. After some failures it persists a
# "force port 443" decision that the plain-HTTP lab server can never satisfy and that survives
# restarts (cli.md §6); wiping its state makes it register as a new node.
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose stop ts2 >/dev/null 2>&1
docker compose run --rm --no-deps --entrypoint rm ts2 -f /var/lib/tailscale/tailscaled.state >/dev/null 2>&1
docker compose start ts2 >/dev/null 2>&1
sleep 4
docker compose exec -T ts2 tailscale up --login-server=http://headscale.lab --hostname=ts2 \
  --accept-dns=false --authkey="$(cat .authkey)" --timeout=30s >/dev/null 2>&1
docker compose exec -T ts2 tailscale ip -4
