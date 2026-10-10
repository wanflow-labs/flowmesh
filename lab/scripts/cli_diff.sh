#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# M7 differential: the same command sequence against the official client (ts2) and flowmeshd (fm1).
# Compares, per step, the command's exit code, BackendState, and the exit code of `status`
# (cli.md §1), then checks that fm1's status JSON carries every agent-read field with the official type.
#   cli_diff.sh [out-dir]  run the differential (flowmeshd is left running in fm1 afterwards);
#                          per-step results and status JSON go to out-dir (default: a temp dir)
set -euo pipefail
# Resolve the output dir before changing directory, so a relative path means relative to the caller.
out=${1:-$(mktemp -d)}
mkdir -p "$out"
out=$(cd "$out" && pwd)
cd "$(dirname "$0")/.."
dc() { docker compose exec -T "$@"; }
key=$(cat .authkey)

echo "== build and start flowmeshd in fm1"
dc fm1 cargo build -q -p flowmesh-daemon -p flowmesh-cli
dc fm1 sh -c 'pkill -x flowmesh-dev || true; pkill -x flowmeshd || true; sleep 1
  ip link del flowmesh0 2>/dev/null || true; rm -rf /target/fmd-state
  nohup /target/debug/flowmeshd --state-dir /target/fmd-state --socket /tmp/fmd.sock > /tmp/flowmeshd.log 2>&1 &'
for _ in $(seq 1 20); do dc fm1 test -S /tmp/fmd.sock && break; sleep 0.5; done

ts2() { dc ts2 timeout 30 tailscale "$@"; }
fm1() { dc fm1 timeout 30 /target/debug/flowmesh --socket=/tmp/fmd.sock "$@"; }

# step <side> <name> <command...>: run, then record exit code + BackendState + status exit.
step() {
  local side=$1 name=$2; shift 2
  if [ "$side" = ts2 ] && [ "$1" = logout ] && [ "$name" != logout-cut ]; then restart_ts2; fi
  # Non-zero exit codes are compared as 1: the official logout against an unreachable server never
  # returns on its own and is ended by `timeout` (deviation #7).
  local rc=0; "$side" "$@" >/dev/null 2>&1 || rc=1
  local js="$out/$side-$name.json"
  "$side" status --json > "$js" 2>/dev/null || true
  local src=0; "$side" status >/dev/null 2>&1 || src=$?
  local bs; bs=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['BackendState'])" "$js")
  printf '%-9s cmd_exit=%s BackendState=%-10s status_exit=%s\n' "$name" "$rc" "$bs" "$src" >> "$out/$side.txt"
  if [ "$side" = ts2 ] && [ "$1" = logout ] && [ "$name" != logout-cut ]; then restart_ts2; fi
}

# Drop the side's traffic to the control server (headscale, 172.29.0.10).
cut()     { dc "$1" ip route add blackhole 172.29.0.10/32; }
restore() { dc "$1" ip route del blackhole 172.29.0.10/32; }

# The official client remembers "a recent noise dial succeeded" and then insists on port 443 for later
# dials, which this plain-HTTP lab control server cannot satisfy (cli.md §6). Logout and the login after
# it both dial, so ts2 is restarted around each logout; state is persisted, so the restart clears only
# that in-memory heuristic.
restart_ts2() {
  docker compose restart ts2 >/dev/null 2>&1
  for _ in $(seq 1 40); do ts2 status --json >/dev/null 2>&1 && return; sleep 0.5; done
}

for side in ts2 fm1; do
  : > "$out/$side.txt"
  host=$side
  full=(--login-server=http://headscale.lab --hostname="$host" --accept-dns=false)
  # Start logged out, so leftovers from other lab scripts cannot change the outcome.
  step "$side" logout0  logout
  step "$side" join     up "${full[@]}" --authkey="$key" --timeout=30s
  # A second non-default flag; then an up that omits it must be refused while staying Running.
  step "$side" routes   up "${full[@]}" --accept-routes --timeout=30s
  step "$side" omit     up "${full[@]}" --timeout=10s
  step "$side" down     down
  step "$side" bare-up  up --timeout=10s
  step "$side" full-up  up "${full[@]}" --accept-routes --timeout=30s
  # Control server unreachable: logout fails, the node stays logged in but Stopped.
  cut "$side"
  step "$side" logout-cut logout
  restore "$side"
  step "$side" logout   logout
  # logout resets preferences, so fewer flags than before are accepted.
  step "$side" relogin  up "${full[@]}" --authkey="$key" --timeout=30s
  # Never a bare `up` while logged out: the official client would fall back to its vendor's
  # default control server.
done

echo "== official (ts2)"; cat "$out/ts2.txt"
echo "== flowmesh (fm1)"; cat "$out/fm1.txt"
if diff "$out/ts2.txt" "$out/fm1.txt" >/dev/null; then
  echo "ok: every step matches"
else
  echo "FAIL: differences"; diff "$out/ts2.txt" "$out/fm1.txt" || true; exit 1
fi

echo "== agent-read fields in status --json (Running)"
python3 - "$out/ts2-relogin.json" "$out/fm1-relogin.json" <<'PY'
import json, sys
off, ours = (json.load(open(p)) for p in sys.argv[1:3])
kind = lambda v: type(v).__name__
bad = []
for k in ["BackendState", "Health", "MagicDNSSuffix", "CurrentTailnet"]:
    if kind(ours.get(k)) != kind(off.get(k)): bad.append(f"{k}: {kind(ours.get(k))} vs {kind(off.get(k))}")
if not str(ours["Self"].get("PublicKey", "")).startswith("nodekey:"): bad.append("Self.PublicKey")
peer_fields = ["HostName","DNSName","TailscaleIPs","Online","LastSeen","OS","Relay","RxBytes","TxBytes","CurAddr","Active","PublicKey","ExitNodeOption"]
op = next(iter(off["Peer"].values())); fp = list((ours.get("Peer") or {}).values())
if not fp: bad.append("fm1 has no peers")
for p in fp:
    for k in peer_fields:
        if kind(p.get(k)) != kind(op.get(k)): bad.append(f"Peer.{k}: {kind(p.get(k))} vs {kind(op.get(k))}")
print("FAIL: " + "; ".join(sorted(set(bad))) if bad else f"ok: all agent fields present with official types ({len(fp)} peers)")
sys.exit(1 if bad else 0)
PY

echo "== restart restores Running (prefs persist)"
dc fm1 sh -c 'pkill -x flowmeshd; for i in $(seq 1 50); do pgrep -x flowmeshd >/dev/null || break; sleep 0.2; done
  nohup /target/debug/flowmeshd --state-dir /target/fmd-state --socket /tmp/fmd.sock >> /tmp/flowmeshd.log 2>&1 &'
for _ in $(seq 1 40); do
  if fm1 status >/dev/null 2>&1; then echo "ok: Running again after daemon restart"; exit 0; fi
  sleep 0.5
done
echo "FAIL: not Running after restart"; fm1 status || true; exit 1
