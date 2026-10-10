#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Deviation #2: an http:// control URL on a high port is used as given, in plain HTTP, with no
# attempt on port 443 (the official client forces TLS on any port but 80, cli.md §6). The control
# server is put behind 127.0.0.1:18080 inside fm1; a capture checks that nothing goes to headscale:443.
set -euo pipefail
cd "$(dirname "$0")/.."
dc() { docker compose exec -T "$@"; }
key=$(cat .authkey)
fm1() { dc fm1 /target/debug/flowmesh --socket=/tmp/fmd.sock "$@"; }
fail() { echo "FAIL: $*"; exit 1; }
join() { # control URL
  fm1 up --login-server="$1" --hostname=fm1 --accept-dns=false --authkey="$key" --reset --timeout=30s
}
restore() {
  dc fm1 sh -c 'pkill -f "[t]cp_forward.py" || true; pkill -x tcpdump || true'
  join http://headscale.lab >/dev/null 2>&1 || true
}
trap restore EXIT

fm1 status >/dev/null || fail "fm1 not Running"
# Kill in a separate call: a shell whose own command line names the script would match itself.
dc fm1 sh -c 'pkill -f "[t]cp_forward.py" || true'
dc fm1 sh -c 'nohup python3 /src/lab/scripts/tcp_forward.py 127.0.0.1 18080 headscale.lab 80 > /tmp/fwd.log 2>&1 &
  nohup tcpdump -i any -n -U -w /tmp/hp443.pcap "host 172.29.0.10 and tcp port 443" > /tmp/tcpdump.log 2>&1 &
  sleep 1'

join http://127.0.0.1:18080 || fail "join through the high port failed"
fm1 status >/dev/null && echo "ok: Running with control URL http://127.0.0.1:18080"
dc fm1 grep -q "connection from" /tmp/fwd.log && echo "ok: control traffic went through the high-port forwarder"
dc fm1 ping -c 2 -W 3 100.64.0.1 >/dev/null && echo "ok: mesh works"
dc fm1 sh -c 'sleep 1; pkill -x tcpdump; sleep 1'
n=$(dc fm1 sh -c 'tcpdump -r /tmp/hp443.pcap -n 2>/dev/null | wc -l' | tr -d '\r ')
[ "$n" = 0 ] && echo "ok: no packet to the control server's port 443" || fail "$n packets to headscale:443"
