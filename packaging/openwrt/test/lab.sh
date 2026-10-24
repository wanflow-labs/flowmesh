#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Test lab for the OpenWrt package tests (run.sh), on one Linux host with KVM:
#   - a control server (upstream headscale release, sqlite, embedded relay + STUN) on $OWT_HOST_IP
#   - a second mesh node ("peer", the linux-x86_64 release binary) in network namespace owt-peer,
#     also an approved exit node; behind it an "Internet" address ($OWT_INET_IP, on a dummy device
#     in owt-peer) where an HTTP server answers every request with the client's address
#   - split DNS: $OWT_SPLIT_DOMAIN is resolved by a tiny DNS server on $OWT_PEER_IP:53 (in owt-peer;
#     the router reaches it from its uplink), answering $OWT_SPLIT_ANSWER for every name in it
#   - the router's LAN: bridge owtbr0 ($OWT_LAN_HOST_IP, used to reach the VM over SSH) and a LAN
#     client in network namespace owt-lan ($OWT_LAN_CLIENT_IP, default route via the router)
# The router VM itself (run.sh) gets a tap on owtbr0 as LAN and QEMU user networking as WAN.
#
#   lab.sh up <work_dir> <headscale_binary> <flowmesh-linux-x86_64.tar.gz>
#   lab.sh down <work_dir>
#   lab.sh peer-stop <work_dir>    stop the peer's daemon (by its PID): the exit node goes offline
#   lab.sh peer-start <work_dir>   start it again (same state: no login), wait until it is Running
# `up` writes <work_dir>/lab.env, which run.sh reads. Needs passwordless sudo (namespaces, bridge).
set -euo pipefail

OWT_HOST_IP=${OWT_HOST_IP:-10.231.0.1}   # host end of the veth to owt-peer; the control server listens here
OWT_PEER_IP=${OWT_PEER_IP:-10.231.0.2}
OWT_HS_PORT=${OWT_HS_PORT:-18480}
OWT_STUN_PORT=${OWT_STUN_PORT:-18478}
OWT_LAN_HOST_IP=${OWT_LAN_HOST_IP:-192.168.1.2}
OWT_LAN_CLIENT_IP=${OWT_LAN_CLIENT_IP:-192.168.1.50}
OWT_ROUTER_LAN_IP=${OWT_ROUTER_LAN_IP:-192.168.1.1}
OWT_INET_IP=${OWT_INET_IP:-198.51.100.1}   # TEST-NET-2: reachable only through the peer as exit node
OWT_INET_PORT=${OWT_INET_PORT:-18492}
OWT_EXTRA_NAME=${OWT_EXTRA_NAME:-app.owt-extra.test}   # extra DNS record (not under the mesh suffix)
OWT_EXTRA_IP=${OWT_EXTRA_IP:-100.64.0.200}
OWT_SPLIT_DOMAIN=${OWT_SPLIT_DOMAIN:-corp.owt-split.test}   # split DNS: answered by a resolver in owt-peer
# Its answer for every name in that domain: a private address, as intranet split DNS gives, which
# dnsmasq's rebind protection discards unless the domain has a rebind_domain exception.
OWT_SPLIT_ANSWER=${OWT_SPLIT_ANSWER:-10.77.0.53}

die() { echo "lab: $*" >&2; exit 1; }

# Stop the process whose PID is in file $1 (only that one), then remove the file.
stop_pidfile() {
  local f=$1 pid
  sudo test -f "$f" || return 0
  pid=$(sudo cat "$f")
  if [ -n "$pid" ] && sudo kill -0 "$pid" 2>/dev/null; then
    sudo kill "$pid" || true
    for _ in $(seq 1 30); do sudo kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
    if sudo kill -0 "$pid" 2>/dev/null; then sudo kill -9 "$pid" || true; fi
  fi
  sudo rm -f "$f"
}

# The peer's daemon in owt-peer, its PID in $1/peer/flowmeshd.pid; waits for its socket.
start_peer() {
  local w=$1
  sudo sh -c "ip netns exec owt-peer '$w/peer/flowmeshd' --state-dir '$w/peer/state' \
      --socket '$w/peer/flowmeshd.sock' --tun owtpeer0 >> '$w/peer/flowmeshd.log' 2>&1 & echo \$! > '$w/peer/flowmeshd.pid'"
  for _ in $(seq 1 30); do sudo test -S "$w/peer/flowmeshd.sock" && break; sleep 0.5; done
}

up() {
  local w hs tarball
  w=$(realpath -m "$1"); hs=$(realpath "$2"); tarball=$(realpath "$3")
  [ -e "$w/lab.env" ] && die "$w/lab.env exists: run 'lab.sh down $w' first"
  mkdir -p "$w/hs" "$w/peer"

  # The second mesh node's binaries.
  tar -xzf "$tarball" -C "$w/peer" --strip-components=1

  # Network: veth host <-> owt-peer; bridge owtbr0 with the LAN client namespace on it.
  sudo ip netns add owt-peer
  sudo ip link add owt-peer0 type veth peer name owt-peer1
  sudo ip link set owt-peer1 netns owt-peer
  sudo ip addr add "$OWT_HOST_IP/30" dev owt-peer0
  sudo ip link set owt-peer0 up
  sudo ip -n owt-peer addr add "$OWT_PEER_IP/30" dev owt-peer1
  sudo ip -n owt-peer link set owt-peer1 up
  sudo ip -n owt-peer link set lo up
  sudo ip -n owt-peer link add owtinet0 type dummy
  sudo ip -n owt-peer addr add "$OWT_INET_IP/32" dev owtinet0
  sudo ip -n owt-peer link set owtinet0 up
  # The router's WAN is QEMU user networking, which connects from this host: here that address must
  # lead nowhere, so that only the peer (as exit node) reaches it.
  sudo ip route replace blackhole "$OWT_INET_IP/32"

  sudo ip link add owtbr0 type bridge
  sudo ip addr add "$OWT_LAN_HOST_IP/24" dev owtbr0
  sudo ip link set owtbr0 up
  sudo ip netns add owt-lan
  sudo ip link add owt-lan0 type veth peer name owt-lan1
  sudo ip link set owt-lan0 master owtbr0 up
  sudo ip link set owt-lan1 netns owt-lan
  sudo ip -n owt-lan addr add "$OWT_LAN_CLIENT_IP/24" dev owt-lan1
  sudo ip -n owt-lan link set owt-lan1 up
  sudo ip -n owt-lan link set lo up
  sudo ip -n owt-lan route add default via "$OWT_ROUTER_LAN_IP"

  # Control server. The embedded relay serves on the same HTTP port; STUN on its own UDP port.
  cat > "$w/hs/config.yaml" <<EOF
server_url: http://$OWT_HOST_IP:$OWT_HS_PORT
listen_addr: $OWT_HOST_IP:$OWT_HS_PORT
metrics_listen_addr: 127.0.0.1:0
grpc_listen_addr: 127.0.0.1:0
grpc_allow_insecure: false
noise:
  private_key_path: $w/hs/noise_private.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential
derp:
  server:
    enabled: true
    region_id: 999
    region_code: lab
    region_name: Lab
    stun_listen_addr: $OWT_HOST_IP:$OWT_STUN_PORT
    private_key_path: $w/hs/derp_server_private.key
    automatically_add_embedded_derp_region: true
    ipv4: $OWT_HOST_IP
  urls: []
  paths: []
  auto_update_enabled: false
database:
  type: sqlite
  sqlite:
    path: $w/hs/db.sqlite
    write_ahead_log: true
dns:
  magic_dns: true
  base_domain: owt.test
  override_local_dns: false
  nameservers:
    global: []
    # A split-DNS domain, with its own resolver.
    split:
      $OWT_SPLIT_DOMAIN:
        - $OWT_PEER_IP
  # A record outside the mesh suffix, as the console's DNS settings make one.
  extra_records:
    - name: $OWT_EXTRA_NAME
      type: A
      value: $OWT_EXTRA_IP
unix_socket: $w/hs/headscale.sock
unix_socket_permission: "0770"
logtail:
  enabled: false
log:
  format: text
  level: info
disable_check_updates: true
EOF
  nohup setsid "$hs" -c "$w/hs/config.yaml" serve > "$w/hs/headscale.log" 2>&1 < /dev/null &
  echo $! > "$w/hs/headscale.pid"
  local hsc="$hs -c $w/hs/config.yaml"
  for _ in $(seq 1 30); do [ -S "$w/hs/headscale.sock" ] && break; sleep 0.5; done
  [ -S "$w/hs/headscale.sock" ] || die "control server did not start: $(tail -5 "$w/hs/headscale.log")"
  $hsc users create lab >/dev/null
  local uid key
  uid=$($hsc users list -o json | jq -r '.[] | select(.name=="lab") | .id')
  # Reusable: run.sh joins one router per OpenWrt version with it.
  key=$($hsc preauthkeys create -u "$uid" --reusable -e 24h -o json | jq -r .key)

  # The "Internet" behind the exit node: who is asking, as this side sees it.
  cat > "$w/peer/echo.py" <<'EOF2'
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = (self.client_address[0] + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
http.server.HTTPServer((sys.argv[1], int(sys.argv[2])), H).serve_forever()
EOF2
  sudo sh -c "ip netns exec owt-peer python3 '$w/peer/echo.py' '$OWT_INET_IP' '$OWT_INET_PORT' > '$w/peer/echo.log' 2>&1 & echo \$! > '$w/peer/echo.pid'"

  # The split-DNS domain's resolver: A records for every name in the domain, NXDOMAIN otherwise.
  cat > "$w/peer/dns.py" <<'EOF2'
import socket, struct, sys
addr, port, zone, answer = sys.argv[1], int(sys.argv[2]), sys.argv[3].lower().rstrip("."), sys.argv[4]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((addr, port))
while True:
    q, peer = s.recvfrom(512)
    try:
        tid = struct.unpack(">H", q[:2])[0]
        i, labels = 12, []
        while q[i]:
            labels.append(q[i + 1:i + 1 + q[i]].decode().lower())
            i += 1 + q[i]
        qtype = struct.unpack(">H", q[i + 1:i + 3])[0]
        name = ".".join(labels)
        ok = name == zone or name.endswith("." + zone)
        ans = b""
        if ok and qtype == 1:
            ans = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(answer)
        hdr = struct.pack(">HHHHHH", tid, 0x8180 | (0 if ok else 3), 1, 1 if ans else 0, 0, 0)
        s.sendto(hdr + q[12:i + 5] + ans, peer)
    except Exception:
        pass
EOF2
  sudo sh -c "ip netns exec owt-peer python3 '$w/peer/dns.py' '$OWT_PEER_IP' 53 '$OWT_SPLIT_DOMAIN' '$OWT_SPLIT_ANSWER' > '$w/peer/dns.log' 2>&1 & echo \$! > '$w/peer/dns.pid'"

  # The peer node accepts subnet routes, so its replies to the router's LAN go back over the mesh.
  # It is also an exit node (approved below), for the router's LAN.
  start_peer "$w"
  sudo "$w/peer/flowmesh" --socket "$w/peer/flowmeshd.sock" up --login-server "http://$OWT_HOST_IP:$OWT_HS_PORT" \
      --auth-key "$key" --hostname owt-peer --accept-routes --advertise-exit-node --accept-dns=false --timeout 30s
  local peer_ip
  peer_ip=$(sudo "$w/peer/flowmesh" --socket "$w/peer/flowmeshd.sock" status --json | jq -r '.Self.TailscaleIPs[0]')
  [ -n "$peer_ip" ] && [ "$peer_ip" != null ] || die "peer did not get a mesh address"
  local peer_id
  peer_id=$($hsc nodes list -o json | jq -r '.[] | select(.given_name == "owt-peer" or .name == "owt-peer") | .id' | head -1)
  $hsc nodes approve-routes -i "$peer_id" -r 0.0.0.0/0,::/0 >/dev/null || die "could not approve the peer's exit routes"

  cat > "$w/lab.env" <<EOF
OWT_LOGIN_SERVER=http://$OWT_HOST_IP:$OWT_HS_PORT
OWT_AUTH_KEY=$key
OWT_PEER_MESH_IP=$peer_ip
OWT_HS="$hsc"
OWT_PEER_CLI="sudo $w/peer/flowmesh --socket $w/peer/flowmeshd.sock"
OWT_LAN_HOST_IP=$OWT_LAN_HOST_IP
OWT_LAN_CLIENT_IP=$OWT_LAN_CLIENT_IP
OWT_ROUTER_LAN_IP=$OWT_ROUTER_LAN_IP
OWT_INET_IP=$OWT_INET_IP
OWT_INET_PORT=$OWT_INET_PORT
OWT_EXTRA_NAME=$OWT_EXTRA_NAME
OWT_EXTRA_IP=$OWT_EXTRA_IP
OWT_SPLIT_DOMAIN=$OWT_SPLIT_DOMAIN
OWT_SPLIT_ANSWER=$OWT_SPLIT_ANSWER
OWT_PEER_IP=$OWT_PEER_IP
EOF
  chmod 0600 "$w/lab.env"
  echo "lab up: control server http://$OWT_HOST_IP:$OWT_HS_PORT, peer $peer_ip; env in $w/lab.env"
}

down() {
  local w
  w=$(realpath -m "$1")
  stop_pidfile "$w/peer/flowmeshd.pid"
  stop_pidfile "$w/peer/echo.pid"
  stop_pidfile "$w/peer/dns.pid"
  stop_pidfile "$w/hs/headscale.pid"
  [ -n "${OWT_INET_IP:-}" ] && sudo ip route del blackhole "$OWT_INET_IP/32" 2>/dev/null || true
  sudo ip link del owt-peer0 2>/dev/null || true
  sudo ip link del owt-lan0 2>/dev/null || true
  sudo ip link del owtbr0 2>/dev/null || true
  sudo ip netns del owt-peer 2>/dev/null || true
  sudo ip netns del owt-lan 2>/dev/null || true
  sudo rm -rf "$w/peer" "$w/hs"
  rm -f "$w/lab.env"
  echo "lab down"
}

peer_stop() {
  local w
  w=$(realpath -m "$1")
  stop_pidfile "$w/peer/flowmeshd.pid"
}

peer_start() {
  local w state=
  w=$(realpath -m "$1")
  sudo test -f "$w/peer/flowmeshd.pid" && sudo kill -0 "$(sudo cat "$w/peer/flowmeshd.pid")" 2>/dev/null &&
    die "the peer's daemon is running"
  start_peer "$w"
  for _ in $(seq 1 60); do
    state=$(sudo "$w/peer/flowmesh" --socket "$w/peer/flowmeshd.sock" status --json 2>/dev/null | jq -r .BackendState)
    [ "$state" = Running ] && return 0
    sleep 0.5
  done
  die "the peer did not get back to Running (state: $state)"
}

case "${1:-}" in
  up) [ $# -eq 4 ] || die "usage: lab.sh up <work_dir> <headscale_binary> <flowmesh-linux-x86_64.tar.gz>"; up "$2" "$3" "$4" ;;
  down) [ $# -eq 2 ] || die "usage: lab.sh down <work_dir>"; down "$2" ;;
  peer-stop) [ $# -eq 2 ] || die "usage: lab.sh peer-stop <work_dir>"; peer_stop "$2" ;;
  peer-start) [ $# -eq 2 ] || die "usage: lab.sh peer-start <work_dir>"; peer_start "$2" ;;
  *) die "usage: lab.sh up|down|peer-stop|peer-start ..." ;;
esac
