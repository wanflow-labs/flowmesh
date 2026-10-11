#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# flowmesh's SSH server and `flowmesh ssh` against the official client, case by case as in
# ssh_observe.sh. Temporary nodes:
#   fsS  flowmeshd --ssh (172.29.0.141), local users alice and carol
#   tsC  official client with OpenSSH's client (172.29.0.142), joined through https://hs-tls.lab
#   tsS  official SSH server (172.29.0.143), for `flowmesh ssh` from fsS
# The policy gets the same `ssh` section as in ssh_observe.sh for the run and is restored at the
# end. Outputs go to OUT_DIR; the first check that does not hold fails the run.
#   ssh_check.sh OUT_DIR
set -euo pipefail
out=$(mkdir -p "$1" && cd "$1" && pwd)
cd "$(dirname "$0")/.."
key=$(cat .authkey)
net=flowmesh-lab_lab
bin=/target/m11/release
img=tailscale/tailscale:v1.94.2
names=(fsS tsC tsS)
hs() { docker compose exec -T headscale headscale "$@"; }
saved=$(mktemp)
hs policy get > "$saved"
cleanup() {
  docker exec fsS "$bin/flowmesh" --socket=/tmp/fmd.sock logout >/dev/null 2>&1 || true
  for n in tsC tsS; do docker exec "$n" tailscale logout >/dev/null 2>&1 || true; done
  docker rm -f "${names[@]}" >/dev/null 2>&1 || true
  docker compose cp "$saved" headscale:/tmp/policy-restore.json >/dev/null 2>&1 &&
    hs policy set -f /tmp/policy-restore.json >/dev/null 2>&1 && echo "policy restored" >&2
  rm -f "$saved"
}
trap cleanup EXIT
docker rm -f "${names[@]}" >/dev/null 2>&1 || true
fail() { echo "FAIL: $*" >&2; exit 1; }

python3 - "$saved" > "$out/policy.json" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
p["ssh"] = [{"action": "accept", "src": ["tag:relay-enabled"], "dst": ["tag:relay-enabled"],
             "users": ["root", "alice", "autogroup:nonroot"]}]
print(json.dumps(p, indent=2))
PY
docker compose cp "$out/policy.json" headscale:/tmp/policy-ssh.json >/dev/null
hs policy set -f /tmp/policy-ssh.json >/dev/null

certs=$(scripts/tls_proxy.sh up)
for pair in "tsC 172.29.0.142" "tsS 172.29.0.143"; do
  set -- $pair
  docker run -d --name "$1" --hostname "$1" --network "$net" --ip "$2" \
    --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun -e TS_NO_LOGS_NO_SUPPORT=true \
    -e SSL_CERT_FILE=/c/ca.pem -v "$certs:/c:ro" \
    --entrypoint tailscaled "$img" --statedir=/tmp/ts --tun=tailscale0 >/dev/null
done
docker exec tsC apk add -q --no-cache openssh-client >/dev/null
docker run -d --name fsS --hostname fsS --network "$net" --ip 172.29.0.141 \
  --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun --init \
  -v flowmesh-lab_fm1-target:/target -v "$PWD/..:/src" -w /src flowmesh-lab/router:local sleep infinity >/dev/null
docker exec -e CARGO_TARGET_DIR=/target/m11 fsS cargo build -q --release -p flowmesh-daemon -p flowmesh-cli 2>&1 | grep -v '^info:' || true
docker exec fsS sh -c 'useradd -m -s /bin/sh alice && useradd -m -s /bin/sh carol'
docker exec -d fsS sh -c "exec $bin/flowmeshd --state-dir /tmp/fmd --socket /tmp/fmd.sock > /tmp/fmd.log 2>&1"
fm() { docker exec fsS "$bin/flowmesh" --socket=/tmp/fmd.sock "$@"; }
for _ in $(seq 1 40); do fm status >/dev/null 2>&1 && break; sleep 0.5; done
fm up --login-server=http://headscale.lab --authkey="$key" --hostname=fsS --accept-dns=false --ssh --timeout=30s >/dev/null
docker exec tsC tailscale up --login-server=https://hs-tls.lab --authkey="$key" --hostname=tsC --accept-dns=false --timeout=30s >/dev/null
docker exec tsS tailscale up --login-server=https://hs-tls.lab --authkey="$key" --hostname=tsS --accept-dns=false --ssh --timeout=30s >/dev/null
s_ip=$(fm ip -4)
s_ip6=$(fm ip -6)
c_ip6=$(docker exec tsC tailscale ip -6)
s_name=$(fm status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["DNSName"].split(".")[0])')
t_name=$(docker exec tsS tailscale status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["DNSName"].split(".")[0])')
echo "flowmesh server $s_name $s_ip; official server $t_name" > "$out/nodes.txt"
# Wait until the client sees the server's host keys (Hostinfo.sshHostKeys).
for _ in $(seq 1 30); do
  docker exec tsC tailscale status --json | grep -q '"sshHostKeys"' && break; sleep 1
done
docker exec tsC tailscale status --json > "$out/client-status.json"

c() { # file command...: run on tsC (30 s at most), record the command, output and exit code
  local f=$1; shift
  { echo "\$ $*"; docker exec tsC timeout 30 sh -c "$*" 2>&1; echo "[exit $?]"; } > "$out/$f" || true
}
has() { grep -qF -- "$2" "$out/$1" || fail "$1: expected «$2»"; }
c ssh-root-id.txt "tailscale ssh root@$s_name id"
c ssh-alice-env.txt "tailscale ssh alice@$s_name 'id; pwd; echo SHELL=\$SHELL; env | sort'"
c ssh-carol-nonroot.txt "tailscale ssh carol@$s_name id"
c ssh-daemon-unlisted.txt "tailscale ssh daemon@$s_name id"
c ssh-nosuchuser.txt "tailscale ssh nosuchuser@$s_name id"
c ssh-exit-code.txt "tailscale ssh root@$s_name 'exit 3'"
c ssh-stdin.txt "echo hello-from-stdin | tailscale ssh root@$s_name cat"
c ssh-tty.txt "tailscale ssh root@$s_name -tt 'tty; echo TERM=\$TERM; stty size'"
c ssh-by-ip.txt "tailscale ssh root@$s_ip hostname"
c ssh-signal-exit.txt "tailscale ssh root@$s_name 'kill -TERM \$\$'"
has ssh-root-id.txt "uid=0(root)"
has ssh-root-id.txt "[exit 0]"
has ssh-alice-env.txt "uid=1000(alice)"
has ssh-alice-env.txt "/home/alice"
has ssh-alice-env.txt "HOME=/home/alice"
# PATH follows /etc/login.defs (Debian adds the games directories).
grep -qE "^PATH=/usr/local/bin:/usr/bin:/bin(:|$)" "$out/ssh-alice-env.txt" || fail "PATH"
has ssh-alice-env.txt "SHELL=/bin/sh"
has ssh-alice-env.txt "USER=alice"
grep -qE "^SSH_CONNECTION=100\.64\.[0-9.]+ [0-9]+ $s_ip 22$" "$out/ssh-alice-env.txt" || fail "SSH_CONNECTION"
for u in carol daemon nosuchuser; do
  f=$(ls "$out" | grep -E "ssh-($u)" | head -1)
  has "$f" "flowmesh: tailnet policy does not permit you to SSH as user \"$u\""
  has "$f" "[exit 255]"
done
has ssh-exit-code.txt "[exit 3]"
has ssh-stdin.txt "hello-from-stdin"
grep -qE "^/dev/pts/[0-9]+" "$out/ssh-tty.txt" || fail "pty"
has ssh-by-ip.txt "fsS"
has ssh-signal-exit.txt "[exit 255]"

# SFTP: the router image has no sftp-server, so this is flowmesh's built-in one.
c sftp.txt "printf 'flowmesh-sftp\n' > /tmp/up.txt; printf 'put /tmp/up.txt /tmp/sftp-up.txt\nls -l /tmp/sftp-up.txt\nget /tmp/sftp-up.txt /tmp/down.txt\nmkdir /tmp/sftp-dir\nrename /tmp/sftp-dir /tmp/sftp-dir2\nrmdir /tmp/sftp-dir2\nrm /tmp/sftp-up.txt\n' | sftp -b - -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null alice@$s_ip && cat /tmp/down.txt"
has sftp.txt "[exit 0]"
grep -q "^flowmesh-sftp" "$out/sftp.txt" || fail "sftp round trip"
grep -qE "^-rw.* 1000 +1000 .*sftp-up.txt" "$out/sftp.txt" || fail "sftp: file owned by alice"

# Local port forwarding (allowAgentForwarding / allowLocalPortForwarding are set by headscale).
docker exec -d fsS sh -c 'echo forwarded-ok | nc -l -p 41112 -q 1'
sleep 1
c forward.txt "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ExitOnForwardFailure=yes -L 18022:127.0.0.1:41112 -N -f root@$s_ip; sleep 1; nc 127.0.0.1 18022 </dev/null; pkill -f 18022:127.0.0.1"
has forward.txt "forwarded-ok"

# Agent forwarding: the key in tsC's agent is listed on the server.
c agent.txt "eval \$(ssh-agent -s) >/dev/null; ssh-keygen -q -t ed25519 -N '' -C agent-check -f /tmp/k; ssh-add -q /tmp/k; ssh -A -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null alice@$s_ip 'echo SOCK=\$SSH_AUTH_SOCK; ssh-add -l'; ssh-agent -k >/dev/null"
has agent.txt "agent-check"

# Local users must not get in through the server's real port (it accepts only what arrives on
# the mesh interface), nor through port 22 of the host's own address (that is the host's sshd).
port=$(docker exec fsS sh -c "grep -o 'listening on port [0-9]*' /tmp/fmd.log | tail -1 | grep -o '[0-9]*\$'")
[ -n "$port" ] || fail "server port not in the log"
{
  echo "\$ (on fsS, as nobody) ssh to own mesh address, server port $port"
  docker exec -u nobody fsS timeout 10 ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -p "$port" root@"$s_ip" id 2>&1; echo "[exit $?]"
  echo "\$ (on fsS, as nobody) ssh to own mesh address, port 22"
  docker exec -u nobody fsS timeout 10 ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 root@"$s_ip" id 2>&1; echo "[exit $?]"
  # IPv6 lets an unprivileged process pick a peer's address as its source (IPV6_FREEBIND).
  echo "\$ (on fsS, as nobody) ssh to own IPv6 mesh address, server port $port, from tsC's IPv6 address"
  docker exec -i -u nobody fsS python3 - "$s_ip6" "$port" "$c_ip6" <<'PY' 2>&1; echo "[exit $?]"
import socket, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.IPPROTO_IPV6, 78, 1)  # IPV6_FREEBIND
s.bind((sys.argv[3], 0))
s.settimeout(5)
try:
    s.connect((sys.argv[1], int(sys.argv[2])))
    data = s.recv(64)
    print("connected; server said", data or b"(closed)")
except Exception as e:
    print("refused:", e)
PY
} > "$out/local-escalation.txt" 2>&1 || true
grep -q "uid=0" "$out/local-escalation.txt" && fail "a local user got root through the SSH server"
[ "$(grep -c '\[exit 255\]' "$out/local-escalation.txt")" -eq 2 ] || fail "local-escalation: expected both refused"
grep -q "SSH-2.0" "$out/local-escalation.txt" && fail "a spoofed local connection got the SSH greeting"
docker exec fsS grep -q "did not come through the mesh" /tmp/fmd.log || fail "server did not log the local refusal"

# flowmesh as the client: to the official server, and to itself through the mesh from tsC's
# point of view is covered above.
{
  echo "\$ flowmesh ssh root@$t_name id"; fm ssh "root@$t_name" id 2>&1; echo "[exit $?]"
  echo "\$ flowmesh ssh carol@$t_name id"; fm ssh "carol@$t_name" id 2>&1; echo "[exit $?]"
  echo "\$ cat ~/.config/flowmesh/ssh_known_hosts"; docker exec fsS cat /root/.config/flowmesh/ssh_known_hosts
} > "$out/flowmesh-client.txt" 2>&1 || true
has flowmesh-client.txt "uid=0(root)"
has flowmesh-client.txt "tailscale: tailnet policy does not permit you to SSH as user \"carol\""
grep -qE "^${t_name}\.mesh\.lab\.internal\. ssh-ed25519 " "$out/flowmesh-client.txt" || fail "known_hosts entry"

# Off again: port 22 belongs to the host (nothing listens there).
fm set --ssh=false
sleep 2
c ssh-after-disable.txt "tailscale ssh root@$s_name id"
has ssh-after-disable.txt "[exit 255]"
grep -q "uid=0" "$out/ssh-after-disable.txt" && fail "still serving after --ssh=false"
docker exec fsS grep -E "ssh:" /tmp/fmd.log > "$out/server-log.txt" || true
echo "all checks passed; outputs in $out"
