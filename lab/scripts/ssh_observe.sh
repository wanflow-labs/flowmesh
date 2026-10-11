#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Observe the official client's SSH server (`up --ssh`) and `tailscale ssh` client. Temporary
# official clients joined through https://hs-tls.lab (see tls_proxy.sh): tsS (172.29.0.131, the
# server, local users alice and carol) and tsC (172.29.0.132, the client, with OpenSSH's client
# installed). The policy gets an `ssh` section for the run and is restored at the end:
#   accept  tag:relay-enabled -> tag:relay-enabled  users root, alice, autogroup:nonroot
# Outputs go to OUT_DIR, one file per case.
#   ssh_observe.sh OUT_DIR
set -euo pipefail
out=$(mkdir -p "$1" && cd "$1" && pwd)
cd "$(dirname "$0")/.."
key=$(cat .authkey)
net=flowmesh-lab_lab
img=tailscale/tailscale:v1.94.2
names=(tsS tsC)
hs() { docker compose exec -T headscale headscale "$@"; }
saved=$(mktemp)
hs policy get > "$saved"
cleanup() {
  for n in "${names[@]}"; do docker exec "$n" tailscale logout >/dev/null 2>&1 || true; done
  docker rm -f "${names[@]}" >/dev/null 2>&1 || true
  docker compose cp "$saved" headscale:/tmp/policy-restore.json >/dev/null 2>&1 &&
    hs policy set -f /tmp/policy-restore.json >/dev/null 2>&1 && echo "policy restored" >&2
  rm -f "$saved"
}
trap cleanup EXIT
docker rm -f "${names[@]}" >/dev/null 2>&1 || true

python3 - "$saved" > "$out/policy.json" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
p["ssh"] = [{"action": "accept", "src": ["tag:relay-enabled"], "dst": ["tag:relay-enabled"],
             "users": ["root", "alice", "autogroup:nonroot"]}]
print(json.dumps(p, indent=2))
PY
docker compose cp "$out/policy.json" headscale:/tmp/policy-ssh.json >/dev/null
hs policy set -f /tmp/policy-ssh.json

certs=$(scripts/tls_proxy.sh up)
ips=(172.29.0.131 172.29.0.132)
for i in 0 1; do
  docker run -d --name "${names[$i]}" --hostname "${names[$i]}" --network "$net" --ip "${ips[$i]}" \
    --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun -e TS_NO_LOGS_NO_SUPPORT=true \
    -e SSL_CERT_FILE=/c/ca.pem -v "$certs:/c:ro" \
    --entrypoint tailscaled "$img" --statedir=/tmp/ts --tun=tailscale0 >/dev/null
done
docker exec tsS sh -c 'adduser -D -s /bin/sh alice && adduser -D -s /bin/sh carol' >/dev/null
docker exec tsC apk add -q --no-cache openssh-client >/dev/null
sleep 2
docker exec tsS tailscale up --login-server=https://hs-tls.lab --authkey="$key" --hostname=tsS --accept-dns=false --ssh --timeout=30s > "$out/up-ssh.txt" 2>&1 || true
docker exec tsC tailscale up --login-server=https://hs-tls.lab --authkey="$key" --hostname=tsC --accept-dns=false --timeout=30s >/dev/null
sleep 3
s_ip=$(docker exec tsS tailscale ip -4)
s_name=$(docker exec tsS tailscale status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["DNSName"].split(".")[0])')
echo "server $s_name $s_ip" > "$out/nodes.txt"

c() { # file command...: run on tsC, record the command, output and exit code
  local f=$1; shift
  # A hung session must not stall the run.
  { echo "\$ $*"; docker exec tsC timeout 30 sh -c "$*" 2>&1; echo "[exit $?]"; } > "$out/$f" || true
}
c ssh-help.txt "tailscale ssh --help"
c ssh-root-id.txt "tailscale ssh root@$s_name id"
c ssh-alice-env.txt "tailscale ssh alice@$s_name 'id; pwd; echo SHELL=\$SHELL; env | sort'"
c ssh-carol-nonroot.txt "tailscale ssh carol@$s_name id"
c ssh-daemon-unlisted.txt "tailscale ssh daemon@$s_name id"
c ssh-nosuchuser.txt "tailscale ssh nosuchuser@$s_name id"
c ssh-exit-code.txt "tailscale ssh root@$s_name 'exit 3'"
c ssh-stdin.txt "echo hello-from-stdin | tailscale ssh root@$s_name cat"
c ssh-tty.txt "tailscale ssh root@$s_name -tt 'tty; echo TERM=\$TERM; stty size'"
c ssh-by-ip.txt "tailscale ssh root@$s_ip hostname"
c ssh-debug-exec.txt "TS_DEBUG_SSH_EXEC=1 tailscale ssh root@$s_name true"
c ssh-known-hosts.txt "cat ~/.config/tailscale/ssh_known_hosts"
c nc-banner.txt "tailscale nc $s_name 22 </dev/null | head -c 64; echo"
c plain-ssh-verbose.txt "ssh -v -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes root@$s_ip id 2>&1 | grep -Ei 'remote software|authentications that can continue|authenticated|server host key|kex:' ; echo done"
c plain-ssh-sftp.txt "echo ls / | sftp -b - -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@$s_ip"
docker exec -d tsS sh -c 'echo forwarded-ok | nc -l -p 41112'
sleep 1
c plain-ssh-forward.txt "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ExitOnForwardFailure=yes -L 18022:127.0.0.1:41112 -N -f root@$s_ip; echo forward-started=\$?; sleep 1; nc 127.0.0.1 18022 </dev/null; pkill -f 18022:127.0.0.1"
docker exec tsC tailscale status --json > "$out/client-status.json" 2>&1 || true
docker exec tsS tailscale debug netmap > "$out/server-netmap.json" 2>&1 || true
python3 - "$out/server-netmap.json" > "$out/server-ssh-policy.json" <<'PY' || true
import json, sys
nm = json.load(open(sys.argv[1]))
print(json.dumps({"SSHPolicy": nm.get("SSHPolicy"), "SelfHostinfoSSHHostKeys": (nm.get("SelfNode") or {}).get("Hostinfo", {}).get("sshHostKeys")}, indent=1))
PY
docker exec tsS tailscale debug prefs > "$out/server-prefs.json" 2>&1 || true
docker exec tsS sh -c 'ls -la /tmp /var/lib/tailscale 2>/dev/null; find / -name "ssh_host_*" -path "*tailscale*" 2>/dev/null' > "$out/server-hostkey-files.txt" 2>&1 || true
docker logs tsS 2>&1 | grep -iE "ssh" | tail -60 > "$out/server-log-ssh.txt" || true
{ echo "\$ tailscale set --ssh=false"; docker exec tsS tailscale set --ssh=false 2>&1; echo "[exit $?]"; } > "$out/set-ssh-false.txt" || true
sleep 2
c ssh-after-disable.txt "tailscale ssh root@$s_name id"
c nc-after-disable.txt "timeout 5 tailscale nc $s_name 22 </dev/null | head -c 64; echo"
echo "written to $out"
