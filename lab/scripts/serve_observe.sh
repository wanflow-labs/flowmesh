#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Observe the official `tailscale serve` (node-level serving; services need control server support
# headscale lacks). Temporary official clients joined through https://hs-tls.lab: svS (172.29.0.161,
# serves; backends: an echo of each HTTP request on 127.0.0.1:3000 and :4000, the same on a Unix
# socket, a TCP echo on 127.0.0.1:7000, a directory) and svC (172.29.0.162, requests with curl).
# One file per case in OUT_DIR. SERVER=flowmesh runs the same cases with flowmeshd on svS (the
# client stays official), for comparison (lab/scripts/serve_compare.py).
#   serve_observe.sh OUT_DIR
set -euo pipefail
out=$(mkdir -p "$1" && cd "$1" && pwd)
cd "$(dirname "$0")/.."
key=$(cat .authkey)
net=flowmesh-lab_lab
img=tailscale/tailscale:v1.94.2
names=(svS svC)
server=${SERVER:-official}
bin=/target/m11/release
cleanup() {
  for n in "${names[@]}"; do docker exec "$n" tailscale logout >/dev/null 2>&1 || true; done
  docker exec svS flowmesh logout >/dev/null 2>&1 || true
  docker rm -f "${names[@]}" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
certs=$(scripts/tls_proxy.sh up)
official_node() { # name ip
  docker run -d --name "$1" --hostname "$1" --network "$net" --ip "$2" \
    --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun -e TS_NO_LOGS_NO_SUPPORT=true \
    -e SSL_CERT_FILE=/c/ca.pem -v "$certs:/c:ro" \
    --entrypoint tailscaled "$img" --statedir=/tmp/ts --tun=tailscale0 >/dev/null
}
official_node svC 172.29.0.162
if [ "$server" = flowmesh ]; then
  docker run -d --name svS --hostname svS --network "$net" --ip 172.29.0.161 \
    --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun --init \
    -v flowmesh-lab_fm1-target:/target -v "$PWD/..:/src" -w /src flowmesh-lab/router:local sleep infinity >/dev/null
  docker exec -e CARGO_TARGET_DIR=/target/m11 svS cargo build -q --release -p flowmesh-daemon -p flowmesh-cli 2>&1 | grep -v '^info:' || true
  docker exec svS sh -c "ln -sf $bin/flowmesh /usr/local/bin/flowmesh"
  docker exec -d svS sh -c "exec $bin/flowmeshd --state-dir /tmp/fmd > /tmp/fmd.log 2>&1"
  for _ in $(seq 1 40); do docker exec svS flowmesh status >/dev/null 2>&1 && break; sleep 0.5; done
  tsx=flowmesh
else
  official_node svS 172.29.0.161
  docker exec svS apk add -q --no-cache python3 >/dev/null
  tsx=tailscale
fi
docker exec svC apk add -q --no-cache curl >/dev/null
# Backends on svS.
docker exec -i svS sh -c 'cat > /tmp/echo.py' <<'PY'
import http.server, socketserver, sys, os, socket
class H(http.server.BaseHTTPRequestHandler):
    def handle_one(self):
        pass
    def do_ANY(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        lines = [f"backend={self.server.tag}", f"{self.command} {self.path} {self.request_version}"]
        lines += [f"{k}: {v}" for k, v in self.headers.items()]
        lines.append(f"body={body.decode(errors='replace')}")
        data = ("\n".join(lines) + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("X-Backend", self.server.tag)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_ANY
    def log_message(self, *a):
        pass
where = sys.argv[1]
if where.startswith("unix:"):
    path = where[5:]
    if os.path.exists(path):
        os.remove(path)
    class S(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        pass
    s = S(path, H)
    s.server_name, s.server_port = "unix", 0
    def get_request(self=s):
        req, _ = socket.socket.accept(self.socket)
        return req, ("unix", 0)
    s.get_request = get_request
else:
    s = http.server.ThreadingHTTPServer(("127.0.0.1", int(where)), H)
s.tag = where
s.serve_forever()
PY
docker exec -i svS sh -c 'cat > /tmp/tcpecho.py' <<'PY'
import socketserver
class H(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"tcp-echo from " + str(self.client_address).encode() + b"\n")
        while True:
            d = self.request.recv(4096)
            if not d:
                return
            self.request.sendall(d)
socketserver.ThreadingTCPServer(("127.0.0.1", 7000), H).serve_forever()
PY
docker exec -d svS python3 /tmp/echo.py 3000
docker exec -d svS python3 /tmp/echo.py 4000
docker exec -d svS python3 /tmp/echo.py unix:/tmp/echo.sock
docker exec -d svS python3 /tmp/tcpecho.py
docker exec svS sh -c 'mkdir -p /tmp/site/sub && echo "<h1>index</h1>" > /tmp/site/index.html && echo hello-file > /tmp/site/sub/a.txt'
sleep 1
# svC joins untagged (a one-off key without tags, 1 h), so requests carry a user identity.
ukey=$(docker compose exec -T headscale headscale preauthkeys create -u 1 --expiration 1h -o json | python3 -c 'import json,sys; print(json.load(sys.stdin)["key"])')
if [ "$server" = flowmesh ]; then
  docker exec svS flowmesh up --login-server=http://headscale.lab --authkey="$key" --hostname=svS --accept-dns=false --timeout=30s >/dev/null
else
  docker exec svS tailscale up --login-server=https://hs-tls.lab --authkey="$key" --hostname=svS --accept-dns=false --timeout=30s >/dev/null
fi
docker exec svC tailscale up --login-server=https://hs-tls.lab --authkey="$ukey" --hostname=svC --accept-dns=false --timeout=30s >/dev/null
sleep 2
s_ip=$(docker exec svS $tsx ip -4)
s_name=$(docker exec svS $tsx status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["DNSName"].rstrip("."))')
echo "server $s_name $s_ip" > "$out/nodes.txt"
# Requests are matched by Host: give the client both names.
docker exec svC sh -c "echo '$s_ip $s_name ${s_name%%.*}' >> /etc/hosts"
u=http://$s_name

srv() { # file args...: a serve command on svS (20 s at most)
  local f=$1; shift
  { echo "\$ $tsx $*"; docker exec svS timeout 20 $tsx "$@" 2>&1; echo "[exit $?]"; } > "$out/$f" || true
}
cli() { # file command: on svC
  local f=$1; shift
  { echo "\$ $*"; docker exec svC timeout 15 sh -c "$*" 2>&1; echo "[exit $?]"; } > "$out/$f" || true
}
srv status-empty.txt serve status
srv status-empty-json.txt serve status --json
srv https-default.txt serve --bg --yes 3000
srv status-after-https.txt serve status
srv reset-1.txt serve reset
srv http-port.txt serve --bg --http=80 3000
srv status-http.txt serve status
srv status-http-json.txt serve status --json
cli get-root.txt "curl -sS -i $u/"
cli get-by-ip.txt "curl -sS -i http://$s_ip/"
cli get-by-short-name.txt "curl -sS -i http://${s_name%%.*}/"
cli get-path-query.txt "curl -sS -i '$u/a/b?x=1&y=2'"
cli post-body.txt "curl -sS -i -X POST -d hello-body $u/post"
cli get-spoofed-headers.txt "curl -sS -i -H 'Tailscale-User-Login: evil@example.com' -H 'X-Forwarded-For: 6.6.6.6' $u/"
srv set-path.txt serve --bg --http=80 --set-path=/api http://127.0.0.1:4000
srv set-path-sub.txt serve --bg --http=80 --set-path=/text text:hello-text
srv status-paths.txt serve status
srv status-paths-json.txt serve status --json
cli get-api.txt "curl -sS -i $u/api/v1/items"
cli get-api-root.txt "curl -sS -i $u/api"
cli get-text.txt "curl -sS -i $u/text"
cli get-other.txt "curl -sS -i $u/other"
srv dir.txt serve --bg --http=8080 /tmp/site
cli get-dir-index.txt "curl -sS -i $u:8080/"
cli get-dir-file.txt "curl -sS -i $u:8080/sub/a.txt"
cli get-dir-listing.txt "curl -sS -i $u:8080/sub/"
cli get-dir-missing.txt "curl -sS -i $u:8080/nope"
srv unix.txt serve --bg --http=8081 unix:/tmp/echo.sock
cli get-unix.txt "curl -sS -i $u:8081/u"
srv backend-down.txt serve --bg --http=8082 3999
cli get-backend-down.txt "curl -sS -i $u:8082/"
srv tcp.txt serve --bg --tcp=2222 tcp://localhost:7000
cli tcp-echo.txt "(printf 'ping-tcp\n'; sleep 1) | nc $s_ip 2222"
srv tcp-port-only.txt serve --bg --tcp=2223 7000
srv tls-terminated.txt serve --bg --tls-terminated-tcp=2224 7000
srv proxy-protocol.txt serve --bg --tcp=2225 --proxy-protocol=1 tcp://localhost:7000
cli tcp-echo-proxy-protocol.txt "(printf 'ping-pp\n'; sleep 1) | nc $s_ip 2225"
cli tcp-by-name.txt "(printf 'ping-name\n'; sleep 1) | nc $s_name 2223"
srv status-all.txt serve status
srv status-all-json.txt serve status --json
srv off-one.txt serve --http=8082 off
srv off-path.txt serve --http=80 --set-path=/api off
srv status-after-off.txt serve status
srv bad-target.txt serve --bg --http=80 ftp://x
srv bad-port.txt serve --bg --http=70000 3000
srv two-modes.txt serve --bg --http=80 --tcp=81 3000
srv service-flag.txt serve --bg --service=svc:web --http=80 3000
srv prefs.txt debug prefs
docker exec svS $tsx serve status --json > "$out/serve-config.json" 2>&1 || true
srv reset-2.txt serve reset
srv status-after-reset.txt serve status
# Foreground: runs until interrupted, config gone afterwards.
{
  echo "\$ $tsx serve --http=9090 3000   (foreground, stopped after 4 s)"
  docker exec svC sh -c "curl -s -o /dev/null -w 'before: %{http_code}\\n' --max-time 3 $u:9090/ || echo 'before: refused'"
  docker exec svS sh -c "$tsx serve --http=9090 3000 > /tmp/fg.out 2>&1 & pid=\$!; sleep 2; $tsx serve status; sleep 2; kill -INT \$pid; sleep 1; echo '--- output:'; cat /tmp/fg.out; echo '--- status after:'; $tsx serve status" &
  sleep 3
  docker exec svC sh -c "curl -s -o /dev/null -w 'during: %{http_code}\\n' --max-time 3 $u:9090/ || echo 'during: refused'"
  wait
  sleep 1
  docker exec svC sh -c "curl -s -o /dev/null -w 'after: %{http_code}\\n' --max-time 3 $u:9090/ || echo 'after: refused'"
} > "$out/foreground.txt" 2>&1 || true
if [ "$server" = flowmesh ]; then
  # Local users must not reach the serve listener directly (it would take a peer's identity).
  srv tcp-again.txt serve --bg --tcp=2226 7000
  port=$(docker exec svS sh -c "grep -o 'serve: port 2226 .* listener port [0-9]*' /tmp/fmd.log | tail -1 | grep -o '[0-9]*\$'")
  {
    echo "\$ (on svS, as nobody) connect to the listener port $port of $s_ip directly"
    docker exec -u nobody svS python3 -c "import socket; s=socket.create_connection(('$s_ip', int('$port')), 3); s.settimeout(2); print('got:', s.recv(64))" 2>&1; echo "[exit $?]"
  } > "$out/local-direct.txt" 2>&1 || true
  docker exec svS grep -E "serve:" /tmp/fmd.log | tail -40 > "$out/server-log.txt" || true
else
  docker logs svS 2>&1 | grep -iE "serve|proxy" | tail -40 > "$out/server-log.txt" || true
fi
echo "written to $out"
