#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Install FlowMesh on Linux and, given a control server and an auth key, join the mesh.
#
#   curl -fsSL https://github.com/wanflow-labs/flowmesh/releases/latest/download/install.sh | sh
#   curl -fsSL .../install.sh | sh -s -- --login-server=URL --auth-key=KEY [options]
#
# Options (each also as an environment variable):
#   --login-server=URL     FLOWMESH_LOGIN_SERVER  join this control server after installing
#   --auth-key=KEY         FLOWMESH_AUTH_KEY      auth key for joining
#   --hostname=NAME        FLOWMESH_HOSTNAME      node name (default: the host name)
#   --advertise-exit-node  FLOWMESH_EXIT_NODE=1   offer this machine as an exit node (turns on IP forwarding)
#   --ssh                  FLOWMESH_SSH=1         run the SSH server (installs the SSH variant of the service)
#   --version=X.Y.Z        FLOWMESH_VERSION       version to install (default: the latest release)
#   --mirror=URL           FLOWMESH_MIRROR        download from URL/latest/... and URL/vX.Y.Z/... instead of GitHub
#   --method=deb|rpm|tar   FLOWMESH_METHOD        how to install (default: deb on dpkg systems, rpm on rpm systems, else tar)
#   --uninstall                                   log out, stop and remove FlowMesh (the node state in /var/lib/flowmesh stays)
#   -- ARGS...                                    further flags for `flowmesh up`
#
# Works with sh (dash, busybox ash, bash), curl or wget, on x86_64 and aarch64. Every download is
# checked against the release's SHA256SUMS.
set -eu

REPO_URL=https://github.com/wanflow-labs/flowmesh
login_server=${FLOWMESH_LOGIN_SERVER:-}
auth_key=${FLOWMESH_AUTH_KEY:-}
hostname=${FLOWMESH_HOSTNAME:-}
exit_node=${FLOWMESH_EXIT_NODE:-}
ssh=${FLOWMESH_SSH:-}
version=${FLOWMESH_VERSION:-}
mirror=${FLOWMESH_MIRROR:-}
method=${FLOWMESH_METHOD:-}
uninstall=
extra=

say() { printf 'flowmesh-install: %s\n' "$*"; }
die() { printf 'flowmesh-install: error: %s\n' "$*" >&2; exit 1; }
# Single-quote a value for reuse in a command line.
quote() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --login-server=*) login_server=${1#*=} ;;
    --auth-key=*|--authkey=*) auth_key=${1#*=} ;;
    --hostname=*) hostname=${1#*=} ;;
    --advertise-exit-node) exit_node=1 ;;
    --ssh) ssh=1 ;;
    --version=*) version=${1#*=} ;;
    --mirror=*) mirror=${1#*=} ;;
    --method=*) method=${1#*=} ;;
    --uninstall) uninstall=1 ;;
    -h|--help) sed -n '3,22p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//' || true; exit 0 ;;
    --) shift; for a in "$@"; do extra="$extra $(quote "$a")"; done; break ;;
    *) die "unknown option: $1 (see the header of this script)" ;;
  esac
  shift
done
version=${version#v}
mirror=${mirror%/}

# --- OpenWrt --------------------------------------------------------------------------------------
# Routers get FlowMesh as OpenWrt packages (procd service, settings in UCI, identity kept across
# sysupgrade). This script would overwrite the package's binaries, start a second daemon next to the
# service and keep the identity in /var/lib/flowmesh, which is lost on reboot there.
if [ -f /etc/openwrt_release ]; then
  if command -v apk >/dev/null 2>&1 && [ -d /etc/apk ]; then
    pkg_cmd="apk update && apk add luci-app-flowmesh"
  else
    pkg_cmd="opkg update && opkg install luci-app-flowmesh"
  fi
  die "this is OpenWrt: install the FlowMesh packages from the FlowMesh feed instead of this script:
    wget -qO- https://dl.wanflow.com/flowmesh/openwrt/add-feed.sh | sh
    $pkg_cmd
  then join under Services > FlowMesh in LuCI, or from the command line, see
  $REPO_URL/blob/main/docs/install.md#openwrt-routers"
fi

# --- privileges -----------------------------------------------------------------------------------
if [ "$(id -u)" = 0 ]; then
  SUDO=
elif command -v sudo >/dev/null 2>&1; then
  SUDO=sudo
elif command -v doas >/dev/null 2>&1; then
  SUDO=doas
else
  die "run as root (no sudo or doas found)"
fi
run() { $SUDO "$@"; }

# --- platform -------------------------------------------------------------------------------------
[ "$(uname -s)" = Linux ] || die "FlowMesh runs on Linux; on $(uname -s) use the Wanflow app (https://www.wanflow.com/downloads)"
case "$(uname -m)" in
  x86_64|amd64) arch=x86_64 deb_arch=amd64 ;;
  aarch64|arm64|armv8*) arch=aarch64 deb_arch=arm64 ;;
  *) die "unsupported CPU architecture $(uname -m): FlowMesh is built for x86_64 and aarch64" ;;
esac

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --retry 3 --connect-timeout 15 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -T 30 -O "$2" "$1"; }
else
  die "curl or wget is needed"
fi
if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
elif command -v openssl >/dev/null 2>&1; then
  sha256() { openssl dgst -sha256 "$1" | sed 's/.*= *//'; }
else
  die "sha256sum, shasum or openssl is needed to check the download"
fi

if [ -d /run/systemd/system ]; then
  init=systemd
elif command -v rc-service >/dev/null 2>&1 && [ -d /etc/init.d ]; then
  init=openrc
else
  init=none
fi

# Without an init system: stop flowmeshd by its /proc entry (minimal systems may lack pkill/pgrep)
# and wait until it has exited, since a stopping flowmeshd first restores routes and DNS (up to 20 s).
daemon_pids() {
  for p in /proc/[0-9]*; do
    [ "$(cat "$p/comm" 2>/dev/null)" = flowmeshd ] && echo "${p#/proc/}"
  done
  return 0
}
stop_daemon() {
  pids=$(daemon_pids)
  [ -n "$pids" ] || return 0
  # shellcheck disable=SC2086 # one argument per pid
  run kill $pids 2>/dev/null || true
  i=0
  while [ -n "$(daemon_pids)" ] && [ $i -lt 40 ]; do sleep 0.5; i=$((i + 1)); done
}

# --- uninstall ------------------------------------------------------------------------------------
if [ -n "$uninstall" ]; then
  if command -v flowmesh >/dev/null 2>&1; then run flowmesh logout >/dev/null 2>&1 || true; fi
  case $init in
    systemd) run systemctl disable --now flowmeshd >/dev/null 2>&1 || true ;;
    openrc) run rc-service flowmeshd stop >/dev/null 2>&1 || true; run rc-update del flowmeshd >/dev/null 2>&1 || true ;;
    none) stop_daemon ;;
  esac
  if command -v dpkg >/dev/null 2>&1 && dpkg -s flowmesh >/dev/null 2>&1; then
    run dpkg -r flowmesh >/dev/null
  elif command -v rpm >/dev/null 2>&1 && rpm -q flowmesh >/dev/null 2>&1; then
    run rpm -e flowmesh
  fi
  run rm -f /usr/sbin/flowmeshd /usr/bin/flowmesh /etc/systemd/system/flowmeshd.service \
    /etc/init.d/flowmeshd /usr/share/flowmesh/flowmeshd-ssh.service /etc/sysctl.d/99-flowmesh.conf
  [ "$init" = systemd ] && run systemctl daemon-reload || true
  say "removed; the node identity in /var/lib/flowmesh is kept (delete it to remove that too)"
  exit 0
fi

# --- what to download -----------------------------------------------------------------------------
url() { # url TAG FILE   (TAG is "latest" or vX.Y.Z)
  if [ -n "$mirror" ]; then
    printf '%s/%s/%s' "$mirror" "$1" "$2"
  elif [ "$1" = latest ]; then
    printf '%s/releases/latest/download/%s' "$REPO_URL" "$2"
  else
    printf '%s/releases/download/%s/%s' "$REPO_URL" "$1" "$2"
  fi
}

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t flowmesh)
trap 'rm -rf "$tmp"' EXIT INT TERM
chmod 755 "$tmp"

tag=latest
[ -n "$version" ] && tag="v$version"
fetch "$(url "$tag" SHA256SUMS)" "$tmp/SHA256SUMS" ||
  die "cannot download $(url "$tag" SHA256SUMS)${mirror:+ (mirror)}; check the network, or pass --mirror=URL"
if [ -z "$version" ]; then
  version=$(sed -n 's/.*  flowmesh-\([0-9][0-9.]*\)-linux-x86_64\.tar\.gz$/\1/p' "$tmp/SHA256SUMS" | head -1)
  [ -n "$version" ] || die "cannot tell the latest version from SHA256SUMS"
fi
tag="v$version"

installed=
if command -v flowmesh >/dev/null 2>&1; then
  installed=$(flowmesh version 2>/dev/null | head -1 | sed 's/^[^0-9]*//; s/[^0-9.].*//')
fi

if [ -z "$method" ]; then
  if command -v dpkg >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
    method=deb
  elif command -v rpm >/dev/null 2>&1 && { command -v dnf >/dev/null 2>&1 || command -v microdnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1 || command -v zypper >/dev/null 2>&1; }; then
    method=rpm
  else
    method=tar
  fi
fi
case $method in
  deb) file="flowmesh_${version}_${deb_arch}.deb" ;;
  rpm) file="flowmesh-${version}-1.${arch}.rpm" ;;
  tar) file="flowmesh-${version}-linux-${arch}.tar.gz" ;;
  *) die "--method must be deb, rpm or tar" ;;
esac

get() { # get FILE: download into $tmp and check it against SHA256SUMS
  want=$(sed -n "s/^\([0-9a-f]\{64\}\)  $1\$/\1/p" "$tmp/SHA256SUMS" | head -1)
  [ -n "$want" ] || die "$1 is not listed in SHA256SUMS of $tag"
  fetch "$(url "$tag" "$1")" "$tmp/$1" || die "cannot download $(url "$tag" "$1")"
  got=$(sha256 "$tmp/$1")
  [ "$got" = "$want" ] || die "checksum mismatch for $1 (got $got, want $want): not installing"
}

# --- install --------------------------------------------------------------------------------------
# flowmeshd configures addresses and routes with iproute2's `ip` (BusyBox's applet lacks some of it).
need_iproute=
if ! command -v ip >/dev/null 2>&1; then
  need_iproute=1
else
  case "$(readlink -f "$(command -v ip)" 2>/dev/null)" in *busybox*) need_iproute=1 ;; esac
fi
# pkg_install DEB_NAME RPM_NAME ALPINE_NAME OTHER_NAME (zypper, pacman): install from the distribution.
pkg_install() {
  if command -v apt-get >/dev/null 2>&1; then
    run env DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null &&
      run env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$1" >/dev/null
  elif command -v dnf >/dev/null 2>&1; then run dnf -y -q install "$2" >/dev/null
  elif command -v microdnf >/dev/null 2>&1; then run microdnf -y install "$2" >/dev/null
  elif command -v yum >/dev/null 2>&1; then run yum -y -q install "$2" >/dev/null
  elif command -v zypper >/dev/null 2>&1; then run zypper -q -n install "$4" >/dev/null
  elif command -v apk >/dev/null 2>&1; then run apk add -q "$3"
  elif command -v pacman >/dev/null 2>&1; then run pacman -S --noconfirm --needed "$4" >/dev/null
  else return 1
  fi
}
if [ -n "$need_iproute" ]; then
  say "installing iproute2 (flowmeshd needs the ip command)"
  pkg_install iproute2 iproute iproute2 iproute2 || die "the ip command (iproute2) is missing; install it and run this again"
fi
# An exit node forwards and masquerades through iptables or nftables.
if [ -n "$exit_node" ] && ! command -v iptables >/dev/null 2>&1 && ! command -v nft >/dev/null 2>&1; then
  say "installing nftables (an exit node needs forwarding rules)"
  pkg_install nftables nftables nftables nftables || say "warning: install iptables or nftables, or the exit node cannot forward"
fi

if [ "$installed" = "$version" ]; then
  say "FlowMesh $version is already installed"
else
  say "installing FlowMesh $version ($method, $arch)${installed:+ over $installed}"
  get "$file"
  case $method in
    deb) run dpkg -i "$tmp/$file" >/dev/null ;;
    rpm) run rpm -U --replacepkgs "$tmp/$file" ;;
    tar)
      tar -xzf "$tmp/$file" -C "$tmp"
      d="$tmp/flowmesh-$version-linux-$arch"
      run install -m 0755 "$d/flowmeshd" /usr/sbin/flowmeshd
      run install -m 0755 "$d/flowmesh" /usr/bin/flowmesh
      run mkdir -p /usr/share/flowmesh
      run install -m 0644 "$d/flowmeshd-ssh.service" /usr/share/flowmesh/flowmeshd-ssh.service
      if [ "$init" = systemd ] && [ ! -f /usr/lib/systemd/system/flowmeshd.service ] && [ ! -f /lib/systemd/system/flowmeshd.service ]; then
        run install -m 0644 "$d/flowmeshd.service" /usr/lib/systemd/system/flowmeshd.service
      fi
      ;;
  esac
fi

# The SSH server needs the unsandboxed unit (its sessions inherit the service's sandbox).
if [ -n "$ssh" ] && [ "$init" = systemd ]; then
  run install -m 0644 /usr/share/flowmesh/flowmeshd-ssh.service /etc/systemd/system/flowmeshd.service
fi

if [ ! -c /dev/net/tun ]; then
  run modprobe tun >/dev/null 2>&1 || true
  [ -c /dev/net/tun ] || say "warning: /dev/net/tun is missing; in a container, give it the TUN device (and NET_ADMIN)"
fi

if [ -n "$exit_node" ]; then
  printf 'net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n' > "$tmp/99-flowmesh.conf"
  run install -m 0644 "$tmp/99-flowmesh.conf" /etc/sysctl.d/99-flowmesh.conf
  run sysctl -q -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 ||
    run sysctl -p /etc/sysctl.d/99-flowmesh.conf >/dev/null 2>&1 || say "warning: could not turn on IP forwarding"
fi

# --- service --------------------------------------------------------------------------------------
case $init in
  systemd)
    run systemctl daemon-reload
    run systemctl enable flowmeshd >/dev/null 2>&1
    run systemctl restart flowmeshd
    ;;
  openrc)
    cat > "$tmp/flowmeshd.openrc" <<'RC'
#!/sbin/openrc-run
description="FlowMesh mesh networking daemon"
command=/usr/sbin/flowmeshd
command_args="--state-dir /var/lib/flowmesh --socket /var/run/flowmesh/flowmeshd.sock"
command_background=true
pidfile=/var/run/flowmeshd.pid
output_log=/var/log/flowmeshd.log
error_log=/var/log/flowmeshd.log
depend() { need net; }
start_pre() { checkpath -d -m 0755 /var/run/flowmesh; checkpath -d -m 0700 /var/lib/flowmesh; }
RC
    run install -m 0755 "$tmp/flowmeshd.openrc" /etc/init.d/flowmeshd
    run rc-update add flowmeshd default >/dev/null 2>&1 || true
    run rc-service flowmeshd restart >/dev/null
    ;;
  none)
    say "no systemd or OpenRC found: starting flowmeshd in the background (it will not start at boot)"
    run mkdir -p /var/run/flowmesh /var/lib/flowmesh
    run chmod 0700 /var/lib/flowmesh
    stop_daemon
    run sh -c 'nohup /usr/sbin/flowmeshd --state-dir /var/lib/flowmesh --socket /var/run/flowmesh/flowmeshd.sock >>/var/log/flowmeshd.log 2>&1 &'
    ;;
esac
i=0
until run flowmesh status >/dev/null 2>&1 || run test -S /var/run/flowmesh/flowmeshd.sock; do
  i=$((i + 1))
  [ $i -lt 40 ] || die "flowmeshd did not start; see journalctl -u flowmeshd or /var/log/flowmeshd.log"
  sleep 0.5
done

# --- join -----------------------------------------------------------------------------------------
if [ -z "$login_server" ]; then
  # An upgrade keeps the node logged in: the daemon reconnects by itself.
  state() { run flowmesh status --json 2>/dev/null | sed -n 's/.*"BackendState": *"\([A-Za-z]*\)".*/\1/p' | head -1; }
  i=0
  while [ $i -lt 20 ]; do
    case "$(state)" in Running|NeedsLogin|Stopped) break ;; esac
    i=$((i + 1)); sleep 0.5
  done
  if [ "$(state)" = Running ]; then
    say "done: this machine is still on the mesh as $(run flowmesh ip -4 2>/dev/null || echo before)"
  else
    say "installed. Join a mesh with: sudo flowmesh up --login-server=<your mesh address> --auth-key=<key>"
  fi
  exit 0
fi
[ -n "$auth_key" ] || die "--login-server needs --auth-key"
# The key goes through a 0600 file, so it never appears in the process list of flowmesh.
umask 077
printf '%s' "$auth_key" > "$tmp/authkey"
set -- up "--login-server=$login_server" "--auth-key=file:$tmp/authkey" --timeout=60s
[ -n "$hostname" ] && set -- "$@" "--hostname=$hostname"
[ -n "$exit_node" ] && set -- "$@" --advertise-exit-node
[ -n "$ssh" ] && set -- "$@" --ssh
eval "set -- \"\$@\" $extra"
say "joining $login_server"
run flowmesh "$@"
ip=$(run flowmesh ip -4 2>/dev/null || true)
say "done: this machine is ${ip:-on the mesh}${hostname:+ ($hostname)}"
