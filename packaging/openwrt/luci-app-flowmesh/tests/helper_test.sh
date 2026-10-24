#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Tests for /usr/libexec/flowmesh-luci. Runs on OpenWrt (busybox ash, jshn, uci, procd) with the
# flowmesh package installed: `sh helper_test.sh` from this directory. A fake `flowmesh` (and
# `logread`) is put first on the helper's PATH; it records its arguments and prints a chosen output.
# `apply` goes through the real /etc/init.d/flowmesh reload (with the fake CLI) and the real
# flowmesh-fw; /etc/config/flowmesh is restored afterwards. Exit status: the number of failures.
# (pass/fail always succeed, so "check && pass || fail" is safe; single quotes keep the payloads literal.)
# shellcheck disable=SC2015,SC2016,SC2329

here=$(cd "$(dirname "$0")" && pwd)
src=$here/../root/usr/libexec/flowmesh-luci
fx=$here/fixtures
work=$(mktemp -d /tmp/flowmesh-luci-test.XXXXXX)
fakebin=$work/bin
mkdir -p "$fakebin"
cp /etc/config/flowmesh "$work/flowmesh.uci"
restore() {
	cp "$work/flowmesh.uci" /etc/config/flowmesh
	/etc/init.d/flowmesh reload > /dev/null 2>&1
	rm -rf "$work"
}
trap restore EXIT

fails=0
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; fails=$((fails + 1)); }

# The helper under test, with the fake bin first on its PATH and a short hard deadline.
helper=$work/flowmesh-luci
sed -e "s|^PATH=/usr/sbin:/usr/bin:/sbin:/bin\$|PATH=$fakebin:/usr/sbin:/usr/bin:/sbin:/bin|" \
	-e 's|^UP_DEADLINE=25 |UP_DEADLINE=3 |' "$src" > "$helper"
chmod 0755 "$helper"
[ "$(grep -c "^PATH=$fakebin:" "$helper")" = 1 ] && [ "$(grep -c '^UP_DEADLINE=3 ' "$helper")" = 1 ] ||
	{ echo "could not point the helper at the fakes"; exit 100; }

# Fake flowmesh: appends "<args, one per line>" and a "--" line to $work/calls; for --auth-key=file:
# records the file's mode and content in $work/keyfile; prints $work/out; exits with $work/rc;
# sleeps $work/sleep seconds first if that file exists. `debug prefs` prints $work/prefs instead,
# when that file exists (and is not recorded).
cat > "$fakebin/flowmesh" <<FAKE
#!/bin/sh
[ "\$1 \$2" = "debug prefs" ] && [ -f $work/prefs ] && { cat $work/prefs; exit 0; }
[ "\$1" = netcheck ] && echo "# Warning: this JSON format is not yet considered a stable interface" >&2
if [ "\$1" = bugreport ]; then
	# Like the real CLI: the output file must not exist yet; its path is recorded.
	[ -e "\$3" ] && { echo "write \$3: File exists" >&2; exit 1; }
	echo "\$3" > $work/reportpath
	[ -f $work/report ] && cat $work/report > "\$3"
fi
for a in "\$@"; do
	printf '%s\n' "\$a" >> $work/calls
	case "\$a" in
	--auth-key=file:*)
		f=\${a#--auth-key=file:}
		{ echo "\$f"; ls -l "\$f" | cut -c1-10; cat "\$f"; } > $work/keyfile ;;
	esac
done
echo -- >> $work/calls
[ -f $work/sleep ] && sleep \$(cat $work/sleep)
[ -f $work/out ] && cat $work/out
exit \$(cat $work/rc 2>/dev/null || echo 0)
FAKE
chmod 0755 "$fakebin/flowmesh"

# Fake logread: 250 numbered lines, one with JSON-hostile characters.
cat > "$fakebin/logread" <<'FAKE'
#!/bin/sh
i=1
while [ $i -le 250 ]; do
	if [ $i = 249 ]; then
		printf '%s\n' 'line 249 "quoted" back\slash	tab'
	else
		echo "daemon.info flowmeshd: line $i"
	fi
	i=$((i + 1))
done
FAKE
chmod 0755 "$fakebin/logread"

# fake <rc> [output file]
fake() {
	rm -f "$work/calls" "$work/keyfile" "$work/out" "$work/sleep" "$work/prefs" "$work/report" "$work/reportpath"
	echo "$1" > "$work/rc"
	[ -n "$2" ] && cp "$2" "$work/out"
}
called() { [ -s "$work/calls" ]; }
# run <args...>: the helper's stdout in $res, its exit status in $rc.
run() {
	res=$("$helper" "$@")
	rc=$?
}
field() { printf '%s' "$res" | jsonfilter -e "@.$1"; }
# expect_code <code> <description>: ran with exit 0, one JSON line, ok false with that code.
expect_code() {
	if [ "$rc" = 0 ] && [ "$(printf '%s\n' "$res" | wc -l)" = 1 ] && [ "$(field ok)" = false ] &&
		[ "$(field code)" = "$1" ]; then
		pass "$2 -> $1"
	else
		fail "$2 -> $1 (rc=$rc, got: $res)"
	fi
}
expect_ok() {
	if [ "$rc" = 0 ] && [ "$(field ok)" = true ]; then pass "$1"; else fail "$1 (rc=$rc, got: $res)"; fi
}

URL=https://mesh.example.com
KEY=0123456789abcdef0123456789abcdef0123456789abcdef

echo "== argument checks (the CLI must not be called)"
long64=$(printf 'a%.0s' $(seq 1 64))
long129=$(printf 'k%.0s' $(seq 1 129))
bad_up() {
	local d="$1"
	shift
	fake 0
	run up "$@"
	expect_code invalid_arg "$d"
	if called; then fail "$d: the CLI was called"; fi
}
bad_up "url: no scheme" mesh.example.com "$KEY" gw1
bad_up "url: ftp" ftp://mesh.example.com "$KEY" gw1
bad_up "url: empty host" https:// "$KEY" gw1
bad_up "url: semicolon" 'https://mesh.example.com;reboot' "$KEY" gw1
bad_up "url: semicolon in path" 'https://mesh.example.com/;reboot' "$KEY" gw1
bad_up "url: backtick" 'https://mesh.example.com/`reboot`' "$KEY" gw1
bad_up "url: \$(...)" 'https://mesh.example.com/$(reboot)' "$KEY" gw1
bad_up "url: space" 'https://mesh.example.com/a b' "$KEY" gw1
bad_up "url: newline" "https://mesh.example.com
reboot" "$KEY" gw1
bad_up "url: quote" "https://mesh.example.com/'x" "$KEY" gw1
bad_up "key: 7 chars" "$URL" abcdefg gw1
bad_up "key: 129 chars" "$URL" "$long129" gw1
bad_up "key: dot" "$URL" abcdefgh.ijk gw1
bad_up "key: semicolon" "$URL" 'abcdefgh;reboot' gw1
bad_up "key: backtick" "$URL" 'abcdefgh`reboot`' gw1
bad_up "key: \$(...)" "$URL" 'abcdefgh$(reboot)' gw1
bad_up "key: newline" "$URL" "abcdefgh
ijklmnop" gw1
bad_up "hostname: empty" "$URL" "$KEY" ''
bad_up "hostname: 64 chars" "$URL" "$KEY" "$long64"
bad_up "hostname: underscore" "$URL" "$KEY" gw_1
bad_up "hostname: dot" "$URL" "$KEY" gw.1
bad_up "hostname: semicolon" "$URL" "$KEY" 'gw;reboot'
bad_up "hostname: \$(...)" "$URL" "$KEY" 'gw$(reboot)'
bad_up "hostname: backtick" "$URL" "$KEY" 'gw`reboot`'
bad_up "too few arguments" "$URL" "$KEY"
bad_up "too many arguments" "$URL" "$KEY" gw1 extra
fake 0; run; expect_code invalid_arg "no command"
fake 0; run reboot; expect_code invalid_arg "unknown command"
fake 0; run status --json; expect_code invalid_arg "status with an argument"
if called; then fail "status with an argument: the CLI was called"; fi
fake 0; run up "$URL" "$KEY" "$(printf 'b%.0s' $(seq 1 63))"; expect_ok "hostname of 63 chars accepted"
fake 0; run up 'http://[fd7a:115c::1]:8080/mesh' "$(printf 'k%.0s' $(seq 1 128))" gw1
expect_ok "IPv6 URL with port and path, 128-char key accepted"

echo "== up: errors, from CLI output recorded against a real control server"
up_error() {
	fake 1 "$fx/$1.txt"
	run up "$URL" "$KEY" gw1
	expect_code "$2" "$1"
	[ "$(field detail)" = "$(cat "$fx/$1.txt")" ] && pass "$1: detail is the CLI's text" ||
		fail "$1: detail is the CLI's text (got: $(field detail))"
}
up_error up-key-used key_invalid
up_error up-key-expired key_invalid
up_error up-key-wrong key_invalid
up_error up-unreachable-refused unreachable
up_error up-unreachable-dns unreachable
up_error up-timeout-silent timeout
up_error daemon-down daemon_down
# Not recorded (see the README in fixtures/): the documented pattern for a refusal over a node limit.
printf '%s\n' 'flowmesh: the control server did not accept this node: site limit reached' > "$work/limit.txt"
fake 1 "$work/limit.txt"; run up "$URL" "$KEY" gw1; expect_code site_limit "refusal naming a limit (pattern, not recorded)"
printf '%s\n' 'flowmesh: something else entirely' > "$work/other.txt"
fake 1 "$work/other.txt"; run up "$URL" "$KEY" gw1; expect_code unknown "unrecognised CLI error"
fake 0; echo 15 > "$work/sleep"
start=$(date +%s)
run up "$URL" "$KEY" gw1
took=$(( $(date +%s) - start ))
expect_code timeout "CLI does not return before the hard deadline"
[ "$took" -le 6 ] && pass "hard deadline returns in ${took}s" || fail "hard deadline took ${took}s"
kf=$(sed -n 1p "$work/keyfile" 2>/dev/null)
[ -n "$kf" ] && [ ! -e "$kf" ] && pass "key file removed after the deadline" || fail "key file removed after the deadline ($kf)"

echo "== up: success"
uci -q set flowmesh.main.hostname=old; uci -q set flowmesh.main.exit_node=0
uci -q set flowmesh.main.accept_routes=1; uci -q set flowmesh.main.advertise_lan=1
uci -q delete flowmesh.main.lan_routes; uci -q add_list flowmesh.main.lan_routes=10.9.0.0/24
uci -q add_list flowmesh.main.lan_routes=10.9.1.0/24; uci commit flowmesh
fake 0
run up "$URL" "$KEY" gw-test
expect_ok "up succeeds"
for a in up --reset "--login-server=$URL" --hostname=gw-test --accept-dns=false --timeout=20s \
	--accept-routes=1 --advertise-routes=10.9.0.0/24,10.9.1.0/24 --advertise-exit-node=0; do
	grep -qxF -- "$a" "$work/calls" && pass "up passes $a" || fail "up passes $a"
done
grep -qF -- "$KEY" "$work/calls" && fail "the key appears in the CLI's arguments" || pass "the key is not in the CLI's arguments"
kf=$(sed -n 1p "$work/keyfile")
[ "$(sed -n 2p "$work/keyfile")" = "-rw-------" ] && pass "key file is 0600" || fail "key file is 0600 ($(sed -n 2p "$work/keyfile"))"
[ "$(sed -n 3p "$work/keyfile")" = "$KEY" ] && pass "key file holds the key" || fail "key file holds the key"
[ -n "$kf" ] && [ ! -e "$kf" ] && pass "key file removed after up" || fail "key file removed after up ($kf)"
ls /tmp/flowmesh-key.* > /dev/null 2>&1 && fail "no flowmesh-key.* left in /tmp" || pass "no flowmesh-key.* left in /tmp"
[ "$(uci -q get flowmesh.main.hostname)" = gw-test ] && pass "hostname saved to UCI" || fail "hostname saved to UCI"
fake 1 "$fx/up-key-used.txt"
run up "$URL" "$KEY" gw-other
[ "$(uci -q get flowmesh.main.hostname)" = gw-test ] && pass "failed up leaves the UCI hostname" || fail "failed up leaves the UCI hostname"
kf=$(sed -n 1p "$work/keyfile")
[ -n "$kf" ] && [ ! -e "$kf" ] && pass "key file removed after a failed up" || fail "key file removed after a failed up"

echo "== reconnect"
# `flowmesh debug prefs` as flowmeshd prints it after `down` (trimmed).
prefs() { printf '{ "control_url": "%s", "hostname": "gw-test", "want_running": false }\n' "$1" > "$work/prefs"; }
fake 0; prefs "$URL"
run reconnect
expect_ok "reconnect succeeds"
for a in up "--login-server=$URL" --hostname=gw-test --accept-dns=false --timeout=20s \
	--accept-routes=1 --advertise-routes=10.9.0.0/24,10.9.1.0/24 --advertise-exit-node=0; do
	grep -qxF -- "$a" "$work/calls" && pass "reconnect passes $a" || fail "reconnect passes $a"
done
grep -qxF -- --reset "$work/calls" && fail "reconnect does not pass --reset" || pass "reconnect does not pass --reset"
grep -q -- '--auth-key' "$work/calls" && fail "reconnect passes no key" || pass "reconnect passes no key"
fake 0; printf '{ "control_url": "" }\n' > "$work/prefs"; run reconnect
expect_code invalid_arg "reconnect, never joined (no control server)"
if called; then fail "reconnect without a control server: the CLI was called"; fi
fake 0; prefs 'https://mesh.example.com/;reboot'; run reconnect
expect_code invalid_arg "reconnect, control server with a semicolon"
if called; then fail "reconnect with a bad control server: the CLI was called"; fi
fake 1 "$fx/daemon-down.txt"; run reconnect; expect_code daemon_down "reconnect, daemon down"
fake 1 "$fx/up-unreachable-refused.txt"; prefs "$URL"; run reconnect; expect_code unreachable "reconnect, control server unreachable"
fake 0; prefs "$URL"; echo 15 > "$work/sleep"; run reconnect; expect_code timeout "reconnect, hard deadline"
fake 0; run reconnect now; expect_code invalid_arg "reconnect with an argument"
ls /tmp/flowmesh-up.* > /dev/null 2>&1 && fail "no flowmesh-up.* left in /tmp" || pass "no flowmesh-up.* left in /tmp"

echo "== status"
printf '%s\n' '{' '  "BackendState": "Running",' '  "PrimaryRoutes": null' '}' > "$work/status.json"
fake 0 "$work/status.json"
run status
[ "$res" = "$(cat "$work/status.json")" ] && pass "status --json passed through unchanged" || fail "status passed through (got: $res)"
grep -qxF -- --json "$work/calls" && pass "status asks for --json" || fail "status asks for --json"
fake 1 "$fx/daemon-down.txt"; run status; expect_code daemon_down "status, daemon down"
# The CLI exits 1 when the node is not running (NeedsLogin, Stopped) but still prints the status.
printf '%s\n' '{' '  "BackendState": "NeedsLogin",' '  "PrimaryRoutes": null' '}' > "$work/status.json"
fake 1 "$work/status.json"
run status
[ "$res" = "$(cat "$work/status.json")" ] && pass "status passed through when the CLI exits 1" ||
	fail "status passed through when the CLI exits 1 (got: $res)"
fake 1 "$work/other.txt"; run status; expect_code unknown "status, non-JSON failure"

echo "== down / logout"
for c in down logout; do
	fake 0; run $c; expect_ok "$c succeeds"
	[ "$(sed -n 1p "$work/calls")" = $c ] && pass "$c runs flowmesh $c" || fail "$c runs flowmesh $c"
	fake 1 "$fx/daemon-down.txt"; run $c; expect_code daemon_down "$c, daemon down"
	fake 0; run $c now; expect_code invalid_arg "$c with an argument"
done

echo "== logs"
fake 0
run logs
expect_ok "logs"
n=$(printf '%s' "$res" | jsonfilter -e '@.lines[*]' | wc -l)
[ "$n" = 200 ] && pass "200 lines" || fail "200 lines (got $n)"
[ "$(printf '%s' "$res" | jsonfilter -e '@.lines[0]')" = "daemon.info flowmeshd: line 51" ] && pass "the last 200" || fail "the last 200"
[ "$(printf '%s' "$res" | jsonfilter -e '@.lines[198]')" = "$(printf '%s' 'line 249 "quoted" back\slash	tab')" ] &&
	pass "quotes, backslash and tab survive" || fail "quotes, backslash and tab survive"

echo "== apply (real init reload and flowmesh-fw, fake CLI)"
uci -q set flowmesh.main.hostname=gw-apply; uci -q set flowmesh.main.exit_node=1; uci commit flowmesh
fake 0
run apply
expect_ok "apply succeeds"
for a in set --accept-dns=false --hostname=gw-apply --advertise-exit-node=1 --accept-routes=1 \
	--advertise-routes=10.9.0.0/24,10.9.1.0/24; do
	grep -qxF -- "$a" "$work/calls" && pass "apply passes $a" || fail "apply passes $a"
done
# A forwarding section flowmesh -> wan exists ("firewall.<id>.src='flowmesh'" splits into
# firewall, <id>, src, flowmesh).
fwd() { uci -q -X show firewall | awk -F"[.=']+" '
	/=forwarding$/ { s[$2] = 1 } $3 == "src" { src[$2] = $4 } $3 == "dest" { dst[$2] = $4 }
	END { for (k in s) if (src[k] == "flowmesh" && dst[k] == "wan") f = 1; exit !f }'; }
fwd && pass "exit node on: forwarding flowmesh -> wan" || fail "exit node on: forwarding flowmesh -> wan"
uci -q set flowmesh.main.exit_node=0; uci commit flowmesh
fake 0; run apply; expect_ok "apply (exit node off)"
fwd && fail "exit node off: no forwarding flowmesh -> wan" || pass "exit node off: no forwarding flowmesh -> wan"
printf '%s\n' 'flowmesh: set: unknown flag -x' > "$work/err.txt"
fake 1 "$work/err.txt"; run apply; expect_code unknown "apply, CLI refuses"
printf '%s' "$(field detail)" | grep -qF 'unknown flag -x' && pass "apply error detail" || fail "apply error detail ($res)"
fake 0; run apply now; expect_code invalid_arg "apply with an argument"

echo "== exitstate"
es=$work/exit-state.json
sed -i "s|^EXIT_STATE=[^ ]*|EXIT_STATE=$es|" "$helper"
[ "$(grep -c "^EXIT_STATE=$es " "$helper")" = 1 ] || fail "could not point the helper at the state file"
rm -f "$es"; run exitstate
[ "$res" = '{"state":"none"}' ] && pass "no state file -> none" || fail "no state file (got: $res)"
printf '%s\n' '{"want":"100.64.0.5","state":"active","since":1790000000}' > "$es"; run exitstate
[ "$(field state)" = active ] && [ "$(field want)" = 100.64.0.5 ] && [ "$(field since)" = 1790000000 ] &&
	[ "$(printf '%s\n' "$res" | wc -l)" = 1 ] && pass "valid state passed through, one line" || fail "valid state (got: $res)"
printf '%s\n' '{"want":"","state":"offline_blocked","since":1}' > "$es"; run exitstate
[ "$(field state)" = offline_blocked ] && pass "offline_blocked passed through" || fail "offline_blocked (got: $res)"
for junk in 'not json {' '' '[1,2]' '"str"' '{"state":'; do
	printf '%s' "$junk" > "$es"; run exitstate
	[ "$res" = '{"state":"none"}' ] && pass "invalid state file ($junk) -> none" || fail "invalid state file '$junk' (got: $res)"
done
fake 0; run exitstate now; expect_code invalid_arg "exitstate with an argument"

echo "== netcheck"
printf '%s\n' '{' '	"UDP": true,' '	"IPv4": true' '}' > "$work/nc.json"
fake 0 "$work/nc.json"; run netcheck
[ "$res" = "$(cat "$work/nc.json")" ] && pass "netcheck JSON passed through unchanged (stderr warning dropped)" || fail "netcheck passthrough (got: $res)"
grep -qxF -- --format=json "$work/calls" && pass "netcheck asks for --format=json" || fail "netcheck asks for --format=json"
fake 1 "$fx/daemon-down.txt"; run netcheck; expect_code daemon_down "netcheck, daemon down"
printf '%s\n' 'flowmesh is not running: connect first' > "$work/nr.txt"
fake 1 "$work/nr.txt"; run netcheck; expect_code unknown "netcheck, not running"
printf '%s' "$(field detail)" | grep -qF 'not running' && pass "netcheck error detail includes stderr" || fail "netcheck detail ($res)"
fake 0 "$work/other.txt"; run netcheck; expect_code unknown "netcheck, output is not JSON"
fake 0 "$work/nc.json"; echo 15 > "$work/sleep"
start=$(date +%s); run netcheck; took=$(( $(date +%s) - start ))
expect_code timeout "netcheck past the hard deadline"
[ "$took" -le 6 ] && pass "netcheck deadline returns in ${took}s" || fail "netcheck deadline took ${took}s"
fake 0; run netcheck now; expect_code invalid_arg "netcheck with an argument"

echo "== ping: arguments (the CLI must not be called)"
bad_ping() {
	fake 0
	run ping "$@"
	expect_code invalid_arg "ping $*"
	if called; then fail "ping $*: the CLI was called"; fi
}
bad_ping 8.8.8.8
bad_ping 192.168.1.1
bad_ping 100.63.255.255
bad_ping 100.128.0.1
bad_ping 100.64.0
bad_ping 100.64.0.256
bad_ping 100.064.0.1
bad_ping 100.64.0.1.1
bad_ping '100.64.0.1;reboot'
bad_ping '100.64.0.1 -c 9'
bad_ping '$(reboot)'
bad_ping '-c'
bad_ping ts1
bad_ping ''
bad_ping '100.64.0.1
reboot'
bad_ping ::1
bad_ping fe80::1
bad_ping fd7a:115c:a1e1::1
bad_ping fd7a:115c:a1e0
bad_ping fd7a:115c:a1e0:::1
bad_ping fd7a:115c:a1e0::1::2
bad_ping fd7a:115c:a1e0:1:2:3:4:5:6
bad_ping fd7a:115c:a1e0:1:2:3:4
bad_ping fd7a:115c:a1e0::12345
bad_ping 'fd7a:115c:a1e0::1;reboot'
bad_ping 'fd7a:115c:a1e0::1%eth0'
bad_ping 100.64.0.1 100.64.0.2
fake 0; run ping; expect_code invalid_arg "ping without an address"
if called; then fail "ping without an address: the CLI was called"; fi

echo "== ping: results"
for ip in 100.64.0.1 100.127.255.254 fd7a:115c:a1e0::1 FD7A:115C:A1E0:AB12::7 fd7a:115c:a1e0:1:2:3:4:5; do
	fake 0 "$fx/ping-direct.txt"; run ping "$ip"; expect_ok "ping $ip accepted"
done
fake 0 "$fx/ping-direct.txt"; run ping 100.64.0.1
[ "$(field path)" = direct ] && [ "$(field ms)" = 2 ] && pass "direct: last answer decides, ms 2" || fail "direct (got: $res)"
[ "$(printf '%s' "$res" | jsonfilter -e '@.lines[*]' | wc -l)" = 3 ] && pass "all lines returned" || fail "lines (got: $res)"
[ "$(printf '%s\n' "$res" | wc -l)" = 1 ] && pass "one JSON line" || fail "one JSON line"
for a in ping -c 3 --until-direct=false --timeout=3s 100.64.0.1; do
	grep -qxF -- "$a" "$work/calls" && pass "ping passes $a" || fail "ping passes $a"
done
fake 0 "$fx/ping-relay.txt"; run ping 100.64.0.9
[ "$(field path)" = relay ] && [ "$(field ms)" = 0 ] && pass "relay, 0s -> ms 0" || fail "relay (got: $res)"
fake 0 "$fx/ping-peer-relay.txt"; run ping 100.64.0.22
[ "$(field path)" = peer-relay ] && [ "$(field ms)" = 1 ] && pass "peer-relay, ms 1" || fail "peer-relay (got: $res)"
printf '%s\n' 'pong from fm-a (100.64.0.9) via DERP(x) in 1.5s' > "$work/p.txt"
fake 0 "$work/p.txt"; run ping 100.64.0.9
[ "$(field path)" = relay ] && [ "$(field ms)" = 1500 ] && pass "1.5s -> ms 1500" || fail "1.5s (got: $res)"
fake 1 "$fx/ping-noreply.txt"; run ping 100.64.0.9
expect_ok "no reply is a result"
[ "$(field path)" = unknown ] && [ "$(printf '%s' "$res" | jsonfilter -t '@.ms')" = null ] && pass "no reply: path unknown, ms null" || fail "no reply (got: $res)"
fake 1 "$fx/daemon-down.txt"; run ping 100.64.0.9; expect_code daemon_down "ping, daemon down"
printf '%s\n' 'no matching peer' > "$work/np.txt"
fake 1 "$work/np.txt"; run ping 100.64.0.9; expect_code unknown "ping, no matching peer"
fake 0; echo 15 > "$work/sleep"; run ping 100.64.0.9; expect_code timeout "ping past the hard deadline"

echo "== bugreport"
printf '%s\n' '{' '  "version": "0.1.7",' '  "note": "quote \" back\\slash"' '}' > "$work/report.src"
fake 0
cp "$work/report.src" "$work/report"
run bugreport
expect_ok "bugreport"
[ "$(printf '%s' "$res" | jsonfilter -e '@.text')" = "$(cat "$work/report.src")" ] && pass "text is the report" || fail "text (got: $res)"
rp=$(cat "$work/reportpath" 2>/dev/null)
[ -n "$rp" ] && [ ! -e "$rp" ] && [ ! -e "$(dirname "$rp")" ] && pass "temporary report and its directory removed" || fail "temporary report removed ($rp)"
ls -d /tmp/flowmesh-bugreport* > /dev/null 2>&1 && fail "no flowmesh-bugreport* left in /tmp" || pass "no flowmesh-bugreport* left in /tmp"
[ "$(sed -n 1,2p "$work/calls" | tr '\n' ' ')" = "bugreport --output " ] && pass "bugreport passes --output" || fail "bugreport args"
fake 1 "$fx/daemon-down.txt"; run bugreport; expect_code daemon_down "bugreport, daemon down"
rp=$(cat "$work/reportpath" 2>/dev/null)
[ -z "$rp" ] || { [ ! -e "$rp" ] && [ ! -e "$(dirname "$rp")" ]; } && pass "failed bugreport leaves nothing" || fail "failed bugreport leaves $rp"
fake 0; echo 15 > "$work/sleep"; run bugreport; expect_code timeout "bugreport past the hard deadline"
rp=$(cat "$work/reportpath" 2>/dev/null)
[ -z "$rp" ] || [ ! -e "$(dirname "$rp")" ] && pass "timed-out bugreport leaves nothing" || fail "timed-out bugreport leaves $rp"
fake 0; run bugreport now; expect_code invalid_arg "bugreport with an argument"
ls /tmp/flowmesh-netcheck.* /tmp/flowmesh-ping.* /tmp/flowmesh-bugreport* > /dev/null 2>&1 && fail "no temp files left in /tmp" || pass "no netcheck/ping/bugreport temp files left in /tmp"

echo "== $fails failure(s)"
exit "$fails"
