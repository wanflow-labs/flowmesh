# Recorded `flowmesh` output

Each file is the combined stdout and stderr of a real `flowmesh` 0.1.5 run on OpenWrt 25.12.6 (QEMU),
against an upstream headscale v0.26.1 control server (the lab from `packaging/openwrt/test/lab.sh`):

| File | Command | Situation |
|---|---|---|
| `up-key-used.txt` | `up --reset ... --auth-key=file:... --timeout=20s` | one-time key already used by another registration |
| `up-key-expired.txt` | same | key created with a 2 s expiry, used after 5 s |
| `up-key-wrong.txt` | same | a key the server never issued |
| `up-unreachable-refused.txt` | same | nothing listening on the control server's port |
| `up-unreachable-dns.txt` | same | control server name does not resolve (`*.invalid`) |
| `up-timeout-silent.txt` | same | a TCP listener that accepts and never answers |
| `daemon-down.txt` | `status --json`, `down`, `up` | flowmeshd not running (all three print this) |

An address with no host behind it (connect hangs) prints exactly what `up-timeout-silent.txt` holds, so
it is reported as `timeout`, not `unreachable`.

Not recorded: a refusal because the mesh has no free node slots. headscale has no such limit, so its
text could not be observed; `flowmesh-luci` reports `site_limit` for any refusal whose reason mentions
a limit or quota, and the test feeds it a made-up line of that form.

## `ping-*.txt`

Lines in the exact format `flowmesh ping` prints (crates/flowmesh-cli/src/ping.rs: the pong line is
`pong from <name> (<ip>) via <endpoint | DERP(<code>) | peer-relay(<addr>)> in <latency>`, a timeout is
`ping "<ip>" timed out`, the verdict `no reply` goes to stderr). The sample lines are the ones that
file's own unit tests assert; they were not captured from a running mesh.
