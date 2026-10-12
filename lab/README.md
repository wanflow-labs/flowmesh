# Interoperability lab

A control server, a DERP server with a self-signed certificate, and two official clients (as the reference) run in local Docker, for black-box observation and differential testing. Nothing connects to any production host.

The server image and source location are set in `lab/.env` (not committed); on first use, copy `lab/.env.example` and fill it in.

| Service | Address |
|---|---|
| headscale | `http://headscale.lab` (172.29.0.10:80) |
| DERP | `derp.lab:443` (172.29.0.11), STUN 3478 |
| ts1 / ts2 | 172.29.0.21 / 172.29.0.22 |

    make lab-up      # start and join ts1 and ts2 (the first run builds a headscale image for the host architecture)
    make lab-smoke   # smoke test: direct ping, home relay, fallback to DERP after blocking the direct path
    make lab-capture # collect observation captures into fixtures/observed/
    make lab-down    # tear down (including volumes)

`lab/.authkey` holds a reusable pre-auth key (with `tag:relay-enabled`, valid for 24 hours); it is listed in .gitignore.

## Differences from production and why

| Difference | Reason |
|---|---|
| headscale listens on port 80 (production uses `http://ip:<high port>`) | The official client only allows a plaintext control connection on port 80 and forces TLS on every other port (see `fixtures/observed/20261010-official-http-control/`). The production client is patched to remove this restriction; flowmesh implements the same behavior as deviation #2. |
| The control server is built from source for the host architecture (`scripts/build-images.sh`; the source location is in `lab/.env`) | When an amd64 image runs under emulation on an arm64 host, the Noise handshake fails with `chacha20poly1305: message authentication failed`. |
| DERP uses a self-signed certificate + `insecurefortests` | The lab has no public domain name. |

## Known issues

After the headscale container restarts, the official clients ts1 and ts2 cannot reconnect on their own: after one failed Noise connection they switch to a "force 443 TLS" mode. Workaround:

    docker compose -f lab/compose.yaml restart ts1 ts2

## Running flowmesh against the lab

headscale's port 80 is published on the host as `127.0.0.1:18080`, so flowmesh components can run directly on the development machine:

    cargo run -q -p flowmesh-probe -- --login-server http://127.0.0.1:18080 \
      --authkey-file lab/.authkey --state "$TMPDIR/probe-state.json" --hostname fm1 \
      --dump "$TMPDIR/probe-dump" --duration 30
