# Serve (`flowmesh serve`)

Sources: `OBS-20261012-serve-official` (`lab/scripts/serve_observe.sh`, official client v1.94.2 serving, an untagged official client requesting). `SERVER=flowmesh lab/scripts/serve_observe.sh` runs the same cases with flowmeshd serving; `lab/scripts/serve_compare.py` compares the two runs file by file: of 54 recorded outputs, 47 agree after normalizing names, addresses, dates, ephemeral ports, header-name case and the order of unordered things; the other 7 are the intended differences below or not comparable (names, logs, preference formats).

Serve shares something on this machine with the mesh: a local HTTP server (reverse proxy), text, a file or directory, or a raw TCP port. Peers reach it by this node's name.

## 1. Configuration

The official `ServeConfig` shape, which `serve status --json` prints:

```json
{
  "TCP": { "80": { "HTTP": true }, "2225": { "TCPForward": "localhost:7000", "ProxyProtocol": 1 } },
  "Web": { "<node>.<domain>:80": { "Handlers": { "/": { "Proxy": "http://127.0.0.1:3000" }, "/text": { "Text": "hi" } } } }
}
```

- `serve --bg …` changes the stored (background) configuration, kept with the preferences in `prefs.json` and served across restarts. Without `--bg` the command serves in the foreground until interrupted: the CLI holds a lease it renews every 5 s and drops on Ctrl+C/SIGTERM; a CLI that dies is dropped after 15 s. As observed of the official CLI, `serve status` shows the background configuration only.
- Targets (`--http`): a port (`3000` → `http://127.0.0.1:3000`), `host:port`, a URL (`http://`, `https://`, `https+insecure://`, with an optional base path), `unix:/path`, `text:<text>`, or a file/directory (absolute or `./` path, stored canonical). Only servers on this machine (`localhost`, `127.0.0.1`, `[::1]`) — serving another host would make the node an open proxy into its LAN. `--tcp`: a port, `host:port` or `tcp://host:port`. `--set-path` mounts under a path; `--proxy-protocol=1|2` sends a PROXY header to the TCP backend. `off` with the same flags removes the mount (the port when its last mount goes).
- Messages as official where observed: `cannot serve multiple types for a single mount point`, `port number 70000 is too high for https flag`, `failed apply web serve: must be a URL starting with one of the supported schemes: [http https https+insecure unix]`; errors print `error: …` and `try \`flowmesh serve --help\` for usage info`, exit 1. The listing texts (`Available within your tailnet:`, `serve status`) are the official layout. The official listing order of ports is Go's random map order; flowmesh sorts by port.

## 2. HTTP

- Requests are matched by `Host`: this node's full DNS name or its short name, any case; an address gets `404 page not found` (Go's `http.NotFound`, as official). Then the longest mount that is the path or a parent of it (`/apix` is not under `/api`); the backend sees the path below the mount (`/api/v1/items` → `/v1/items`, `/api` → `/`), appended to the target's base path; the query is kept.
- Proxy: the client's headers go to the backend minus per-hop ones and minus any `Tailscale-*`, `X-Forwarded-For`, `X-Forwarded-Host` the client sent; then `X-Forwarded-For: <peer address>`, `X-Forwarded-Host: <Host as sent>`, and for peers that act for a user (untagged nodes) `Tailscale-User-Login`, `Tailscale-User-Name`, `Tailscale-User-Profile-Pic` (non-ASCII values RFC 2047-encoded). `Host` is passed as sent (`localhost` for a Unix socket backend). Header names go out in the usual capitalization; the client always gets HTTP/1.1. Protocol upgrades (WebSockets) are passed through. A backend that cannot be reached gives `502 Bad Gateway` with an empty body.
- Text: `200`, `text/plain; charset=utf-8`. Files: type from the extension (else text if it looks like text), `Last-Modified`, `Accept-Ranges: bytes` with single ranges; a directory gives its `index.html`, else the official plain listing; a directory without its trailing slash is redirected (`301`, `Location: <name>/`). Paths never leave the served directory (`..` and encoded `..` stop at its root; an encoded `/` is refused).

## 3. TCP

Raw forwarding to the target. With `--proxy-protocol=1` the backend first gets `PROXY TCP4 <peer> <this node> <peer port> <backend port>` — the destination port is the backend's, as observed; version 2 is the binary form.

## 4. Reaching the listeners

As for the SSH server (ssh.md §3): each configured port has a listener on the mesh addresses on a port of its own; the dataplane delivers the configured port to it and sends replies from the configured port; the listener port itself cannot be reached from the mesh. The packet filter sees the configured port. A connection is served only if the dataplane admitted its SYN (it came over WireGuard) and its source is a peer; local processes connecting to the listener are refused and logged (`serve: refused connection … did not come through the mesh`), so nobody on the host can borrow a peer's identity. A port used by the SSH server cannot be served. The daemon checks every configuration it gets over the local API against the CLI's rules (targets on this machine only, well-formed handlers), since it can arrive without the CLI; and because flowmeshd runs as root, only root may add or change file, directory and Unix socket handlers — the operator (`--operator`) may keep existing ones and add proxies, text and TCP forwards, but cannot make the daemon read what the operator could not. Listeners restart only when what a port does changes; HTTP handler changes apply to the running listener.

## 5. Intended differences

| Case | Official | flowmesh |
|---|---|---|
| HTTPS (`serve <target>` without a mode, `--https`, `--tls-terminated-tcp`) | needs certificates from the control server; with headscale `error enabling https feature: … 404` (or, for TLS-terminated TCP, a configuration that cannot work) | refused with the reason (deviation #16) |
| Services (`--service`, `advertise`, `drain`, `clear`, `get-config`, `set-config`, `--tun`), `--accept-app-caps` | stored, waiting for an approval headscale cannot give | refused with the reason (deviation #17) |
| `Tailscale-Headers-Info: https://tailscale.com/s/serve-headers`, `Accept-Encoding: gzip` added by Go's HTTP client | sent to the backend | not sent (deviation #18) |
