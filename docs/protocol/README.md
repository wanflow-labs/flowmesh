# flowmesh protocol specification

This directory describes, in our own words, the Tailscale-compatible protocols that flowmesh implements.

## Rules

1. Every protocol fact must cite a source; the IDs are listed in [sources.md](sources.md):
   - `PUB-<n>`: public documents, including specifications, papers, the official blog and knowledge base.
   - `OBS-<directory>/<file>`: black-box observation captures under `fixtures/observed/`.
2. Neither this specification nor the flowmesh code is written with reference to the source code of Tailscale, headscale, or projects derived from them.
3. Interoperability constants such as magic numbers, frame type numbers and capability versions may be used directly, but their source must be cited.

## Chapters

| File | Content |
|---|---|
| control.md | Control channel handshake, registration, netmap |
| filter.md | Filter rule format and matching semantics |
| derp.md | DERP frame format |
| disco.md | disco and STUN |
| dns.md | MagicDNS |
| routes.md | Subnet routes and host routing |
| peer-relay.md | Peer relay |
| cli.md | CLI and status semantics |
| ssh.md | SSH server and client |
| serve.md | `flowmesh serve` |
