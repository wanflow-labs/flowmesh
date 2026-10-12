# Contributing to flowmesh

Thank you for helping. A few rules keep the project what it promises to be.

## Sign-off (DCO)

Every commit needs a `Signed-off-by:` line, which certifies the [Developer Certificate of Origin](https://developercertificate.org/): you wrote the change or have the right to submit it under the project's license (Apache-2.0).

    git commit -s

CI rejects pull requests with unsigned commits (`scripts/check-dco.sh`).

## Independent implementation

flowmesh is compatible with Tailscale but contains none of its code, and must stay that way.

- Do not copy code from Tailscale, headscale or other implementations of the protocol, and do not translate it line by line from Go.
- Protocol facts come from observing the official client (lab captures, command output) and are written up in `docs/protocol` with the observation that supports them. Recorded evidence goes under `fixtures/observed/<date>-<topic>/`.
- CI runs a similarity scan against the Tailscale and headscale sources. Shared wire-format constants and similar unavoidable matches are listed, with reasons, in `docs/similarity-allowlist.txt`.

## Behavior

Everything that can be observed from outside matches the official client: CLI flags, output, exit codes, wire behavior. A change that deliberately differs needs a row in `docs/deviations.md` with its reason and evidence. Any other difference is a bug.

## Code

- `make check` must pass: `cargo fmt`, `cargo clippy -D warnings`, `cargo test`, `cargo deny`, the similarity scan.
- No `unsafe` (the workspace forbids it), no `unwrap`/`expect` outside tests.
- Decisions that can be pure functions are pure functions with unit tests; Linux glue (`main.rs`, `engine/src/linux.rs`) stays thin. Mutation testing (`cargo mutants`) should leave no surviving mutant that is not explained in `docs/mutants-allowlist.md`.
- Comments and documentation are in English.

## Testing against real clients

`lab/` runs official clients, a control server and relays in Docker so behavior can be compared side by side. See `lab/README.md`. The lab needs `lab/.env` (copy `lab/.env.example`).

## Reporting security issues

Please do not open a public issue for a vulnerability. Report it privately through GitHub's security advisory form for this repository.
