# SPDX-License-Identifier: Apache-2.0
REFS ?= ../wanflow-mesh ../control-server

.PHONY: check fmt clippy test deny similarity lab-up lab-smoke lab-capture lab-down fuzz release reproduce

check: fmt clippy test deny similarity

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace

deny:
	cargo deny check

similarity:
	cargo xtask similarity $(foreach r,$(REFS),--reference $(r)) \
		--allowlist docs/similarity-allowlist.txt crates xtask fuzz

lab-up:
	lab/scripts/up.sh

lab-smoke:
	lab/scripts/smoke.sh

lab-capture:
	lab/scripts/capture.sh

lab-down:
	docker compose -f lab/compose.yaml down -v

# Fuzz every untrusted-input parser (nightly + cargo-fuzz; FUZZ_SECONDS per target).
FUZZ_SECONDS ?= 600
fuzz:
	python3 fuzz/seed.py
	fuzz/run_all.sh $(FUZZ_SECONDS)

# Reproducible static release build in the pinned container (design §6.2). Always linux/amd64: the
# build host's architecture changes the output (docs/reproducible-builds.md), so on an arm64 machine
# this runs emulated (slow, same bytes).
release:
	docker build -q --platform linux/amd64 -f build/Dockerfile -t flowmesh-build:1 build
	docker run --rm --platform linux/amd64 -v "$(CURDIR)":/flowmesh -e SOURCE_DATE_EPOCH=$$(git log -1 --format=%ct) flowmesh-build:1 build/release.sh dist

# Rebuild and compare with published checksums: make reproduce SUMS=path/to/SHA256SUMS
reproduce: release
	cd dist && sha256sum -c "$(abspath $(SUMS))"
