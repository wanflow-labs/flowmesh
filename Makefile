# SPDX-License-Identifier: Apache-2.0
REFS ?= ../wanflow-mesh ../control-server

.PHONY: check fmt clippy test deny similarity lab-up lab-smoke lab-capture lab-down

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
		--allowlist docs/similarity-allowlist.txt crates xtask

lab-up:
	lab/scripts/up.sh

lab-smoke:
	lab/scripts/smoke.sh

lab-capture:
	lab/scripts/capture.sh

lab-down:
	docker compose -f lab/compose.yaml down -v
