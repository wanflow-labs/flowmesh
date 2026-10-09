#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# 检查区间内每个 commit 都带有 Signed-off-by:（DCO）。用法：scripts/check-dco.sh origin/main..HEAD
set -euo pipefail
range="${1:?usage: check-dco.sh <rev-range>}"
bad=0
for c in $(git rev-list --no-merges "$range"); do
  if ! git log -1 --format=%B "$c" | grep -q '^Signed-off-by: '; then
    echo "missing Signed-off-by: $(git log -1 --format='%h %s' "$c")"
    bad=1
  fi
done
exit "$bad"
