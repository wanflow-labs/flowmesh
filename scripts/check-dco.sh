#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Checks that every commit in the range carries Signed-off-by: (DCO). Usage: scripts/check-dco.sh origin/main..HEAD
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
