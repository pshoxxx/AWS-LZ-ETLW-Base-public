#!/usr/bin/env bash
# tf-apply-filter.sh <workspace> <suppressed-pattern> [<suppressed-pattern> ...]
#
# Runs `terraform apply -auto-approve -no-color`, tees output to a log file,
# then filters out known-benign errors. Exits non-zero only on unexpected errors.
#
# Usage:
#   scripts/tf-apply-filter.sh networking \
#     "AlreadyAssociated" \
#     "AWSServiceRoleForConfig has been taken" \
#     "InvalidTokenException"
set -euo pipefail

WORKSPACE="${1:?workspace name required}"
shift
SUPPRESS=("$@")

LOG="/tmp/tf_${WORKSPACE}_apply.log"

set +e
terraform apply -auto-approve -no-color 2>&1 | tee "$LOG"
APPLY_EXIT="${PIPESTATUS[0]}"
set -e

if [[ $APPLY_EXIT -ne 0 ]]; then
  ALL_ERRORS=$(grep "Error:" "$LOG" || true)
  UNEXPECTED="$ALL_ERRORS"
  for pattern in "${SUPPRESS[@]}"; do
    UNEXPECTED=$(echo "$UNEXPECTED" | grep -v "$pattern" || true)
  done

  if [[ -n "$UNEXPECTED" ]]; then
    echo "::error::Unexpected error(s) in ${WORKSPACE} apply:"
    echo "$UNEXPECTED"
    exit 1
  fi

  echo "::warning::${WORKSPACE} apply had suppressed errors -- rerun if needed."
fi
