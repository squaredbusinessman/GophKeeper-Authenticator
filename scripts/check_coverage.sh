#!/usr/bin/env bash
set -euo pipefail

THRESHOLD="${COVERAGE_THRESHOLD:-70.0}"
RAW_PROFILE="${COVERAGE_RAW_PROFILE:-coverage.raw.out}"
PROFILE="${COVERAGE_PROFILE:-coverage.out}"

go test ./... -coverprofile="${RAW_PROFILE}"

grep -v '/internal/gen/' "${RAW_PROFILE}" > "${PROFILE}"

go tool cover -func="${PROFILE}"

TOTAL="$(go tool cover -func="${PROFILE}" | awk '/^total:/ { sub(/%/, "", $3); print $3 }')"

awk -v total="${TOTAL}" -v threshold="${THRESHOLD}" 'BEGIN {
	if (total + 0 < threshold + 0) {
		printf("coverage %.1f%% is below required %.1f%%\n", total, threshold)
		exit 1
	}
	printf("coverage %.1f%% meets required %.1f%%\n", total, threshold)
}'
