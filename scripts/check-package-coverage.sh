#!/usr/bin/env bash
# -coverpkg=./... credits a package for lines another package's tests execute;
# the default per-package figure would report those as 0%. Floor is 75% per
# package, never a module average. COVERAGE_SKIP_REGEX names an exclusion.
set -euo pipefail

MIN="${COVERAGE_MIN:-75}"
SKIP="${COVERAGE_SKIP_REGEX:-}"

go test -race -coverpkg=./... -coverprofile=coverage.out ./...

awk -v min="$MIN" -v skip="$SKIP" '
NR == 1 { next }
{
	file = $1
	sub(/:[0-9]+\.[0-9]+,[0-9]+\.[0-9]+$/, "", file)
	pkg = file
	sub(/\/[^\/]+$/, "", pkg)
	if (skip != "" && pkg ~ skip) next
	stmts = $2 + 0
	hits = $3 + 0
	total[pkg] += stmts
	if (hits > 0) covered[pkg] += stmts
}
END {
	fail = 0
	for (p in total) {
		if (total[p] == 0) pct = 100
		else pct = 100 * covered[p] / total[p]
		printf "%s %.1f%%\n", p, pct
		if (pct + 0 < min + 0) {
			printf "coverage gate: %s %.1f%% < %s%%\n", p, pct, min > "/dev/stderr"
			fail = 1
		}
	}
	exit fail
}
' coverage.out
