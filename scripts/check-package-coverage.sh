#!/usr/bin/env bash
# -coverpkg=./... credits a package for lines another package's tests execute;
# the default per-package figure would report those as 0%. Floor is 75% per
# package, never a module average. COVERAGE_SKIP_REGEX names an exclusion.
set -euo pipefail

MIN="${COVERAGE_MIN:-75}"
SKIP="${COVERAGE_SKIP_REGEX:-}"

if [[ ! "$MIN" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
  printf 'coverage gate: COVERAGE_MIN %q is not a number\n' "$MIN" >&2
  exit 2
fi

go test -race -coverpkg=./... -coverprofile=coverage.out ./...

# Each package profile repeats every coverpkg block; counting them twice
# halves a package the other binary did not execute.
awk -v min="$MIN" -v skip="$SKIP" '
NR == 1 { next }
{
	loc = $1
	stmt[loc] = $2 + 0
	hits = $3 + 0
	if (hits > hit[loc]) hit[loc] = hits
}
END {
	for (loc in stmt) {
		file = loc
		sub(/:[0-9]+\.[0-9]+,[0-9]+\.[0-9]+$/, "", file)
		pkg = file
		sub(/\/[^\/]+$/, "", pkg)
		if (skip != "" && pkg ~ skip) {
			if (!(pkg in seen_skip)) {
				printf "coverage gate: skipping %s\n", pkg > "/dev/stderr"
				seen_skip[pkg] = 1
			}
			continue
		}
		total[pkg] += stmt[loc]
		if (hit[loc] > 0) covered[pkg] += stmt[loc]
	}
	n = 0
	fail = 0
	for (p in total) {
		n++
		if (total[p] == 0) pct = 100
		else pct = 100 * covered[p] / total[p]
		printf "%s %.1f%%\n", p, pct
		if (pct + 0 < min + 0) {
			printf "coverage gate: %s %.1f%% < %s%%\n", p, pct, min > "/dev/stderr"
			fail = 1
		}
	}
	if (n == 0) {
		printf "coverage gate: no packages checked\n" > "/dev/stderr"
		exit 1
	}
	exit fail
}
' coverage.out
