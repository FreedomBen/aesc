#!/usr/bin/env bash
#
# Check that the built packages make no claim on the old paladin names: no
# Provides/Replaces/Conflicts (deb) and no Provides/Obsoletes/Conflicts (rpm)
# may mention paladin. An unrelated "paladin" project exists at versions below
# ours, so any constraint on the name — even version-scoped — blocks it from
# installing (see the comments in packaging/nfpm-*.yaml). Upgrades from the
# old paladin <= 0.2.1 packages remove them by hand instead.
#
# Usage: packaging/verify-rename-metadata.sh [distdir]   (default: dist)
#
# Needs rpm to check .rpm files and dpkg-deb to check .deb files; a missing
# tool skips that format with a warning, but at least one format must be
# checked for the script to succeed.

set -euo pipefail

DISTDIR="${1:-dist}"

failures=0
checked=0

fail() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}

check_rpm() {
  local pkg="$1"
  local rel entries
  for rel in provides obsoletes conflicts; do
    entries="$(rpm -qp "--${rel}" "${pkg}" | grep 'paladin' || true)"
    if [ -n "${entries}" ]; then
      fail "${pkg}: ${rel} mentions a paladin name: '${entries}'"
    fi
  done
  checked=$((checked + 1))
}

check_deb() {
  local pkg="$1"
  local field value
  for field in Provides Replaces Conflicts; do
    value="$(dpkg-deb -f "${pkg}" "${field}")"
    if echo "${value}" | grep -q 'paladin'; then
      fail "${pkg}: ${field} mentions a paladin name: '${value}'"
    fi
  done
  checked=$((checked + 1))
}

shopt -s nullglob
rpms=("${DISTDIR}"/*.rpm)
debs=("${DISTDIR}"/*.deb)

if [ "${#rpms[@]}" -eq 0 ] && [ "${#debs[@]}" -eq 0 ]; then
  echo "error: no .deb or .rpm files in '${DISTDIR}' — build them first (make package)" >&2
  exit 1
fi

if command -v rpm >/dev/null 2>&1; then
  for pkg in "${rpms[@]}"; do check_rpm "${pkg}"; done
elif [ "${#rpms[@]}" -gt 0 ]; then
  echo "warning: rpm not available; skipping ${#rpms[@]} .rpm file(s)" >&2
fi

if command -v dpkg-deb >/dev/null 2>&1; then
  for pkg in "${debs[@]}"; do check_deb "${pkg}"; done
elif [ "${#debs[@]}" -gt 0 ]; then
  echo "warning: dpkg-deb not available; skipping ${#debs[@]} .deb file(s)" >&2
fi

if [ "${checked}" -eq 0 ]; then
  echo "error: no packages could be checked (rpm and dpkg-deb both missing?)" >&2
  exit 1
fi

if [ "${failures}" -gt 0 ]; then
  echo "${failures} problem(s) found across ${checked} package(s)" >&2
  exit 1
fi

echo "ok: ${checked} package(s) make no claim on the old paladin names"
