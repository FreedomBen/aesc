#!/usr/bin/env bash
#
# Check the successor metadata on built packages: the old paladin names must
# appear only version-scoped (< 0.3.0) in Replaces/Conflicts (deb) and
# Obsoletes/Conflicts (rpm), and never in Provides. An unrelated "paladin"
# project exists, and an unversioned claim on the name blocks it from
# installing (see the comments in packaging/nfpm-*.yaml).
#
# Usage: packaging/verify-rename-metadata.sh [distdir]   (default: dist)
#
# Needs rpm to check .rpm files and dpkg-deb to check .deb files; a missing
# tool skips that format with a warning, but at least one format must be
# checked for the script to succeed.

set -euo pipefail

DISTDIR="${1:-dist}"
CUTOFF="0.3.0"

failures=0
checked=0

fail() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}

# Map a package name to the pre-rename name it supersedes: aesc -> paladin,
# aesc-tui -> paladin-tui, aesc-gtk -> paladin-gtk.
old_name_for() {
  case "$1" in
    aesc) echo "paladin" ;;
    aesc-*) echo "paladin-${1#aesc-}" ;;
    *) echo "" ;;
  esac
}

check_rpm() {
  local pkg="$1"
  local name old rel entries
  name="$(rpm -qp --qf '%{NAME}' "${pkg}")"
  old="$(old_name_for "${name}")"
  if [ -z "${old}" ]; then
    fail "${pkg}: unexpected package name '${name}'"
    return
  fi

  if rpm -qp --provides "${pkg}" | grep -q '^paladin'; then
    fail "${pkg}: Provides claims a paladin name"
  fi

  for rel in obsoletes conflicts; do
    entries="$(rpm -qp "--${rel}" "${pkg}" | grep '^paladin' || true)"
    if [ "${entries}" != "${old} < ${CUTOFF}" ]; then
      fail "${pkg}: ${rel} paladin entries are '${entries}'; want exactly '${old} < ${CUTOFF}'"
    fi
  done
  checked=$((checked + 1))
}

check_deb() {
  local pkg="$1"
  local name old field value
  name="$(dpkg-deb -f "${pkg}" Package)"
  old="$(old_name_for "${name}")"
  if [ -z "${old}" ]; then
    fail "${pkg}: unexpected package name '${name}'"
    return
  fi

  if dpkg-deb -f "${pkg}" Provides | grep -q 'paladin'; then
    fail "${pkg}: Provides claims a paladin name"
  fi

  for field in Replaces Conflicts; do
    value="$(dpkg-deb -f "${pkg}" "${field}")"
    if [ "${value}" != "${old} (<< ${CUTOFF})" ]; then
      fail "${pkg}: ${field} is '${value}'; want exactly '${old} (<< ${CUTOFF})'"
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

echo "ok: ${checked} package(s) carry correctly scoped rename metadata"
