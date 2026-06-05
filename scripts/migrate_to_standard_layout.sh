#!/usr/bin/env bash
#
# One-shot migration from the original flat Skannr tree to the standard layout:
#
#   src/skannr/              Python package and shipped UI assets
#   src/skannr/data/         bundled lookup data used by the code
#   config/                  operator-editable configuration
#   runtime/                 generated logs, materialized views, and state
#   requirements/            install dependency manifests
#
# This script intentionally does not create compatibility symlinks. It refuses
# to overwrite existing destinations so layout conflicts are visible.

set -euo pipefail

DRY_RUN=0
CODE_ALREADY_MIGRATED=0

usage() {
  cat <<'EOF'
Usage: scripts/migrate_to_standard_layout.sh [--dry-run]

Moves the current Skannr checkout into the standard source/config/runtime
layout. Run from anywhere inside the checkout.

Options:
  --dry-run   Print the moves without changing files.
  -h, --help  Show this help.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

log() {
  echo "$*"
}

run() {
  if [ "${DRY_RUN}" -eq 1 ]; then
    printf '+'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

ensure_original_tree() {
  [ -f "VERSION" ] || die "VERSION not found; run from a Skannr checkout"

  if [ -d "src/skannr" ] && [ ! -f "main.py" ]; then
    CODE_ALREADY_MIGRATED=1
    log "src/skannr already exists and no flat main.py remains; code layout looks migrated."
    return 0
  fi

  [ -f "main.py" ] || die "main.py not found; this does not look like the original flat Skannr layout"
  [ -d "collectors" ] || die "collectors/ not found"
  [ -d "static" ] || die "static/ not found"
}

ensure_parent_dir() {
  local path="$1"
  local parent
  parent="$(dirname "${path}")"
  [ -d "${parent}" ] || run mkdir -p "${parent}"
}

move_if_present() {
  local src="$1"
  local dst="$2"

  if [ ! -e "${src}" ]; then
    if [ -e "${dst}" ]; then
      log "already moved: ${dst}"
      return 0
    fi
    log "skipping missing source: ${src}"
    return 0
  fi

  [ ! -e "${dst}" ] || die "destination already exists: ${dst}"
  ensure_parent_dir "${dst}"
  log "move ${src} -> ${dst}"
  run mv "${src}" "${dst}"
}

remove_dir_if_empty() {
  local dir="$1"
  [ -d "${dir}" ] || return 0
  if [ -z "$(find "${dir}" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
    log "remove empty directory ${dir}"
    run rmdir "${dir}"
  fi
}

remove_pycache_dirs() {
  local dir
  for dir in \
    "__pycache__" \
    "collectors/__pycache__" \
    "persistence/__pycache__" \
    "src/skannr/__pycache__" \
    "src/skannr/collectors/__pycache__" \
    "src/skannr/persistence/__pycache__"
  do
    if [ -d "${dir}" ]; then
      log "remove generated cache ${dir}"
      run rm -rf "${dir}"
    fi
  done
}

create_directories() {
  run mkdir -p \
    "src/skannr" \
    "src/skannr/collectors" \
    "src/skannr/data/collectors" \
    "config/collectors" \
    "requirements" \
    "runtime"
}

create_package_marker() {
  [ "${CODE_ALREADY_MIGRATED}" -eq 0 ] || return 0
  if [ -e "src/skannr/__init__.py" ]; then
    return 0
  fi
  log "create src/skannr/__init__.py"
  if [ "${DRY_RUN}" -eq 1 ]; then
    echo "+ : > src/skannr/__init__.py"
  else
    : > "src/skannr/__init__.py"
  fi
}

move_top_level_python() {
  [ "${CODE_ALREADY_MIGRATED}" -eq 0 ] || return 0
  local file
  for file in \
    "auth.py" \
    "bus.py" \
    "config.py" \
    "device_history.py" \
    "findings.py" \
    "history_analysis.py" \
    "log_utils.py" \
    "main.py" \
    "oui_lookup.py" \
    "reports.py"
  do
    move_if_present "${file}" "src/skannr/${file}"
  done
}

move_collectors() {
  [ "${CODE_ALREADY_MIGRATED}" -eq 0 ] || return 0
  local file

  shopt -s nullglob
  for file in collectors/*.py; do
    move_if_present "${file}" "src/skannr/collectors/$(basename "${file}")"
  done

  for file in collectors/*.yaml; do
    move_if_present "${file}" "config/collectors/$(basename "${file}")"
  done

  for file in collectors/*.txt; do
    move_if_present "${file}" "src/skannr/data/collectors/$(basename "${file}")"
  done
  shopt -u nullglob

  remove_dir_if_empty "collectors"
}

move_persistence() {
  [ "${CODE_ALREADY_MIGRATED}" -eq 0 ] || return 0
  if [ -d "persistence" ]; then
    [ ! -e "src/skannr/persistence" ] || die "destination already exists: src/skannr/persistence"
    log "move persistence -> src/skannr/persistence"
    run mv "persistence" "src/skannr/persistence"
  elif [ -d "src/skannr/persistence" ]; then
    log "already moved: src/skannr/persistence"
  else
    log "skipping missing source: persistence"
  fi
}

move_static_assets() {
  [ "${CODE_ALREADY_MIGRATED}" -eq 0 ] || return 0
  move_if_present "static" "src/skannr/static"
}

move_config() {
  move_if_present "skannr.yaml" "config/skannr.yaml"
}

normalize_migrated_config() {
  local path="config/skannr.yaml"

  [ -f "${path}" ] || return 0
  if grep -Eq '^[[:space:]]*log_dir:[[:space:]]*['"'"'"]?logs/?['"'"'"]?[[:space:]]*$' "${path}"; then
    log "update legacy log_dir in ${path}: logs -> runtime/logs"
    run sed -i -E \
      -e 's#^([[:space:]]*log_dir:[[:space:]]*)logs/?([[:space:]]*)$#\1runtime/logs\2#' \
      -e 's#^([[:space:]]*log_dir:[[:space:]]*)"logs/?"([[:space:]]*)$#\1runtime/logs\2#' \
      -e "s#^([[:space:]]*log_dir:[[:space:]]*)'logs/?'([[:space:]]*)\$#\1runtime/logs\2#" \
      "${path}"
  fi
}

move_requirements() {
  local file

  shopt -s nullglob
  for file in requirements*.txt; do
    move_if_present "${file}" "requirements/$(basename "${file}")"
  done
  shopt -u nullglob
}

move_runtime_state() {
  if [ -d "logs" ]; then
    move_if_present "logs" "runtime/logs"
  fi
}

print_summary() {
  cat <<'EOF'

Migration layout:
  src/skannr/                  Python package
  src/skannr/collectors/       Collector Python code
  src/skannr/data/collectors/  Bundled lookup data
  src/skannr/static/           Browser UI assets
  config/skannr.yaml           Main editable config
  config/collectors/*.yaml     Collector editable config
  requirements/*.txt           Install dependency manifests
  runtime/                     Generated logs/materialized state

Run Skannr after migration with:
  PYTHONPATH=<skannr-dir>/src <skannr-dir>/.venv/bin/python -m skannr.main

For sudo runs, preserve PYTHONPATH explicitly:
  sudo env PYTHONPATH=<skannr-dir>/src <skannr-dir>/.venv/bin/python -m skannr.main
EOF
}

ensure_original_tree
remove_pycache_dirs
create_directories
create_package_marker
move_top_level_python
move_collectors
move_persistence
move_static_assets
move_config
normalize_migrated_config
move_requirements
move_runtime_state
print_summary
