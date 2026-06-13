#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON_BIN=${PYTHON:-python3}
VENV_DIR=${VENV_DIR:-"$ROOT_DIR/.venv"}
CONFIG_DIR="$ROOT_DIR/config"
CONFIG_EXAMPLE_DIR="$ROOT_DIR/config.example"
CONFIG_FILE="$CONFIG_DIR/skannr.yaml"
PRECHECK_FILE="$CONFIG_DIR/precheck.yaml"
FRESH_CONFIG=0

usage() {
  cat <<EOF
Usage: ./install.sh

Installs Skannr Python dependencies and creates local config/ from
config.example/ when config/skannr.yaml does not exist. On fresh config it
applies config/precheck.yaml, installs Python dependencies, runs
scripts/skannr_postcheck.py to write config/postcheck.yaml, then applies the
final postcheck enabled flags. Existing config/skannr.yaml is not rewritten.
Optional system tools are reported by scripts/skannr_precheck.py and
scripts/skannr_postcheck.py; install them with your OS package manager.
EOF
}

for arg in "$@"; do
  case "$arg" in
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      usage >&2
      exit 1
      ;;
  esac
done

VERSION=$("$PYTHON_BIN" -c 'import sys; print("{}.{}".format(sys.version_info[0], sys.version_info[1]))')
MAJOR=$("$PYTHON_BIN" -c 'import sys; print(sys.version_info[0])')
MINOR=$("$PYTHON_BIN" -c 'import sys; print(sys.version_info[1])')

if [ "$MAJOR" -lt 3 ]; then
  echo "Python 3.6 or newer is required; found $VERSION" >&2
  exit 1
fi

if [ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 6 ]; then
  echo "Python 3.6 or newer is required; found $VERSION" >&2
  exit 1
fi

if [ "$MAJOR" -eq 3 ] && [ "$MINOR" -eq 6 ]; then
  REQUIREMENTS="$ROOT_DIR/requirements/requirements-py36.txt"
elif [ "$MAJOR" -eq 3 ] && [ "$MINOR" -eq 7 ]; then
  REQUIREMENTS="$ROOT_DIR/requirements/requirements-py37.txt"
else
  REQUIREMENTS="$ROOT_DIR/requirements/requirements-py38plus.txt"
fi

echo "Using Python $VERSION: $PYTHON_BIN"
echo "Using requirements: $REQUIREMENTS"

if [ ! -f "$CONFIG_FILE" ]; then
  if [ -d "$CONFIG_EXAMPLE_DIR" ]; then
    if [ -d "$CONFIG_DIR" ]; then
      EXTRA_CONFIG_FILES=$(find "$CONFIG_DIR" -mindepth 1 ! -name precheck.yaml -print -quit)
      if [ -n "$EXTRA_CONFIG_FILES" ]; then
        echo "config/ is not empty but config/skannr.yaml is missing; refusing to overwrite local files." >&2
        echo "Create config/skannr.yaml manually or move the existing config/ aside and rerun install.sh." >&2
        exit 1
      fi
    fi
    echo "Creating local config from config.example"
    mkdir -p "$CONFIG_DIR"
    cp -R "$CONFIG_EXAMPLE_DIR/." "$CONFIG_DIR/"
    FRESH_CONFIG=1
  else
    echo "No config/skannr.yaml or config.example/ found; Skannr will create defaults on first run."
  fi
fi

if [ "$FRESH_CONFIG" -eq 1 ]; then
  if [ ! -f "$PRECHECK_FILE" ]; then
    echo
    echo "Running install-time collector precheck"
    "$PYTHON_BIN" "$ROOT_DIR/scripts/skannr_precheck.py" --output "$PRECHECK_FILE"
  fi
  echo
  echo "Applying collector enabled flags from $PRECHECK_FILE"
  "$PYTHON_BIN" "$ROOT_DIR/scripts/skannr_precheck.py" --apply --precheck "$PRECHECK_FILE" --collector-dir "$CONFIG_DIR/collectors"
fi

if [ ! -d "$VENV_DIR" ]; then
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

"$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel
"$VENV_DIR/bin/python" -m pip install -r "$REQUIREMENTS"

echo
POSTCHECK_FILE="$CONFIG_DIR/postcheck.yaml"
PYTHONPATH="$ROOT_DIR/src" "$VENV_DIR/bin/python" "$ROOT_DIR/scripts/skannr_postcheck.py" --output "$POSTCHECK_FILE"
if [ "$FRESH_CONFIG" -eq 1 ]; then
  echo
  echo "Applying final collector enabled flags from $POSTCHECK_FILE"
  "$VENV_DIR/bin/python" "$ROOT_DIR/scripts/skannr_precheck.py" --apply --precheck "$POSTCHECK_FILE" --collector-dir "$CONFIG_DIR/collectors"
fi

echo
echo "Python dependencies installed in $VENV_DIR"
echo "Install optional system collector tools separately if needed."
echo "Run scripts/skannr_precheck.py again after installing tools, then rerun install.sh on a fresh config or edit config/collectors/*.yaml manually."
echo
echo "Run Skannr with:"
echo "  sudo env PYTHONPATH=$ROOT_DIR/src $VENV_DIR/bin/python -m skannr.main"
