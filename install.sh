#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON_BIN=${PYTHON:-python3}
VENV_DIR=${VENV_DIR:-"$ROOT_DIR/.venv"}
CONFIG_DIR="$ROOT_DIR/config"
CONFIG_EXAMPLE_DIR="$ROOT_DIR/config.example"
CONFIG_FILE="$CONFIG_DIR/skannr.yaml"
INSTALL_LAN_TOOLS=0

usage() {
  cat <<EOF
Usage: ./install.sh [--with-lan-tools]

Options:
  --with-lan-tools  Install optional LAN enrichment/probing tools with apt:
                    arp-scan avahi-daemon avahi-utils nmap curl iproute2 net-tools
EOF
}

for arg in "$@"; do
  case "$arg" in
    --with-lan-tools)
      INSTALL_LAN_TOOLS=1
      ;;
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
    if [ -d "$CONFIG_DIR" ] && [ -n "$(find "$CONFIG_DIR" -mindepth 1 -print -quit)" ]; then
      echo "config/ is not empty but config/skannr.yaml is missing; refusing to overwrite local files." >&2
      echo "Create config/skannr.yaml manually or move the existing config/ aside and rerun install.sh." >&2
      exit 1
    fi
    echo "Creating local config from config.example"
    mkdir -p "$CONFIG_DIR"
    cp -R "$CONFIG_EXAMPLE_DIR/." "$CONFIG_DIR/"
  else
    echo "No config/skannr.yaml or config.example/ found; Skannr will create defaults on first run."
  fi
fi

if [ ! -d "$VENV_DIR" ]; then
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

"$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel
"$VENV_DIR/bin/python" -m pip install -r "$REQUIREMENTS"

if [ "$INSTALL_LAN_TOOLS" -eq 1 ]; then
  if command -v apt-get >/dev/null 2>&1; then
    SUDO=
    if [ "$(id -u)" -ne 0 ]; then
      SUDO=sudo
    fi
    echo
    echo "Installing optional LAN tools with apt"
    $SUDO apt-get update
    $SUDO apt-get install -y arp-scan avahi-daemon avahi-utils nmap curl iproute2 net-tools
  else
    echo
    echo "Cannot install optional LAN tools automatically: apt-get not found." >&2
    echo "Install these packages manually if needed:" >&2
    echo "  arp-scan avahi-daemon avahi-utils nmap curl iproute2 net-tools" >&2
  fi
fi

echo
echo "Python dependencies installed in $VENV_DIR"
echo "Install system collector tools separately if needed:"
echo "  sudo apt install rtl-sdr librtlsdr-dev aircrack-ng bluetooth bluez"
echo "  sudo apt install arp-scan avahi-daemon avahi-utils nmap curl iproute2 net-tools"
echo "Or rerun install.sh with --with-lan-tools to install the optional LAN tool set."
echo
echo "Run Skannr with:"
echo "  sudo env PYTHONPATH=$ROOT_DIR/src $VENV_DIR/bin/python -m skannr.main"
