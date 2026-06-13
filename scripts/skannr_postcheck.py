#!/usr/bin/env python3
"""Post-install Skannr collector check.

Run this with the installed Skannr virtualenv Python. It reuses the precheck
inventory, verifies Python modules such as bleak/scapy, repeats selected
hardware probes, and writes config/postcheck.yaml by default. install.sh
applies this final postcheck result only when it just created fresh config.
Pass --no-write for a report-only run.
"""

from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parents[1]
PRECHECK = ROOT / "scripts" / "skannr_precheck.py"
DEFAULT_OUTPUT = ROOT / "config" / "postcheck.yaml"


def print_help():
    print(__doc__.strip())
    print()
    print("Options:")
    print("  --output PATH       postcheck YAML output path")
    print("  --no-write          print only; do not write postcheck YAML")
    print("  --apply             apply an existing check file to config/collectors/*.yaml")
    print("  --precheck PATH     check YAML path to apply")
    print("  --collector-dir DIR collector config directory to update")


def main():
    args = sys.argv[1:]
    if any(arg in {"-h", "--help"} for arg in args):
        print_help()
        return
    has_output_control = any(arg == "--no-write" or arg == "--apply" or arg == "--output" or arg.startswith("--output=") for arg in args)
    forwarded = [str(PRECHECK), "--check-python"]
    if not has_output_control:
        forwarded.extend(["--output", str(DEFAULT_OUTPUT)])
    forwarded.extend(args)
    sys.argv = forwarded
    runpy.run_path(str(PRECHECK), run_name="__main__")


if __name__ == "__main__":
    main()
