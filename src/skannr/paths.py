"""Filesystem layout constants for the standard Skannr tree."""

import os


PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.dirname(PACKAGE_DIR)
PROJECT_ROOT = os.path.dirname(SRC_DIR)

CONFIG_DIR = os.path.join(PROJECT_ROOT, "config")
CONFIG_PATH = os.path.join(CONFIG_DIR, "skannr.yaml")
CONFIG_COLLECTORS_DIR = os.path.join(CONFIG_DIR, "collectors")

RUNTIME_DIR = os.path.join(PROJECT_ROOT, "runtime")
RUNTIME_LOG_DIR = os.path.join(RUNTIME_DIR, "logs")

DATA_DIR = os.path.join(PACKAGE_DIR, "data")
DATA_COLLECTORS_DIR = os.path.join(DATA_DIR, "collectors")
STATIC_DIR = os.path.join(PACKAGE_DIR, "static")
VERSION_PATH = os.path.join(PROJECT_ROOT, "VERSION")
